// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <emrtd/emrtd_card.h>
#include <emrtd/crypto/bac.h>
#include <emrtd/crypto/pace.h>
#include <smartcard/apdu.h>
#include <smartcard/pcsc_connection.h>

#include <openssl/crypto.h>

#include <stdexcept>

namespace emrtd {

EMRTDCard::EMRTDCard(smartcard::PCSCConnection& conn, const MRZData& mrz) : conn(conn), credentials(mrz) {}

EMRTDCard::EMRTDCard(smartcard::PCSCConnection& conn, const std::string& can) : conn(conn), credentials(can) {}

EMRTDCard::~EMRTDCard()
{
    // Securely clear credentials
    if (auto* mrz = std::get_if<MRZData>(&credentials)) {
        OPENSSL_cleanse(mrz->documentNumber.data(), mrz->documentNumber.size());
        OPENSSL_cleanse(mrz->dateOfBirth.data(), mrz->dateOfBirth.size());
        OPENSSL_cleanse(mrz->dateOfExpiry.data(), mrz->dateOfExpiry.size());
    } else if (auto* can = std::get_if<std::string>(&credentials)) {
        OPENSSL_cleanse(can->data(), can->size());
    }
}

bool EMRTDCard::selectApplet()
{
    smartcard::APDUCommand cmd{0x00, 0xA4, 0x04, 0x0C, {EMRTD_AID, EMRTD_AID + EMRTD_AID_LEN}, 0, false};
    auto resp = conn.transmit(cmd);
    return resp.isSuccess();
}

std::vector<uint8_t> EMRTDCard::readCardAccess()
{
    // Method 1: READ BINARY with short file identifier (SFID)
    smartcard::APDUCommand cmd{0x00, 0xB0, static_cast<uint8_t>(0x80 | SFID_CARD_ACCESS), 0x00, {}, 0x00, true};
    auto resp = conn.transmit(cmd);
    if (resp.isSuccess())
        return resp.data;

    // Method 2: SELECT MF (3F00) then SELECT EF.CardAccess by FID (011C) with P1=00 P2=00
    // Some cards (e.g. Georgian eID) require explicit MF selection before EF.CardAccess
    smartcard::APDUCommand selectMF{0x00, 0xA4, 0x00, 0x00, {0x3F, 0x00}, 0x00, true};
    conn.transmit(selectMF); // ignore result

    smartcard::APDUCommand selectCmd{0x00, 0xA4, 0x00, 0x00, {0x01, 0x1C}, 0x00, true};
    auto selectResp = conn.transmit(selectCmd);
    if (selectResp.isSuccess()) {
        // Read entire file (CardAccess is typically <256 bytes)
        // Le=0x00 means 256 bytes; card returns what it has (62 82 = end of file)
        smartcard::APDUCommand readAll{0x00, 0xB0, 0x00, 0x00, {}, 0x00, true};
        auto readResp = conn.transmit(readAll);
        if (!readResp.data.empty())
            return readResp.data;
    }

    return {};
}

AuthResult EMRTDCard::authenticate()
{
    // Read EF.CardAccess BEFORE selecting eMRTD applet — it lives in MF context,
    // not inside the applet. Some cards (e.g. Georgian eID) only allow reading
    // CardAccess from MF, not from within the eMRTD applet.
    auto cardAccess = readCardAccess();
    auto paceEntries = crypto::parseCardAccessWithParams(cardAccess);

    // Do NOT select eMRTD applet before PACE — MSE SET AT runs at card level (MF),
    // not inside the applet. Applet selection happens AFTER PACE succeeds.

    // If CardAccess is unavailable but user provided CAN, try PACE with common parameters.
    // Many cards support PACE but restrict CardAccess before auth. Try all common variants.
    bool hasCAN = std::holds_alternative<std::string>(credentials);
    if (paceEntries.empty() && hasCAN) {
        using namespace crypto::pace_oid;
        // Try without paramId first (some cards reject explicit paramId)
        paceEntries.emplace_back(ECDH_GM_AES_CBC_CMAC_256, -1);
        paceEntries.emplace_back(ECDH_GM_AES_CBC_CMAC_128, -1);
        paceEntries.emplace_back(ECDH_IM_AES_CBC_CMAC_256, -1);
        paceEntries.emplace_back(ECDH_IM_AES_CBC_CMAC_128, -1);
        paceEntries.emplace_back(ECDH_CAM_AES_CBC_CMAC_256, -1);
        paceEntries.emplace_back(ECDH_CAM_AES_CBC_CMAC_128, -1);
        // Then with explicit paramId=13 (brainpoolP256r1)
        paceEntries.emplace_back(ECDH_GM_AES_CBC_CMAC_256, 13);
        paceEntries.emplace_back(ECDH_GM_AES_CBC_CMAC_128, 13);
    }

    if (!paceEntries.empty()) {
        // Derive password for PACE
        std::vector<uint8_t> password;
        crypto::PACEPasswordType pwType;

        if (auto* mrz = std::get_if<MRZData>(&credentials)) {
            // PACE with MRZ: password = MRZ_information string bytes
            std::string paddedDocNo = mrz->documentNumber;
            while (paddedDocNo.size() < 9)
                paddedDocNo += '<';
            auto cd = [](const std::string& s) { return crypto::detail::computeCheckDigit(s); };
            std::string mrzInfo = paddedDocNo + std::to_string(cd(paddedDocNo)) + mrz->dateOfBirth +
                                  std::to_string(cd(mrz->dateOfBirth)) + mrz->dateOfExpiry +
                                  std::to_string(cd(mrz->dateOfExpiry));
            password.assign(mrzInfo.begin(), mrzInfo.end());
            pwType = crypto::PACEPasswordType::MRZ;
        } else if (auto* can = std::get_if<std::string>(&credentials)) {
            password.assign(can->begin(), can->end());
            pwType = crypto::PACEPasswordType::CAN;
        } else {
            return {false, AuthMethod::BAC, "No credentials"};
        }

        // Try each PACE OID with its associated parameter ID
        // PACE runs at card (MF) level, NOT inside the applet
        for (const auto& [oid, paramId] : paceEntries) {

            crypto::PACEParams params{oid, pwType, password, paramId};
            std::optional<crypto::SessionKeys> session;
            try {
                session = crypto::performPACE(conn, params);
            } catch (const std::exception&) {
                continue;
            }
            if (session) {
                smAlgo = crypto::paceOIDToSMAlgorithm(oid);
                sm = std::make_unique<crypto::SecureMessaging>(*session, smAlgo);
                // Select eMRTD applet AFTER PACE via SM (non-SM commands may invalidate session)
                std::vector<uint8_t> selectAid = {0x00, 0xA4, 0x04, 0x0C, static_cast<uint8_t>(EMRTD_AID_LEN)};
                selectAid.insert(selectAid.end(), EMRTD_AID, EMRTD_AID + EMRTD_AID_LEN);
                transmitSecure(selectAid);
                AuthMethod method =
                    (pwType == crypto::PACEPasswordType::CAN) ? AuthMethod::PACE_CAN : AuthMethod::PACE_MRZ;
                return {true, method, ""};
            }
        }
        // PACE failed, fall through to BAC
    }

    // Try BAC (only with MRZ credentials)
    if (auto* mrz = std::get_if<MRZData>(&credentials)) {
        if (!selectApplet())
            return {false, AuthMethod::BAC, "Failed to re-select applet for BAC"};

        auto bacKeys = crypto::deriveBACKeys(mrz->documentNumber, mrz->dateOfBirth, mrz->dateOfExpiry);
        auto session = crypto::performBAC(conn, bacKeys);
        if (session) {
            smAlgo = crypto::SMAlgorithm::DES3;
            sm = std::make_unique<crypto::SecureMessaging>(*session, smAlgo);
            return {true, AuthMethod::BAC, ""};
        }
        return {false, AuthMethod::BAC, "BAC authentication failed"};
    }

    return {false, AuthMethod::PACE_CAN, "PACE failed and BAC requires MRZ credentials"};
}

std::optional<std::vector<uint8_t>> EMRTDCard::transmitSecure(const std::vector<uint8_t>& apduBytes)
{
    if (!sm)
        return std::nullopt;

    auto protectedApdu = sm->protect(apduBytes);

    // Build APDUCommand from protected bytes
    if (protectedApdu.size() < 5)
        return std::nullopt;
    smartcard::APDUCommand cmd;
    cmd.cla = protectedApdu[0];
    cmd.ins = protectedApdu[1];
    cmd.p1 = protectedApdu[2];
    cmd.p2 = protectedApdu[3];
    // Lc is at [4], data follows, Le is last byte
    uint8_t lc = protectedApdu[4];
    cmd.data.assign(protectedApdu.begin() + 5, protectedApdu.begin() + 5 + lc);
    cmd.le = protectedApdu.back();
    cmd.hasLe = true;

    smartcard::APDUResponse resp;
    try {
        resp = conn.transmitRaw(cmd);
    } catch (const smartcard::PCSCError&) {
        if (recovering)
            return std::nullopt;
        // Try recovery on card reset
        try {
            recover();
            protectedApdu = sm->protect(apduBytes);
            if (protectedApdu.size() < 5)
                return std::nullopt;
            cmd.cla = protectedApdu[0];
            cmd.ins = protectedApdu[1];
            cmd.p1 = protectedApdu[2];
            cmd.p2 = protectedApdu[3];
            lc = protectedApdu[4];
            cmd.data.assign(protectedApdu.begin() + 5, protectedApdu.begin() + 5 + lc);
            cmd.le = protectedApdu.back();
            resp = conn.transmitRaw(cmd);
        } catch (const smartcard::PCSCError&) {
            return std::nullopt;
        }
    }

    // Build response bytes for unprotect: data + SW1 + SW2
    std::vector<uint8_t> respBytes = resp.data;
    respBytes.push_back(resp.sw1);
    respBytes.push_back(resp.sw2);

    return sm->unprotect(respBytes);
}

smartcard::APDUResponse EMRTDCard::transmitSecureAPDU(const smartcard::APDUCommand& cmd)
{
    if (!sm)
        return {{}, 0x69, 0x82};

    auto cmdBytes = cmd.toBytes();
    auto protectedApdu = sm->protect(cmdBytes);
    if (protectedApdu.size() < 5)
        return {{}, 0x69, 0x82};

    // Send via transmitRaw to bypass TransmitFilter (avoids recursion)
    auto resp = conn.transmitRaw(protectedApdu.data(), static_cast<DWORD>(protectedApdu.size()));

    std::vector<uint8_t> respBytes = resp.data;
    respBytes.push_back(resp.sw1);
    respBytes.push_back(resp.sw2);

    auto result = sm->unprotectWithSW(respBytes);
    if (!result)
        return {{}, 0x69, 0x82};

    return {std::move(result->data), result->sw1, result->sw2};
}

void EMRTDCard::recover()
{
    recovering = true;
    struct RecoveryGuard
    {
        bool& flag;
        ~RecoveryGuard()
        {
            flag = false;
        }
    } guard{recovering};

    conn.reconnect();
    sm.reset();
    authenticate();
}

std::optional<std::vector<uint8_t>> EMRTDCard::readFile(uint16_t fid)
{
    // SELECT file by FID (P2=0x0C: no response data expected)
    std::vector<uint8_t> selectApdu = {
        0x00, 0xA4, 0x02, 0x0C, 0x02, static_cast<uint8_t>(fid >> 8), static_cast<uint8_t>(fid & 0xFF)};
    transmitSecure(selectApdu);

    // READ BINARY in chunks of 256 bytes (Le=0x00 = 256 in short APDU form)
    static constexpr uint8_t READ_LE = 0x00;
    std::vector<uint8_t> fileData;
    size_t offset = 0;
    bool firstChunk = true;
    size_t totalLength = 0;

    while (true) {
        uint8_t p1 = static_cast<uint8_t>((offset >> 8) & 0x7F);
        uint8_t p2 = static_cast<uint8_t>(offset & 0xFF);
        std::vector<uint8_t> readApdu = {0x00, 0xB0, p1, p2, READ_LE};

        auto chunk = transmitSecure(readApdu);
        if (!chunk || chunk->empty())
            break;

        fileData.insert(fileData.end(), chunk->begin(), chunk->end());

        // Parse TLV length from first chunk to know total file size
        if (firstChunk && fileData.size() >= 4) {
            firstChunk = false;
            size_t pos = 1; // skip tag byte
            // Multi-byte tag check
            if ((fileData[0] & 0x1F) == 0x1F) {
                while (pos < fileData.size() && (fileData[pos] & 0x80))
                    pos++;
                pos++; // skip last tag byte
            }
            // Parse length
            if (pos < fileData.size()) {
                uint8_t lenByte = fileData[pos];
                if (lenByte < 0x80) {
                    totalLength = pos + 1 + lenByte;
                } else if (lenByte == 0x81 && pos + 1 < fileData.size()) {
                    totalLength = pos + 2 + fileData[pos + 1];
                } else if (lenByte == 0x82 && pos + 2 < fileData.size()) {
                    totalLength = pos + 3 + (fileData[pos + 1] << 8 | fileData[pos + 2]);
                } else if (lenByte == 0x83 && pos + 3 < fileData.size()) {
                    totalLength = pos + 4 + (fileData[pos + 1] << 16 | fileData[pos + 2] << 8 | fileData[pos + 3]);
                }
            }
        }

        offset += chunk->size();

        // Stop if we've read enough
        if (totalLength > 0 && fileData.size() >= totalLength) {
            fileData.resize(totalLength);
            break;
        }

        // Safety: stop after 1MB
        if (fileData.size() > 1024 * 1024)
            break;
    }

    if (fileData.empty())
        return std::nullopt;
    return fileData;
}

std::vector<int> EMRTDCard::readCOM()
{
    auto comData = readFile(FID_COM);
    if (!comData)
        return {};

    // COM contains tag 0x60, with sub-tag 0x5C listing present DG tags
    std::vector<int> dgList;
    auto& data = *comData;

    // Find tag 0x5C (tag list)
    for (size_t i = 0; i + 1 < data.size(); ++i) {
        if (data[i] == 0x5C) {
            size_t lenPos = i + 1;
            size_t len = 0;
            size_t dataStart = 0;

            if (data[lenPos] < 0x80) {
                len = data[lenPos];
                dataStart = lenPos + 1;
            } else if (data[lenPos] == 0x81 && lenPos + 1 < data.size()) {
                len = data[lenPos + 1];
                dataStart = lenPos + 2;
            }

            // Each byte in the tag list is a DG tag
            for (size_t j = dataStart; j < dataStart + len && j < data.size(); ++j) {
                uint8_t tag = data[j];
                // DG tags: 0x61=DG1, 0x75=DG2, 0x63=DG3, ...
                if (tag == 0x61)
                    dgList.push_back(1);
                else if (tag == 0x75)
                    dgList.push_back(2);
                else if (tag == 0x63)
                    dgList.push_back(3);
                else if (tag == 0x76)
                    dgList.push_back(4);
                else if (tag == 0x65)
                    dgList.push_back(5);
                else if (tag == 0x66)
                    dgList.push_back(6);
                else if (tag == 0x67)
                    dgList.push_back(7);
                else if (tag == 0x68)
                    dgList.push_back(8);
                else if (tag == 0x69)
                    dgList.push_back(9);
                else if (tag == 0x6A)
                    dgList.push_back(10);
                else if (tag == 0x6B)
                    dgList.push_back(11);
                else if (tag == 0x6C)
                    dgList.push_back(12);
                else if (tag == 0x6D)
                    dgList.push_back(13);
                else if (tag == 0x6E)
                    dgList.push_back(14);
                else if (tag == 0x6F)
                    dgList.push_back(15);
                else if (tag == 0x70)
                    dgList.push_back(16);
            }
            break;
        }
    }

    return dgList;
}

std::optional<std::vector<uint8_t>> EMRTDCard::readDataGroup(int dgNumber)
{
    uint16_t fid = dgToFID(dgNumber);
    if (fid == 0)
        return std::nullopt;
    return readFile(fid);
}

} // namespace emrtd
