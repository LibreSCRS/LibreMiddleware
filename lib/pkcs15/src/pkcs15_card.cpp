// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <pkcs15/pkcs15_card.h>
#include <pkcs15/pkcs15_parser.h>
#include <smartcard/apdu.h>
#include <smartcard/pcsc_connection.h>

#include <openssl/crypto.h>
#include <stdexcept>

namespace pkcs15 {

namespace {

const std::vector<uint8_t> PKCS15_AID = {0xA0, 0x00, 0x00, 0x00, 0x63, 0x50, 0x4B, 0x43, 0x53, 0x2D, 0x31, 0x35};
constexpr size_t MAX_FILE_SIZE = 65536;
constexpr uint8_t READ_CHUNK_SIZE = 128;

} // namespace

PKCS15Card::PKCS15Card(smartcard::PCSCConnection& conn) : conn(conn) {}

bool PKCS15Card::probe()
{
    // Strategy A: try AID SELECT first (fast path)
    auto resp = conn.transmit(smartcard::selectByAID(PKCS15_AID, 0x0C));
    if (resp.isSuccess()) {
        pkcs15Path.clear(); // AID works, no path needed
        fileSelectP2 = 0x0C;
        return true;
    }

    // Fallback: try AID with P2=0x00 (some cards need FCI)
    resp = conn.transmit(smartcard::selectByAID(PKCS15_AID));
    if (resp.isSuccess()) {
        pkcs15Path.clear();
        fileSelectP2 = 0x00;
        return true;
    }

    // Strategy A fallback: read EF.DIR to discover PKCS#15 path
    return probeViaEfDir();
}

bool PKCS15Card::selectApplet()
{
    if (pkcs15Path.empty()) {
        // AID-based selection worked during probe
        auto resp = conn.transmit(smartcard::selectByAID(PKCS15_AID, 0x0C));
        if (resp.isSuccess())
            return true;
        resp = conn.transmit(smartcard::selectByAID(PKCS15_AID));
        return resp.isSuccess();
    }

    // Path-based selection (discovered from EF.DIR)
    return selectByPath(pkcs15Path);
}

bool PKCS15Card::probeViaEfDir()
{
    // SELECT MF (3F00) — try default P2, then P2=0x0C
    auto resp = conn.transmit(smartcard::selectByFileId(0x3F, 0x00));
    if (!resp.isSuccess()) {
        resp = conn.transmit(smartcard::selectByFileId(0x3F, 0x00, 0x0C));
        if (!resp.isSuccess())
            return false;
        fileSelectP2 = 0x0C;
    }

    // SELECT EF.DIR (2F00) — use discovered P2
    resp = conn.transmit(smartcard::selectByFileId(0x2F, 0x00, fileSelectP2));
    if (!resp.isSuccess()) {
        uint8_t altP2 = (fileSelectP2 == 0x0C) ? 0x00 : 0x0C;
        resp = conn.transmit(smartcard::selectByFileId(0x2F, 0x00, altP2));
        if (!resp.isSuccess())
            return false;
        fileSelectP2 = altP2;
    }

    // READ EF.DIR
    auto efDir = readSelectedFile();
    if (efDir.empty())
        return false;

    // Parse EF.DIR — look for PKCS#15 AID entries with a path
    // EF.DIR contains Application Template (tag 61) entries:
    //   4F = AID, 50 = label, 51 = path
    size_t pos = 0;
    while (pos + 2 < efDir.size()) {
        if (efDir[pos] != 0x61) {
            pos++;
            continue;
        }
        uint8_t entryLen = efDir[pos + 1];
        if (pos + 2 + entryLen > efDir.size())
            break;

        // Parse entry fields
        std::vector<uint8_t> aid;
        std::vector<uint8_t> path;
        size_t fieldPos = pos + 2;
        size_t entryEnd = pos + 2 + entryLen;

        while (fieldPos + 2 <= entryEnd) {
            uint8_t tag = efDir[fieldPos];
            uint8_t len = efDir[fieldPos + 1];
            if (fieldPos + 2 + len > entryEnd)
                break;

            if (tag == 0x4F) { // AID
                aid.assign(efDir.begin() + fieldPos + 2, efDir.begin() + fieldPos + 2 + len);
            } else if (tag == 0x51) { // Path
                path.assign(efDir.begin() + fieldPos + 2, efDir.begin() + fieldPos + 2 + len);
            }
            fieldPos += 2 + len;
        }

        // Check if this is a PKCS#15 entry with a usable path
        if (aid == PKCS15_AID && !path.empty() && path.size() % 2 == 0) {
            // Try to select by path
            if (selectByPath(path)) {
                pkcs15Path = path;
                return true;
            }
        }

        pos = entryEnd;
    }

    return false;
}

PKCS15Profile PKCS15Card::readProfile()
{
    smartcard::CardTransaction tx(conn);

    if (!selectApplet())
        throw std::runtime_error("Failed to select PKCS#15 applet");

    // Read ODF (EF.ODF = 5031)
    const uint8_t odfFid[] = {0x50, 0x31};
    if (!selectByPath(odfFid))
        throw std::runtime_error("Failed to select EF.ODF");
    auto odfData = readSelectedFile();
    auto odf = parseODF(odfData);

    // Re-select applet before reading TokenInfo
    if (!selectApplet())
        throw std::runtime_error("PKCS15: failed to select applet");

    // Read TokenInfo (EF.TokenInfo = 5032)
    const uint8_t tokenInfoFid[] = {0x50, 0x32};
    if (!selectByPath(tokenInfoFid))
        throw std::runtime_error("Failed to select EF.TokenInfo");
    auto tokenData = readSelectedFile();
    auto tokenInfo = parseTokenInfo(tokenData);

    PKCS15Profile profile;
    profile.odf = odf;
    profile.tokenInfo = tokenInfo;

    // Read CDF if present
    if (!odf.certificatesPath.empty()) {
        if (!selectApplet())
            throw std::runtime_error("PKCS15: failed to select applet");
        if (selectByPath(odf.certificatesPath))
            profile.certificates = parseCDF(readSelectedFile());
    }

    // Read PrKDF if present
    if (!odf.privateKeysPath.empty()) {
        if (!selectApplet())
            throw std::runtime_error("PKCS15: failed to select applet");
        if (selectByPath(odf.privateKeysPath))
            profile.privateKeys = parsePrKDF(readSelectedFile());
    }

    // Read AODF if present
    if (!odf.authObjectsPath.empty()) {
        if (!selectApplet())
            throw std::runtime_error("PKCS15: failed to select applet");
        if (selectByPath(odf.authObjectsPath))
            profile.pins = parseAODF(readSelectedFile());
    }

    return profile;
}

std::vector<uint8_t> PKCS15Card::readCertificate(const CertificateInfo& cert)
{
    smartcard::CardTransaction tx(conn);
    if (!selectApplet())
        return {};

    if (!selectByPath(cert.path))
        return {};

    return readSelectedFile();
}

int PKCS15Card::getPINTriesLeft(const PinInfo& pin)
{
    smartcard::CardTransaction tx(conn);
    if (!selectApplet())
        throw std::runtime_error("PKCS15: failed to select applet");

    // Navigate to PIN's DF if path is given
    if (!pin.path.empty())
        selectByPath(pin.path);

    // Try pinReference directly
    auto resp = conn.transmit(smartcard::verifyPINStatus(pin.pinReference));
    if (resp.sw1 == 0x63 && (resp.sw2 & 0xF0) == 0xC0)
        return resp.sw2 & 0x0F;
    if (resp.isSuccess())
        return -1; // already verified

    // Fallback: strip local bit (0x80)
    uint8_t altRef = pin.pinReference & 0x7F;
    if (altRef != pin.pinReference) {
        resp = conn.transmit(smartcard::verifyPINStatus(altRef));
        if (resp.sw1 == 0x63 && (resp.sw2 & 0xF0) == 0xC0)
            return resp.sw2 & 0x0F;
        if (resp.isSuccess())
            return -1;
    }

    return -1; // unknown
}

PinResult PKCS15Card::verifyPIN(const PinInfo& pin, const std::string& pinValue)
{
    smartcard::CardTransaction tx(conn);
    if (!selectApplet())
        throw std::runtime_error("PKCS15: failed to select applet");

    if (!pin.path.empty())
        selectByPath(pin.path);

    // Encode PIN data
    std::vector<uint8_t> pinData(pinValue.begin(), pinValue.end());
    if (pin.storedLength > 0 && static_cast<int>(pinData.size()) > pin.storedLength)
        pinData.resize(pin.storedLength);
    if (pin.storedLength > 0 && static_cast<int>(pinData.size()) < pin.storedLength)
        pinData.resize(pin.storedLength, pin.padChar);

    // Try pinReference directly
    auto resp = conn.transmit(smartcard::verifyPIN(pin.pinReference, pinData));
    if (resp.isSuccess()) {
        OPENSSL_cleanse(pinData.data(), pinData.size());
        return {true, -1, false};
    }
    if (resp.sw1 == 0x63 && (resp.sw2 & 0xF0) == 0xC0) {
        OPENSSL_cleanse(pinData.data(), pinData.size());
        return {false, resp.sw2 & 0x0F, false};
    }
    if (resp.statusWord() == 0x6983) {
        OPENSSL_cleanse(pinData.data(), pinData.size());
        return {false, 0, true};
    }

    // Fallback: strip local bit
    uint8_t altRef = pin.pinReference & 0x7F;
    if (altRef != pin.pinReference) {
        resp = conn.transmit(smartcard::verifyPIN(altRef, pinData));
        if (resp.isSuccess()) {
            OPENSSL_cleanse(pinData.data(), pinData.size());
            return {true, -1, false};
        }
        if (resp.sw1 == 0x63 && (resp.sw2 & 0xF0) == 0xC0) {
            OPENSSL_cleanse(pinData.data(), pinData.size());
            return {false, resp.sw2 & 0x0F, false};
        }
        if (resp.statusWord() == 0x6983) {
            OPENSSL_cleanse(pinData.data(), pinData.size());
            return {false, 0, true};
        }
    }

    OPENSSL_cleanse(pinData.data(), pinData.size());
    return {false, -1, false};
}

PinResult PKCS15Card::changePIN(const PinInfo& pin, const std::string& oldPin, const std::string& newPin)
{
    smartcard::CardTransaction tx(conn);
    if (!selectApplet())
        throw std::runtime_error("PKCS15: failed to select applet");

    if (!pin.path.empty())
        selectByPath(pin.path);

    // Encode old PIN
    std::vector<uint8_t> oldData(oldPin.begin(), oldPin.end());
    if (pin.storedLength > 0 && static_cast<int>(oldData.size()) > pin.storedLength)
        oldData.resize(pin.storedLength);
    if (pin.storedLength > 0 && static_cast<int>(oldData.size()) < pin.storedLength)
        oldData.resize(pin.storedLength, pin.padChar);

    // Encode new PIN
    std::vector<uint8_t> newData(newPin.begin(), newPin.end());
    if (pin.storedLength > 0 && static_cast<int>(newData.size()) > pin.storedLength)
        newData.resize(pin.storedLength);
    if (pin.storedLength > 0 && static_cast<int>(newData.size()) < pin.storedLength)
        newData.resize(pin.storedLength, pin.padChar);

    auto resp = conn.transmit(smartcard::changeReferenceData(pin.pinReference, oldData, newData));
    if (resp.isSuccess()) {
        OPENSSL_cleanse(oldData.data(), oldData.size());
        OPENSSL_cleanse(newData.data(), newData.size());
        return {true, -1, false};
    }
    if (resp.sw1 == 0x63 && (resp.sw2 & 0xF0) == 0xC0) {
        OPENSSL_cleanse(oldData.data(), oldData.size());
        OPENSSL_cleanse(newData.data(), newData.size());
        return {false, resp.sw2 & 0x0F, false};
    }
    if (resp.statusWord() == 0x6983) {
        OPENSSL_cleanse(oldData.data(), oldData.size());
        OPENSSL_cleanse(newData.data(), newData.size());
        return {false, 0, true};
    }

    // Fallback: strip local bit — ONLY on reference-not-found errors
    uint8_t altRef = pin.pinReference & 0x7F;
    if (altRef != pin.pinReference && (resp.statusWord() == 0x6A86 || resp.statusWord() == 0x6A88)) {
        resp = conn.transmit(smartcard::changeReferenceData(altRef, oldData, newData));
        if (resp.isSuccess()) {
            OPENSSL_cleanse(oldData.data(), oldData.size());
            OPENSSL_cleanse(newData.data(), newData.size());
            return {true, -1, false};
        }
        if (resp.sw1 == 0x63 && (resp.sw2 & 0xF0) == 0xC0) {
            OPENSSL_cleanse(oldData.data(), oldData.size());
            OPENSSL_cleanse(newData.data(), newData.size());
            return {false, resp.sw2 & 0x0F, false};
        }
        if (resp.statusWord() == 0x6983) {
            OPENSSL_cleanse(oldData.data(), oldData.size());
            OPENSSL_cleanse(newData.data(), newData.size());
            return {false, 0, true};
        }
    }

    OPENSSL_cleanse(oldData.data(), oldData.size());
    OPENSSL_cleanse(newData.data(), newData.size());
    return {false, -1, false};
}

bool PKCS15Card::selectByPath(std::span<const uint8_t> path, uint8_t selectP2)
{
    if (path.empty() || path.size() % 2 != 0)
        return false;

    uint8_t p2 = (selectP2 != 0x00) ? selectP2 : fileSelectP2;

    // Skip 3FFF prefix — in PKCS#15 this means "current application DF",
    // and we already selected the applet via AID
    size_t startIdx = 0;
    if (path.size() >= 2 && path[0] == 0x3F && path[1] == 0xFF) {
        startIdx = 2;
    }

    for (size_t i = startIdx; i + 1 < path.size(); i += 2) {
        auto resp = conn.transmit(smartcard::selectByFileId(path[i], path[i + 1], p2));
        if (resp.isSuccess())
            continue;

        // Try alternative P2 on retryable errors
        if (resp.statusWord() == 0x6700 || resp.statusWord() == 0x6A86) {
            uint8_t altP2 = (p2 == 0x0C) ? 0x00 : 0x0C;
            resp = conn.transmit(smartcard::selectByFileId(path[i], path[i + 1], altP2));
            if (resp.isSuccess()) {
                fileSelectP2 = altP2;
                p2 = altP2;
                continue;
            }
        }
        return false;
    }
    return true;
}

std::vector<uint8_t> PKCS15Card::readSelectedFile()
{
    std::vector<uint8_t> result;
    size_t offset = 0;

    while (true) {
        auto resp = conn.transmit(smartcard::readBinary(static_cast<uint16_t>(offset), READ_CHUNK_SIZE));

        // 6282 = standard EOF; 6A86 = some cards signal EOF this way (e.g. Gemalto SafeSign)
        bool isEof = resp.statusWord() == 0x6282 || (resp.statusWord() == 0x6A86 && !result.empty());

        if (resp.data.empty() || (!resp.isSuccess() && !isEof))
            break;

        result.insert(result.end(), resp.data.begin(), resp.data.end());
        offset += resp.data.size();

        if (offset >= MAX_FILE_SIZE)
            break;
        if (isEof)
            break;
    }

    return result;
}

} // namespace pkcs15
