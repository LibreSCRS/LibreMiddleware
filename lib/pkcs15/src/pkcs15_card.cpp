// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "pkcs15_card.h"
#include "pkcs15_parser.h"
#include "pkcs15_types.h"
#include <LibreSCRS/CancelToken.h>
#include <LibreSCRS/SecureChannel/ISecureChannel.h>
#include <apdu.h>
#include <smartcard/secure_buffer.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <stdexcept>

#include "probe_trace.h"

namespace pkcs15 {

namespace {
// ISO 7816-4 READ BINARY short form: P1 bits 0–6 = offset high byte → max offset 32767.
constexpr size_t MAX_FILE_SIZE = 32767;
constexpr uint8_t READ_CHUNK_SIZE = 128;

std::vector<uint8_t> computeHash(const EVP_MD* md, const std::vector<uint8_t>& data)
{
    std::vector<uint8_t> hash(static_cast<size_t>(EVP_MD_size(md)));
    unsigned int hLen = 0;
    auto ctx = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (!ctx || !EVP_DigestInit_ex(ctx.get(), md, nullptr) || !EVP_DigestUpdate(ctx.get(), data.data(), data.size()) ||
        !EVP_DigestFinal_ex(ctx.get(), hash.data(), &hLen))
        throw std::runtime_error("PKCS15: hash computation failed");
    hash.resize(hLen);
    return hash;
}

// MGF1 per RFC 8017 section B.2.1
std::vector<uint8_t> mgf1(const EVP_MD* md, const std::vector<uint8_t>& seed, size_t maskLen)
{
    std::vector<uint8_t> mask;
    mask.reserve(maskLen);
    for (uint32_t counter = 0; mask.size() < maskLen; ++counter) {
        std::vector<uint8_t> input = seed;
        input.push_back(static_cast<uint8_t>((counter >> 24) & 0xFF));
        input.push_back(static_cast<uint8_t>((counter >> 16) & 0xFF));
        input.push_back(static_cast<uint8_t>((counter >> 8) & 0xFF));
        input.push_back(static_cast<uint8_t>(counter & 0xFF));
        auto h = computeHash(md, input);
        mask.insert(mask.end(), h.begin(), h.end());
    }
    mask.resize(maskLen);
    return mask;
}

// PKCS#1 v1.5 padding: 00 01 FF...FF 00 || DigestInfo
// Some cards with RSA_RAW algo expect the full padded block, not just DigestInfo.
std::vector<uint8_t> applyPkcs1v15Padding(const std::vector<uint8_t>& digestInfo, uint16_t keySizeBits)
{
    size_t emLen = keySizeBits / 8;
    if (digestInfo.size() + 11 > emLen)
        throw std::runtime_error("PKCS15: key too short for PKCS#1 v1.5 padding");
    std::vector<uint8_t> em(emLen, 0xFF);
    em[0] = 0x00;
    em[1] = 0x01;
    em[emLen - digestInfo.size() - 1] = 0x00;
    std::copy(digestInfo.begin(), digestInfo.end(), em.end() - digestInfo.size());
    return em;
}

// EMSA-PSS-ENCODE per RFC 8017 section 9.1.1
// hash = Hash(M), already computed. sLen = salt length = hash length (standard).
std::vector<uint8_t> applyPssPadding(const std::vector<uint8_t>& hash, const EVP_MD* md, uint16_t keySizeBits)
{
    size_t hLen = static_cast<size_t>(EVP_MD_size(md));
    size_t emLen = keySizeBits / 8;
    // Salt length = hash length per RFC 8017 section 9.1 Note 1 (standard PSS)
    size_t sLen = hLen;

    if (emLen < hLen + sLen + 2)
        throw std::runtime_error("PKCS15: key too short for PSS padding");

    // Generate random salt
    std::vector<uint8_t> salt(sLen);
    if (RAND_bytes(salt.data(), static_cast<int>(sLen)) != 1)
        throw std::runtime_error("PKCS15: RAND_bytes failed");

    // M' = 00 00 00 00 00 00 00 00 || hash || salt
    std::vector<uint8_t> mPrime(8, 0x00);
    mPrime.insert(mPrime.end(), hash.begin(), hash.end());
    mPrime.insert(mPrime.end(), salt.begin(), salt.end());

    auto H = computeHash(md, mPrime);

    // DB = PS || 0x01 || salt  (PS = zero padding)
    size_t dbLen = emLen - hLen - 1;
    std::vector<uint8_t> DB(dbLen, 0x00);
    DB[dbLen - sLen - 1] = 0x01;
    std::copy(salt.begin(), salt.end(), DB.begin() + static_cast<ptrdiff_t>(dbLen - sLen));

    // dbMask = MGF1(H, dbLen)
    auto dbMask = mgf1(md, H, dbLen);

    // maskedDB = DB XOR dbMask
    for (size_t i = 0; i < dbLen; ++i)
        DB[i] ^= dbMask[i];

    // Clear leftmost bits: 8*emLen - emBits (for keySizeBits that are byte-aligned, this is 0)
    size_t emBits = keySizeBits - 1; // RSA modulus is keySizeBits, emBits = emLen*8 - 1 for MSB
    size_t zeroBits = 8 * emLen - emBits;
    if (zeroBits > 0 && zeroBits < 8)
        DB[0] &= static_cast<uint8_t>(0xFF >> zeroBits);

    // EM = maskedDB || H || 0xbc
    std::vector<uint8_t> em;
    em.reserve(emLen);
    em.insert(em.end(), DB.begin(), DB.end());
    em.insert(em.end(), H.begin(), H.end());
    em.push_back(0xBC);

    return em;
}

} // namespace

PKCS15Card::PKCS15Card(LibreSCRS::SecureChannel::ISecureChannel& channel) : channel(channel) {}

bool PKCS15Card::probe()
{
    // Strategy A: try AID SELECT first (fast path)
    std::vector<uint8_t> aid(kPkcs15Aid.begin(), kPkcs15Aid.end());
    auto resp = channel.transmit(LibreSCRS::SmartCard::Internal::selectByAID(aid, 0x0C), LibreSCRS::CancelToken{});
    if (resp.isSuccess()) {
        pkcs15Path.clear(); // AID works, no path needed
        fileSelectP2 = 0x0C;
        return true;
    }

    // Fallback: try AID with P2=0x00 (some cards need FCI)
    resp = channel.transmit(LibreSCRS::SmartCard::Internal::selectByAID(aid), LibreSCRS::CancelToken{});
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
        // AID-based selection worked during probe.
        std::vector<uint8_t> aid(kPkcs15Aid.begin(), kPkcs15Aid.end());
        auto resp = channel.transmit(LibreSCRS::SmartCard::Internal::selectByAID(aid, 0x0C), LibreSCRS::CancelToken{});
        if (resp.isSuccess())
            return true;
        resp = channel.transmit(LibreSCRS::SmartCard::Internal::selectByAID(aid), LibreSCRS::CancelToken{});
        return resp.isSuccess();
    }

    // Path-based selection (discovered from EF.DIR during probe).
    return selectByPath(pkcs15Path);
}

bool PKCS15Card::probeViaEfDir()
{
    // SELECT MF (3F00) — try default P2, then P2=0x0C
    auto resp = channel.transmit(LibreSCRS::SmartCard::Internal::selectByFileId(0x3F, 0x00), LibreSCRS::CancelToken{});
    if (!resp.isSuccess()) {
        resp = channel.transmit(LibreSCRS::SmartCard::Internal::selectByFileId(0x3F, 0x00, 0x0C),
                                LibreSCRS::CancelToken{});
        if (!resp.isSuccess())
            return false;
        fileSelectP2 = 0x0C;
    }

    // SELECT EF.DIR (2F00) — use discovered P2
    resp = channel.transmit(LibreSCRS::SmartCard::Internal::selectByFileId(0x2F, 0x00, fileSelectP2),
                            LibreSCRS::CancelToken{});
    if (!resp.isSuccess()) {
        uint8_t altP2 = (fileSelectP2 == 0x0C) ? 0x00 : 0x0C;
        resp = channel.transmit(LibreSCRS::SmartCard::Internal::selectByFileId(0x2F, 0x00, altP2),
                                LibreSCRS::CancelToken{});
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
        std::vector<uint8_t> pkcs15Aid(kPkcs15Aid.begin(), kPkcs15Aid.end());
        if (aid == pkcs15Aid && !path.empty() && path.size() % 2 == 0) {
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

TokenInfo PKCS15Card::readTokenInfo()
{

    if (!selectApplet())
        throw std::runtime_error("Failed to select PKCS#15 applet");

    const uint8_t tokenInfoFid[] = {0x50, 0x32};
    if (!selectByPath(tokenInfoFid))
        throw std::runtime_error("Failed to select EF.TokenInfo");
    auto tokenData = readSelectedFile();
    return parseTokenInfo(tokenData);
}

PKCS15Profile PKCS15Card::readProfile()
{
    const bool trace = std::getenv("LIBRESCRS_SIGN_TRACE") != nullptr;
    auto dumpHex = [](const std::vector<uint8_t>& v, std::size_t maxLen) {
        std::string out;
        const auto n = std::min(maxLen, v.size());
        for (std::size_t i = 0; i < n; ++i) {
            char buf[4];
            std::snprintf(buf, sizeof(buf), "%02X", v[i]);
            out += buf;
        }
        if (v.size() > n)
            out += "...";
        return out;
    };
    {
        char buf[64];
        std::snprintf(buf, sizeof(buf), "READPROFILE-ENTRY this=%p", static_cast<const void*>(this));
        LibreSCRS::Internal::probeTrace(buf);
    }
    if (trace)
        std::fprintf(stderr, "[PKCS15::readProfile] entry this=%p\n", static_cast<const void*>(this));

    if (!selectApplet()) {
        if (trace)
            std::fprintf(stderr, "[PKCS15::readProfile] selectApplet FAILED\n");
        throw std::runtime_error("Failed to select PKCS#15 applet");
    }
    if (trace)
        std::fprintf(stderr, "[PKCS15::readProfile] selectApplet OK\n");

    // Read ODF (EF.ODF = 5031)
    const uint8_t odfFid[] = {0x50, 0x31};
    if (!selectByPath(odfFid)) {
        if (trace)
            std::fprintf(stderr, "[PKCS15::readProfile] selectByPath(EF.ODF 5031) FAILED\n");
        throw std::runtime_error("Failed to select EF.ODF");
    }
    auto odfData = readSelectedFile();
    if (trace)
        std::fprintf(stderr, "[PKCS15::readProfile] EF.ODF %zuB head=%s\n", odfData.size(),
                     dumpHex(odfData, 32).c_str());
    auto odf = parseODF(odfData);
    if (trace)
        std::fprintf(stderr, "[PKCS15::readProfile] parseODF: certsPath=%zuB keysPath=%zuB aodfPath=%zuB\n",
                     odf.certificatesPath.size(), odf.privateKeysPath.size(), odf.authObjectsPath.size());

    // Re-select applet before reading TokenInfo
    if (!selectApplet())
        throw std::runtime_error("PKCS15: failed to select applet");

    // Read TokenInfo (EF.TokenInfo = 5032)
    const uint8_t tokenInfoFid[] = {0x50, 0x32};
    if (!selectByPath(tokenInfoFid))
        throw std::runtime_error("Failed to select EF.TokenInfo");
    auto tokenData = readSelectedFile();
    if (trace)
        std::fprintf(stderr, "[PKCS15::readProfile] EF.TokenInfo %zuB head=%s\n", tokenData.size(),
                     dumpHex(tokenData, 32).c_str());
    auto tokenInfo = parseTokenInfo(tokenData);

    PKCS15Profile profile;
    profile.odf = odf;
    profile.tokenInfo = tokenInfo;

    // Read CDF if present
    if (!odf.certificatesPath.empty()) {
        if (!selectApplet())
            throw std::runtime_error("PKCS15: failed to select applet");
        if (selectByPath(odf.certificatesPath)) {
            auto cdfData = readSelectedFile();
            if (trace)
                std::fprintf(stderr, "[PKCS15::readProfile] CDF %zuB head=%s\n", cdfData.size(),
                             dumpHex(cdfData, 32).c_str());
            profile.certificates = parseCDF(cdfData);
        } else if (trace) {
            std::fprintf(stderr, "[PKCS15::readProfile] selectByPath(CDF) FAILED\n");
        }
    }

    // Read PrKDF if present
    if (!odf.privateKeysPath.empty()) {
        if (!selectApplet())
            throw std::runtime_error("PKCS15: failed to select applet");
        if (selectByPath(odf.privateKeysPath)) {
            auto prkdfData = readSelectedFile();
            if (trace)
                std::fprintf(stderr, "[PKCS15::readProfile] PrKDF %zuB head=%s\n", prkdfData.size(),
                             dumpHex(prkdfData, 32).c_str());
            profile.privateKeys = parsePrKDF(prkdfData);
        } else if (trace) {
            std::fprintf(stderr, "[PKCS15::readProfile] selectByPath(PrKDF) FAILED\n");
        }
    }

    // Read AODF if present
    if (!odf.authObjectsPath.empty()) {
        if (!selectApplet())
            throw std::runtime_error("PKCS15: failed to select applet");
        if (selectByPath(odf.authObjectsPath)) {
            auto aodfData = readSelectedFile();
            if (trace)
                std::fprintf(stderr, "[PKCS15::readProfile] AODF %zuB head=%s\n", aodfData.size(),
                             dumpHex(aodfData, 32).c_str());
            profile.pins = parseAODF(aodfData);
        } else if (trace) {
            std::fprintf(stderr, "[PKCS15::readProfile] selectByPath(AODF) FAILED\n");
        }
    }

    if (trace)
        std::fprintf(stderr, "[PKCS15::readProfile] DONE pins=%zu keys=%zu certs=%zu\n", profile.pins.size(),
                     profile.privateKeys.size(), profile.certificates.size());

    return profile;
}

std::vector<uint8_t> PKCS15Card::readCertificate(const CertificateInfo& cert)
{
    if (!selectApplet())
        return {};

    if (!selectByPath(cert.path))
        return {};

    return readSelectedFile();
}

int PKCS15Card::getPINTriesLeft(const PinInfo& pin)
{
    if (!selectApplet())
        throw std::runtime_error("PKCS15: failed to select applet");

    // Navigate to PIN's DF if path is given
    if (!pin.path.empty())
        selectByPath(pin.path);

    // Try pinReference directly
    auto resp =
        channel.transmit(LibreSCRS::SmartCard::Internal::verifyPINStatus(pin.pinReference), LibreSCRS::CancelToken{});
    if (resp.sw1 == 0x63 && (resp.sw2 & 0xF0) == 0xC0)
        return resp.sw2 & 0x0F;
    if (resp.isSuccess())
        return -1; // already verified

    // Fallback: strip local bit (0x80)
    uint8_t altRef = pin.pinReference & 0x7F;
    if (altRef != pin.pinReference) {
        resp = channel.transmit(LibreSCRS::SmartCard::Internal::verifyPINStatus(altRef), LibreSCRS::CancelToken{});
        if (resp.sw1 == 0x63 && (resp.sw2 & 0xF0) == 0xC0)
            return resp.sw2 & 0x0F;
        if (resp.isSuccess())
            return -1;
    }

    return -1; // unknown
}

PinResult PKCS15Card::verifyPIN(const PinInfo& pin, std::string_view pinValue)
{
    if (!selectApplet())
        throw std::runtime_error("PKCS15: failed to select applet");

    if (!pin.path.empty())
        selectByPath(pin.path);

    auto pinData = encodePIN(pinValue, pin);

    if (std::getenv("LIBRESCRS_SIGN_TRACE"))
        std::fprintf(
            stderr,
            "[PKCS15] verifyPIN ref=0x%02X label=\"%s\" path=%zuB rawLen=%zu encLen=%zu stored=%d padChar=0x%02X\n",
            pin.pinReference, pin.label.c_str(), pin.path.size(), pinValue.size(), pinData.size(), pin.storedLength,
            static_cast<unsigned>(pin.padChar) & 0xFF);

    // Try pinReference directly
    auto resp = channel.transmit(LibreSCRS::SmartCard::Internal::verifyPIN(pin.pinReference, pinData),
                                 LibreSCRS::CancelToken{});
    if (std::getenv("LIBRESCRS_SIGN_TRACE"))
        std::fprintf(stderr, "[PKCS15] verifyPIN ref=0x%02X SW=%04X\n", pin.pinReference, resp.statusWord());
    if (resp.isSuccess())
        return {true, -1, false};
    if (resp.sw1 == 0x63 && (resp.sw2 & 0xF0) == 0xC0)
        return {false, resp.sw2 & 0x0F, false};
    if (resp.statusWord() == 0x6983)
        return {false, 0, true};

    // Fallback: strip local bit
    uint8_t altRef = pin.pinReference & 0x7F;
    if (altRef != pin.pinReference) {
        resp = channel.transmit(LibreSCRS::SmartCard::Internal::verifyPIN(altRef, pinData), LibreSCRS::CancelToken{});
        if (std::getenv("LIBRESCRS_SIGN_TRACE"))
            std::fprintf(stderr, "[PKCS15] verifyPIN altRef=0x%02X SW=%04X\n", altRef, resp.statusWord());
        if (resp.isSuccess())
            return {true, -1, false};
        if (resp.sw1 == 0x63 && (resp.sw2 & 0xF0) == 0xC0)
            return {false, resp.sw2 & 0x0F, false};
        if (resp.statusWord() == 0x6983)
            return {false, 0, true};
    }

    return {false, -1, false};
}

PinResult PKCS15Card::changePIN(const PinInfo& pin, std::string_view oldPin, std::string_view newPin)
{
    if (!selectApplet())
        throw std::runtime_error("PKCS15: failed to select applet");

    if (!pin.path.empty())
        selectByPath(pin.path);

    auto oldData = encodePIN(oldPin, pin);
    auto newData = encodePIN(newPin, pin);

    auto resp =
        channel.transmit(LibreSCRS::SmartCard::Internal::changeReferenceData(pin.pinReference, oldData, newData),
                         LibreSCRS::CancelToken{});
    if (resp.isSuccess())
        return {true, -1, false};
    if (resp.sw1 == 0x63 && (resp.sw2 & 0xF0) == 0xC0)
        return {false, resp.sw2 & 0x0F, false};
    if (resp.statusWord() == 0x6983)
        return {false, 0, true};

    // Fallback: strip local bit — ONLY on reference-not-found errors
    uint8_t altRef = pin.pinReference & 0x7F;
    if (altRef != pin.pinReference && (resp.statusWord() == 0x6A86 || resp.statusWord() == 0x6A88)) {
        resp = channel.transmit(LibreSCRS::SmartCard::Internal::changeReferenceData(altRef, oldData, newData),
                                LibreSCRS::CancelToken{});
        if (resp.isSuccess())
            return {true, -1, false};
        if (resp.sw1 == 0x63 && (resp.sw2 & 0xF0) == 0xC0)
            return {false, resp.sw2 & 0x0F, false};
        if (resp.statusWord() == 0x6983)
            return {false, 0, true};
    }

    return {false, -1, false};
}

LibreSCRS::SmartCard::Internal::SecureBuffer PKCS15Card::encodePIN(std::string_view pin, const PinInfo& pinInfo)
{
    LibreSCRS::SmartCard::Internal::SecureBuffer pinData(pin);
    if (pinInfo.storedLength > 0 && static_cast<int>(pinData.size()) > pinInfo.storedLength)
        pinData.resize(pinInfo.storedLength);
    if (pinInfo.storedLength > 0 && static_cast<int>(pinData.size()) < pinInfo.storedLength)
        pinData.resize(pinInfo.storedLength, pinInfo.padChar);
    return pinData;
}

int PKCS15Card::verifyPinInline(const PinInfo& pinInfo, const LibreSCRS::SmartCard::Internal::SecureBuffer& pinData)
{
    auto resp = channel.transmit(LibreSCRS::SmartCard::Internal::verifyPIN(pinInfo.pinReference, pinData),
                                 LibreSCRS::CancelToken{});
#ifndef NDEBUG
    fprintf(stderr, "[PKCS15] verifyPIN ref=0x%02X pinLen=%zu SW=%04X\n", pinInfo.pinReference, pinData.size(),
            resp.statusWord());
#endif
    if (resp.isSuccess())
        return 1;
    if (resp.sw1 == 0x63 && (resp.sw2 & 0xF0) == 0xC0)
        return 0; // wrong PIN — do NOT try alternate reference, it would burn another retry

    // Primary reference was not recognized (6A86/6A88/etc.) — try stripping local bit
    uint8_t altRef = pinInfo.pinReference & 0x7F;
    if (altRef != pinInfo.pinReference) {
        auto resp2 =
            channel.transmit(LibreSCRS::SmartCard::Internal::verifyPIN(altRef, pinData), LibreSCRS::CancelToken{});
#ifndef NDEBUG
        fprintf(stderr, "[PKCS15] verifyPIN altRef=0x%02X SW=%04X\n", altRef, resp2.statusWord());
#endif
        if (resp2.isSuccess())
            return 1;
        if (resp2.sw1 == 0x63 && (resp2.sw2 & 0xF0) == 0xC0)
            return 0; // wrong PIN
    }
    return -1;
}

PKCS15Card::KeyRefInfo PKCS15Card::resolveKeyRef(const PrivateKeyInfo& key)
{
    if (key.keyReference != 0)
        return {0x84, {key.keyReference}};
    if (!key.path.empty())
        return {0x81, {0x00, key.path.back()}};
    return {0x84, {0x00}};
}

std::vector<uint8_t> PKCS15Card::tryMsePsoOid(std::span<const uint8_t> algoOid, const KeyRefInfo& keyRef,
                                              const std::vector<uint8_t>& psoData, uint16_t expectedSigLen,
                                              uint16_t& lastSW)
{
    std::vector<uint8_t> mseData;
    mseData.reserve(2 + algoOid.size() + 2 + keyRef.keyRefData.size());
    mseData.push_back(0x80);
    mseData.push_back(static_cast<uint8_t>(algoOid.size()));
    mseData.insert(mseData.end(), algoOid.begin(), algoOid.end());
    mseData.push_back(keyRef.keyTag);
    mseData.push_back(static_cast<uint8_t>(keyRef.keyRefData.size()));
    mseData.insert(mseData.end(), keyRef.keyRefData.begin(), keyRef.keyRefData.end());
#ifndef NDEBUG
    fprintf(stderr, "[PKCS15] MSE SET OID: oid=");
    for (auto b : algoOid)
        fprintf(stderr, "%02X", b);
    fprintf(stderr, " keyTag=0x%02X keyRef=", keyRef.keyTag);
    for (auto b : keyRef.keyRefData)
        fprintf(stderr, "%02X", b);
    fprintf(stderr, " psoDataLen=%zu\n", psoData.size());
#endif
    LibreSCRS::SmartCard::Internal::APDUCommand mseSet{
        .cla = 0x00, .ins = 0x22, .p1 = 0x41, .p2 = 0xB6, .data = std::move(mseData), .le = 0, .hasLe = false};
    auto resp = channel.transmit(mseSet, LibreSCRS::CancelToken{});
#ifndef NDEBUG
    fprintf(stderr, "[PKCS15] MSE SET OID SW=%04X\n", resp.statusWord());
#endif
    if (!resp.isSuccess()) {
        lastSW = resp.statusWord();
        return {};
    }
    uint16_t psoLe = (expectedSigLen <= 256) ? 0 : expectedSigLen;
    LibreSCRS::SmartCard::Internal::APDUCommand pso{
        .cla = 0x00, .ins = 0x2A, .p1 = 0x9E, .p2 = 0x9A, .data = psoData, .le = psoLe, .hasLe = true};
    resp = channel.transmit(pso, LibreSCRS::CancelToken{});
    lastSW = resp.statusWord();
#ifndef NDEBUG
    fprintf(stderr, "[PKCS15] PSO COMPUTE (OID) SW=%04X sigLen=%zu\n", resp.statusWord(), resp.data.size());
#endif
    return resp.isSuccess() ? resp.data : std::vector<uint8_t>{};
}

std::vector<uint8_t> PKCS15Card::tryMsePso(uint8_t sigAlgo, const KeyRefInfo& keyRef,
                                           const std::vector<uint8_t>& psoData, uint16_t expectedSigLen,
                                           uint16_t& lastSW)
{
    std::vector<uint8_t> mseData = {0x80, 0x01, sigAlgo, keyRef.keyTag, static_cast<uint8_t>(keyRef.keyRefData.size())};
    mseData.insert(mseData.end(), keyRef.keyRefData.begin(), keyRef.keyRefData.end());
#ifndef NDEBUG
    fprintf(stderr, "[PKCS15] MSE SET: algo=0x%02X keyTag=0x%02X keyRef=", sigAlgo, keyRef.keyTag);
    for (auto b : keyRef.keyRefData)
        fprintf(stderr, "%02X", b);
    fprintf(stderr, " psoDataLen=%zu\n", psoData.size());
#endif
    LibreSCRS::SmartCard::Internal::APDUCommand mseSet{
        .cla = 0x00, .ins = 0x22, .p1 = 0x41, .p2 = 0xB6, .data = std::move(mseData), .le = 0, .hasLe = false};
    auto resp = channel.transmit(mseSet, LibreSCRS::CancelToken{});
#ifndef NDEBUG
    fprintf(stderr, "[PKCS15] MSE SET SW=%04X\n", resp.statusWord());
#endif
    if (!resp.isSuccess()) {
        lastSW = resp.statusWord();
        return {};
    }
    // Le=0x00 in short APDU means "expect up to 256 bytes" — avoids triggering
    // extended APDU encoding (2-byte Le) which some cards don't support.
    uint16_t psoLe = (expectedSigLen <= 256) ? 0 : expectedSigLen;
    LibreSCRS::SmartCard::Internal::APDUCommand pso{
        .cla = 0x00, .ins = 0x2A, .p1 = 0x9E, .p2 = 0x9A, .data = psoData, .le = psoLe, .hasLe = true};
    resp = channel.transmit(pso, LibreSCRS::CancelToken{});
    lastSW = resp.statusWord();
#ifndef NDEBUG
    fprintf(stderr, "[PKCS15] PSO COMPUTE SW=%04X sigLen=%zu\n", resp.statusWord(), resp.data.size());
#endif
    return resp.isSuccess() ? resp.data : std::vector<uint8_t>{};
}

std::vector<uint8_t> PKCS15Card::sign(const PrivateKeyInfo& key, std::string_view pin, const PinInfo& pinInfo,
                                      const std::vector<uint8_t>& digestInfo, const std::vector<uint8_t>& rawData,
                                      SignScheme scheme)
{
    auto pinData = encodePIN(pin, pinInfo);
    auto keyRef = resolveKeyRef(key);
    uint16_t sigLen = key.keySizeBits > 0 ? (key.keySizeBits / 8) : 256;
#ifndef NDEBUG
    fprintf(stderr, "[PKCS15] sign(): keyRef=%d keyPath=", key.keyReference);
    for (auto b : key.path)
        fprintf(stderr, "%02X", b);
    fprintf(stderr, " keySizeBits=%d scheme=%d\n", key.keySizeBits, static_cast<int>(scheme));
    fprintf(stderr, "[PKCS15] resolved: tag=0x%02X ref=", keyRef.keyTag);
    for (auto b : keyRef.keyRefData)
        fprintf(stderr, "%02X", b);
    fprintf(stderr, " pinRef=0x%02X pinPath=", pinInfo.pinReference);
    for (auto b : pinInfo.path)
        fprintf(stderr, "%02X", b);
    fprintf(stderr, " pinStoredLen=%d\n", pinInfo.storedLength);
#endif

    struct AlgoAttempt
    {
        uint8_t sigAlgo;
        std::vector<uint8_t> psoData;
    };
    std::vector<AlgoAttempt> attempts;

    if (scheme == SignScheme::RsaPkcs1) {
        attempts.push_back({sig_algo::RSA_RAW, digestInfo});
        attempts.push_back({sig_algo::RSA_PKCS1_V15, digestInfo});
        // Some cards (e.g. SafeSign) accept algo 0x02 but expect full padded block
        if (sigLen > digestInfo.size() + 11) {
            auto padded = applyPkcs1v15Padding(digestInfo, key.keySizeBits);
            attempts.push_back({sig_algo::RSA_PKCS1_V15, padded});
            // True-RAW path: pre-pad on host, card does only the RSA private
            // operation. Required by some IAS-ECC SSCDs (Cryptovision
            // SCE 8.0-C2V0) that lock down all hash-on-card algos but
            // still expose raw RSA for SSCD use.
            attempts.push_back({sig_algo::RSA_RAW, std::move(padded)});
        }
        auto rawHash = extractRawHash(digestInfo);
        // Some cards expect only raw hash with algo 0x02, not DigestInfo
        if (!rawHash.empty())
            attempts.push_back({sig_algo::RSA_PKCS1_V15, rawHash});
        // IAS-ECC SHA-256 PKCS#1 algo (Cryptovision SCE 8.0 family). Try
        // this BEFORE the legacy 0x28 because some IAS-ECC cards quietly
        // accept 0x28 as a custom mechanism that re-hashes the input
        // (producing a structurally valid but semantically wrong signature
        // that fails downstream verification). The tryAllAttempts loop
        // returns on first non-empty signature, so ordering matters.
        if (rawHash.size() == 32)
            attempts.push_back({sig_algo::RSA_SHA256_PKCS1_IASECC, rawHash});
        uint8_t ha = 0;
        if (rawHash.size() == 20)
            ha = sig_algo::RSA_SHA1_PKCS1;
        else if (rawHash.size() == 32)
            ha = sig_algo::RSA_SHA256_PKCS1;
        else if (rawHash.size() == 48)
            ha = sig_algo::RSA_SHA384_PKCS1;
        else if (rawHash.size() == 64)
            ha = sig_algo::RSA_SHA512_PKCS1;
        if (ha != 0)
            attempts.push_back({ha, rawHash});
    } else if (scheme == SignScheme::RsaSha1Pkcs1) {
        // Hash-specific algo: card hashes internally, send raw data.
        // Fallback: pre-hashed for cards that expect hash input.
        auto h = computeHash(EVP_sha1(), rawData);
        attempts.push_back({sig_algo::RSA_RAW, digestInfo});
        attempts.push_back({sig_algo::RSA_PKCS1_V15, digestInfo});
        attempts.push_back({sig_algo::RSA_SHA1_PKCS1, rawData});
        attempts.push_back({sig_algo::RSA_SHA1_PKCS1, h});
    } else if (scheme == SignScheme::RsaSha256Pkcs1) {
        auto h = computeHash(EVP_sha256(), rawData);
        attempts.push_back({sig_algo::RSA_RAW, digestInfo});
        attempts.push_back({sig_algo::RSA_PKCS1_V15, digestInfo});
        attempts.push_back({sig_algo::RSA_SHA256_PKCS1, rawData});
        attempts.push_back({sig_algo::RSA_SHA256_PKCS1, h});
        attempts.push_back({sig_algo::RSA_SHA256_PKCS1_IASECC, h});
    } else if (scheme == SignScheme::RsaSha384Pkcs1) {
        auto h = computeHash(EVP_sha384(), rawData);
        attempts.push_back({sig_algo::RSA_RAW, digestInfo});
        attempts.push_back({sig_algo::RSA_PKCS1_V15, digestInfo});
        attempts.push_back({sig_algo::RSA_SHA384_PKCS1, rawData});
        attempts.push_back({sig_algo::RSA_SHA384_PKCS1, h});
    } else if (scheme == SignScheme::RsaSha512Pkcs1) {
        auto h = computeHash(EVP_sha512(), rawData);
        attempts.push_back({sig_algo::RSA_RAW, digestInfo});
        attempts.push_back({sig_algo::RSA_PKCS1_V15, digestInfo});
        attempts.push_back({sig_algo::RSA_SHA512_PKCS1, rawData});
        attempts.push_back({sig_algo::RSA_SHA512_PKCS1, h});
    } else if (scheme == SignScheme::RsaPssSha256) {
        auto h = computeHash(EVP_sha256(), rawData);
        attempts.push_back({sig_algo::RSASSA_PSS_SHA256, h});
        attempts.push_back(
            {sig_algo::RSA_RAW, applyPssPadding(h, EVP_sha256(), key.keySizeBits > 0 ? key.keySizeBits : 2048)});
    } else if (scheme == SignScheme::RsaPssSha384) {
        auto h = computeHash(EVP_sha384(), rawData);
        attempts.push_back({sig_algo::RSASSA_PSS_SHA384, h});
        attempts.push_back(
            {sig_algo::RSA_RAW, applyPssPadding(h, EVP_sha384(), key.keySizeBits > 0 ? key.keySizeBits : 2048)});
    } else if (scheme == SignScheme::RsaPssSha512) {
        auto h = computeHash(EVP_sha512(), rawData);
        attempts.push_back({sig_algo::RSASSA_PSS_SHA512, h});
        attempts.push_back(
            {sig_algo::RSA_RAW, applyPssPadding(h, EVP_sha512(), key.keySizeBits > 0 ? key.keySizeBits : 2048)});
    } else if (scheme == SignScheme::EcdsaRaw) {
        // ECDSA: send pre-hashed data directly to PSO:CDS, no DigestInfo wrapping.
        attempts.push_back({sig_algo::ECDSA_PLAIN, digestInfo});
    } else {
        throw std::runtime_error("PKCS15: unsupported sign scheme");
    }

    uint16_t lastPsoSW = 0;

    // Alternative key reference: try tag 0x81 (file ref) if primary is 0x84, or vice versa.
    // Some cards only accept one tag format — we try both before giving up.
    KeyRefInfo altKeyRef = {0x81, {0x00, key.keyReference}};
    if (keyRef.keyTag == 0x81)
        altKeyRef = {0x84, {key.keyReference != 0 ? key.keyReference : uint8_t(0x00)}};

    // BSI TR-03110 / ISO 7816-8 algorithm OIDs for cards (Cryptovision
    // SCE 8.0-C2V0 SSCD and family) that reject the legacy 1-byte algo
    // reference. Each entry is paired with the canonical PSO input shape
    // the OID implies (raw hash for hash-specific OIDs, DigestInfo /
    // padded-block for the generic RSA OID).
    struct OidAttempt
    {
        std::span<const uint8_t> oid;
        std::vector<uint8_t> psoData;
    };
    auto rawHashForOid = extractRawHash(digestInfo);
    std::vector<OidAttempt> oidAttempts;
    if (scheme == SignScheme::RsaPkcs1 || scheme == SignScheme::RsaSha256Pkcs1) {
        // sigS_PKCS1_V15_SHA_256 = 0.4.0.127.0.7.2.2.2.1.3
        static constexpr uint8_t kSigPkcs1Sha256[] = {0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x02, 0x01, 0x03};
        if (rawHashForOid.size() == 32)
            oidAttempts.push_back({kSigPkcs1Sha256, rawHashForOid});
    }
    if (scheme == SignScheme::RsaPkcs1 || scheme == SignScheme::RsaSha1Pkcs1) {
        // sigS_PKCS1_V15_SHA_1 = 0.4.0.127.0.7.2.2.2.1.1
        static constexpr uint8_t kSigPkcs1Sha1[] = {0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x02, 0x01, 0x01};
        if (rawHashForOid.size() == 20)
            oidAttempts.push_back({kSigPkcs1Sha1, rawHashForOid});
    }
    if (scheme == SignScheme::RsaPkcs1 || scheme == SignScheme::RsaSha384Pkcs1) {
        // sigS_PKCS1_V15_SHA_384 = 0.4.0.127.0.7.2.2.2.1.4
        static constexpr uint8_t kSigPkcs1Sha384[] = {0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x02, 0x01, 0x04};
        if (rawHashForOid.size() == 48)
            oidAttempts.push_back({kSigPkcs1Sha384, rawHashForOid});
    }
    if (scheme == SignScheme::RsaPkcs1 || scheme == SignScheme::RsaSha512Pkcs1) {
        // sigS_PKCS1_V15_SHA_512 = 0.4.0.127.0.7.2.2.2.1.5
        static constexpr uint8_t kSigPkcs1Sha512[] = {0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x02, 0x01, 0x05};
        if (rawHashForOid.size() == 64)
            oidAttempts.push_back({kSigPkcs1Sha512, rawHashForOid});
    }
    if (scheme == SignScheme::RsaPssSha256) {
        // sigS_PSS_SHA_256 = 0.4.0.127.0.7.2.2.2.2.3
        static constexpr uint8_t kSigPssSha256[] = {0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x02, 0x02, 0x03};
        auto h = computeHash(EVP_sha256(), rawData);
        oidAttempts.push_back({kSigPssSha256, std::move(h)});
    }
    if (scheme == SignScheme::RsaPssSha384) {
        static constexpr uint8_t kSigPssSha384[] = {0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x02, 0x02, 0x04};
        auto h = computeHash(EVP_sha384(), rawData);
        oidAttempts.push_back({kSigPssSha384, std::move(h)});
    }
    if (scheme == SignScheme::RsaPssSha512) {
        static constexpr uint8_t kSigPssSha512[] = {0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x02, 0x02, 0x05};
        auto h = computeHash(EVP_sha512(), rawData);
        oidAttempts.push_back({kSigPssSha512, std::move(h)});
    }

    auto tryAllAttempts = [&]() -> std::vector<uint8_t> {
        // OID-style attempts first — BSI TR-03110 cards reject legacy 1-byte
        // algo references with SW 6A80 / wrong-padded-block on PSO. When
        // none of the OID attempts succeed (the typical case on legacy
        // cards that don't speak the OID dialect), fall through to the
        // single-byte form.
        for (const auto& a : oidAttempts) {
            auto sig = tryMsePsoOid(a.oid, keyRef, a.psoData, sigLen, lastPsoSW);
            if (!sig.empty())
                return sig;
        }
        for (const auto& a : oidAttempts) {
            auto sig = tryMsePsoOid(a.oid, altKeyRef, a.psoData, sigLen, lastPsoSW);
            if (!sig.empty())
                return sig;
        }
        for (const auto& a : attempts) {
            auto sig = tryMsePso(a.sigAlgo, keyRef, a.psoData, sigLen, lastPsoSW);
            if (!sig.empty())
                return sig;
        }
        for (const auto& a : attempts) {
            auto sig = tryMsePso(a.sigAlgo, altKeyRef, a.psoData, sigLen, lastPsoSW);
            if (!sig.empty())
                return sig;
        }
        return {};
    };

    // Strategy 1: AID-based — verify PIN inline, then sign
#ifndef NDEBUG
    fprintf(stderr, "[PKCS15] Strategy 1: AID-based\n");
#endif
    if (!selectApplet())
        throw std::runtime_error("PKCS15: failed to select applet");
    int pinStatus = verifyPinInline(pinInfo, pinData);
    if (pinStatus == 0)
        throw std::runtime_error("PKCS15: wrong PIN");
    if (pinStatus == 1) {
        auto result = tryAllAttempts();
        if (!result.empty())
            return result;
#ifndef NDEBUG
        fprintf(stderr, "[PKCS15] Strategy 1: all attempts failed, lastSW=%04X\n", lastPsoSW);
#endif
    }

    // Strategy 2: path-based — navigate to PIN's DF, verify, then navigate to
    // the key's DF (NOT AID SELECT which resets security state on some cards,
    // and NOT the metadata PKCS#15 DF which would miss SSCD-bound keys whose
    // file lives outside DF_PKCS15_FID — observed on GEO QSCD where the
    // sign key path resolves under a sibling DF). When the key has no
    // explicit path (or only a 2-byte FID) we fall back to the metadata
    // DF so SR eID and other "key under DF_PKCS15_FID" cards keep working.
    if (!pinInfo.path.empty()) {
#ifndef NDEBUG
        fprintf(stderr, "[PKCS15] Strategy 2: path-based\n");
#endif
        selectByPath(pinInfo.path);
        pinStatus = verifyPinInline(pinInfo, pinData);
        if (pinStatus == 0)
            throw std::runtime_error("PKCS15: wrong PIN");
        if (pinStatus == 1) {
            // Prefer the key's DF (drop the trailing 2-byte EF when the
            // path ends with the key file itself). When key.path is
            // empty or only encodes a bare 2-byte FID, fall back to the
            // PKCS#15 metadata DF to preserve pre-4.1 behaviour for
            // cards whose key file lives directly under it.
            std::vector<std::uint8_t> targetPath;
            if (key.path.size() >= 4 && (key.path.size() % 2) == 0) {
                targetPath.assign(key.path.begin(), key.path.end() - 2);
            } else {
                targetPath.assign(DF_PKCS15_FID.begin(), DF_PKCS15_FID.end());
            }
            selectByPath(targetPath);
            auto result = tryAllAttempts();
            if (!result.empty())
                return result;
#ifndef NDEBUG
            fprintf(stderr, "[PKCS15] Strategy 2: all attempts failed, lastSW=%04X\n", lastPsoSW);
#endif
        }
    }

    throw std::runtime_error("PKCS15: all signing attempts failed");
}

std::vector<uint8_t> PKCS15Card::extractRawHash(const std::vector<uint8_t>& digestInfo)
{
    // DER DigestInfo: SEQUENCE { SEQUENCE { OID, NULL }, OCTET STRING hash }
    // Extract the raw hash from a DER-encoded DigestInfo structure.
    if (digestInfo.size() < 11 || digestInfo[0] != 0x30)
        return {};

    auto readLen = [&](size_t& pos) -> size_t {
        if (pos >= digestInfo.size())
            return 0;
        uint8_t first = digestInfo[pos++];
        if (first < 0x80)
            return first;
        size_t nBytes = first & 0x7F;
        if (nBytes == 0 || nBytes > 2 || pos + nBytes > digestInfo.size())
            return 0;
        size_t len = 0;
        for (size_t i = 0; i < nBytes; ++i)
            len = (len << 8) | digestInfo[pos++];
        return len;
    };

    size_t pos = 1; // skip outer SEQUENCE tag
    readLen(pos);   // skip outer length

    // Inner SEQUENCE (AlgorithmIdentifier)
    if (pos >= digestInfo.size() || digestInfo[pos] != 0x30)
        return {};
    pos++; // skip tag
    size_t innerLen = readLen(pos);
    pos += innerLen; // skip AlgorithmIdentifier content

    // OCTET STRING containing hash
    if (pos >= digestInfo.size() || digestInfo[pos] != 0x04)
        return {};
    pos++; // skip tag
    size_t hashLen = readLen(pos);

    if (pos + hashLen > digestInfo.size())
        return {};

    return {digestInfo.begin() + static_cast<ptrdiff_t>(pos),
            digestInfo.begin() + static_cast<ptrdiff_t>(pos + hashLen)};
}

bool PKCS15Card::selectByPath(std::span<const uint8_t> path, uint8_t selectP2)
{
    const bool trace = std::getenv("LIBRESCRS_SIGN_TRACE") != nullptr;
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
        auto resp = channel.transmit(LibreSCRS::SmartCard::Internal::selectByFileId(path[i], path[i + 1], p2),
                                     LibreSCRS::CancelToken{});
        if (trace)
            std::fprintf(stderr, "[PKCS15::selectByPath] FID=%02X%02X P2=%02X SW=%04X\n", path[i], path[i + 1], p2,
                         resp.statusWord());
        if (resp.isSuccess())
            continue;

        // Try alternative P2 on retryable errors
        if (resp.statusWord() == 0x6700 || resp.statusWord() == 0x6A86) {
            uint8_t altP2 = (p2 == 0x0C) ? 0x00 : 0x0C;
            resp = channel.transmit(LibreSCRS::SmartCard::Internal::selectByFileId(path[i], path[i + 1], altP2),
                                    LibreSCRS::CancelToken{});
            if (trace)
                std::fprintf(stderr, "[PKCS15::selectByPath] FID=%02X%02X retry altP2=%02X SW=%04X\n", path[i],
                             path[i + 1], altP2, resp.statusWord());
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
        auto resp =
            channel.transmit(LibreSCRS::SmartCard::Internal::readBinary(static_cast<uint16_t>(offset), READ_CHUNK_SIZE),
                             LibreSCRS::CancelToken{});

        // 6282 = standard EOF; 6A86 = some tokens signal EOF this way
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
