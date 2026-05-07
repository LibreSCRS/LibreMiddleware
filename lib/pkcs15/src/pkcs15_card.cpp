// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "pkcs15_card.h"
#include "pkcs15_parser.h"
#include "pkcs15_types.h"
#include <apdu.h>
#include <smartcard/pcsc_connection.h>
#include <smartcard/secure_buffer.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <cstdio>
#include <memory>
#include <stdexcept>

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

PKCS15Card::PKCS15Card(smartcard::PCSCConnection& conn) : conn(conn) {}

bool PKCS15Card::probe()
{
    // Strategy A: try AID SELECT first (fast path)
    std::vector<uint8_t> aid(kPkcs15Aid.begin(), kPkcs15Aid.end());
    auto resp = conn.transmit(smartcard::selectByAID(aid, 0x0C));
    if (resp.isSuccess()) {
        pkcs15Path.clear(); // AID works, no path needed
        fileSelectP2 = 0x0C;
        return true;
    }

    // Fallback: try AID with P2=0x00 (some cards need FCI)
    resp = conn.transmit(smartcard::selectByAID(aid));
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
        std::vector<uint8_t> aid(kPkcs15Aid.begin(), kPkcs15Aid.end());
        auto resp = conn.transmit(smartcard::selectByAID(aid, 0x0C));
        if (resp.isSuccess())
            return true;
        resp = conn.transmit(smartcard::selectByAID(aid));
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
    smartcard::CardTransaction tx(conn);

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
        if (selectByPath(odf.authObjectsPath)) {
            auto aodfData = readSelectedFile();
            profile.pins = parseAODF(aodfData);
        }
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

PinResult PKCS15Card::verifyPIN(const PinInfo& pin, std::string_view pinValue)
{
    smartcard::CardTransaction tx(conn);
    if (!selectApplet())
        throw std::runtime_error("PKCS15: failed to select applet");

    if (!pin.path.empty())
        selectByPath(pin.path);

    auto pinData = encodePIN(pinValue, pin);

    // Try pinReference directly
    auto resp = conn.transmit(smartcard::verifyPIN(pin.pinReference, pinData));
    if (resp.isSuccess())
        return {true, -1, false};
    if (resp.sw1 == 0x63 && (resp.sw2 & 0xF0) == 0xC0)
        return {false, resp.sw2 & 0x0F, false};
    if (resp.statusWord() == 0x6983)
        return {false, 0, true};

    // Fallback: strip local bit
    uint8_t altRef = pin.pinReference & 0x7F;
    if (altRef != pin.pinReference) {
        resp = conn.transmit(smartcard::verifyPIN(altRef, pinData));
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
    smartcard::CardTransaction tx(conn);
    if (!selectApplet())
        throw std::runtime_error("PKCS15: failed to select applet");

    if (!pin.path.empty())
        selectByPath(pin.path);

    auto oldData = encodePIN(oldPin, pin);
    auto newData = encodePIN(newPin, pin);

    auto resp = conn.transmit(smartcard::changeReferenceData(pin.pinReference, oldData, newData));
    if (resp.isSuccess())
        return {true, -1, false};
    if (resp.sw1 == 0x63 && (resp.sw2 & 0xF0) == 0xC0)
        return {false, resp.sw2 & 0x0F, false};
    if (resp.statusWord() == 0x6983)
        return {false, 0, true};

    // Fallback: strip local bit — ONLY on reference-not-found errors
    uint8_t altRef = pin.pinReference & 0x7F;
    if (altRef != pin.pinReference && (resp.statusWord() == 0x6A86 || resp.statusWord() == 0x6A88)) {
        resp = conn.transmit(smartcard::changeReferenceData(altRef, oldData, newData));
        if (resp.isSuccess())
            return {true, -1, false};
        if (resp.sw1 == 0x63 && (resp.sw2 & 0xF0) == 0xC0)
            return {false, resp.sw2 & 0x0F, false};
        if (resp.statusWord() == 0x6983)
            return {false, 0, true};
    }

    return {false, -1, false};
}

smartcard::SecureBuffer PKCS15Card::encodePIN(std::string_view pin, const PinInfo& pinInfo)
{
    smartcard::SecureBuffer pinData(pin);
    if (pinInfo.storedLength > 0 && static_cast<int>(pinData.size()) > pinInfo.storedLength)
        pinData.resize(pinInfo.storedLength);
    if (pinInfo.storedLength > 0 && static_cast<int>(pinData.size()) < pinInfo.storedLength)
        pinData.resize(pinInfo.storedLength, pinInfo.padChar);
    return pinData;
}

int PKCS15Card::verifyPinInline(const PinInfo& pinInfo, const smartcard::SecureBuffer& pinData)
{
    auto resp = conn.transmit(smartcard::verifyPIN(pinInfo.pinReference, pinData));
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
        auto resp2 = conn.transmit(smartcard::verifyPIN(altRef, pinData));
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
    smartcard::APDUCommand mseSet{
        .cla = 0x00, .ins = 0x22, .p1 = 0x41, .p2 = 0xB6, .data = std::move(mseData), .le = 0, .hasLe = false};
    auto resp = conn.transmit(mseSet);
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
    smartcard::APDUCommand pso{
        .cla = 0x00, .ins = 0x2A, .p1 = 0x9E, .p2 = 0x9A, .data = psoData, .le = psoLe, .hasLe = true};
    resp = conn.transmit(pso);
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
    smartcard::CardTransaction tx(conn);
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
        if (sigLen > digestInfo.size() + 11)
            attempts.push_back({sig_algo::RSA_PKCS1_V15, applyPkcs1v15Padding(digestInfo, key.keySizeBits)});
        auto rawHash = extractRawHash(digestInfo);
        // Some cards expect only raw hash with algo 0x02, not DigestInfo
        if (!rawHash.empty())
            attempts.push_back({sig_algo::RSA_PKCS1_V15, rawHash});
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

    auto tryAllAttempts = [&]() -> std::vector<uint8_t> {
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
    // PKCS#15 DF by path (NOT AID SELECT which resets security state on some cards).
    if (!pinInfo.path.empty()) {
#ifndef NDEBUG
        fprintf(stderr, "[PKCS15] Strategy 2: path-based\n");
#endif
        selectByPath(pinInfo.path);
        pinStatus = verifyPinInline(pinInfo, pinData);
        if (pinStatus == 0)
            throw std::runtime_error("PKCS15: wrong PIN");
        if (pinStatus == 1) {
            selectByPath(DF_PKCS15_FID);
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
