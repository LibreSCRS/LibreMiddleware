// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <emrtd/crypto/chip_auth.h>
#include "crypto_utils.h"

#include <smartcard/apdu.h>
#include <smartcard/pcsc_connection.h>

#include <limits>

#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>
#include <openssl/x509.h>

#include <algorithm>
#include <cstring>
#include <memory>
#include <stdexcept>

namespace emrtd::crypto {

// ---------------------------------------------------------------------------
// RAII wrappers for OpenSSL types
// ---------------------------------------------------------------------------

struct BNDeleter
{
    void operator()(BIGNUM* p) const
    {
        BN_free(p);
    }
};
struct BNCtxDeleter
{
    void operator()(BN_CTX* p) const
    {
        BN_CTX_free(p);
    }
};
struct ECGroupDeleter
{
    void operator()(EC_GROUP* p) const
    {
        EC_GROUP_free(p);
    }
};
struct ECPointDeleter
{
    void operator()(EC_POINT* p) const
    {
        EC_POINT_free(p);
    }
};
struct EVPPKeyDeleter
{
    void operator()(EVP_PKEY* p) const
    {
        EVP_PKEY_free(p);
    }
};
struct EVPPKeyCtxDeleter
{
    void operator()(EVP_PKEY_CTX* p) const
    {
        EVP_PKEY_CTX_free(p);
    }
};

using BNPtr = std::unique_ptr<BIGNUM, BNDeleter>;
using BNCtxPtr = std::unique_ptr<BN_CTX, BNCtxDeleter>;
using ECGroupPtr = std::unique_ptr<EC_GROUP, ECGroupDeleter>;
using ECPointPtr = std::unique_ptr<EC_POINT, ECPointDeleter>;
using EVPPKeyPtr = std::unique_ptr<EVP_PKEY, EVPPKeyDeleter>;
using EVPPKeyCtxPtr = std::unique_ptr<EVP_PKEY_CTX, EVPPKeyCtxDeleter>;

// ---------------------------------------------------------------------------
// BER-TLV helpers
// ---------------------------------------------------------------------------

static std::pair<size_t, size_t> parseBERLength(const std::vector<uint8_t>& data, size_t pos)
{
    if (pos >= data.size())
        return {0, 0};

    uint8_t first = data[pos];
    if (first < 0x80) {
        return {first, 1};
    }
    size_t numBytes = first & 0x7F;
    if (numBytes == 0 || numBytes > sizeof(size_t) || pos + 1 + numBytes > data.size())
        return {0, 0};

    size_t len = 0;
    for (size_t i = 0; i < numBytes; ++i) {
        len = (len << 8) | data[pos + 1 + i];
    }
    return {len, 1 + numBytes};
}

static std::string oidBytesToString(const uint8_t* data, size_t len)
{
    if (len == 0)
        return {};

    std::string result;
    result += std::to_string(data[0] / 40) + "." + std::to_string(data[0] % 40);

    unsigned long value = 0;
    for (size_t i = 1; i < len; ++i) {
        if (value > (std::numeric_limits<unsigned long>::max() >> 7))
            return {}; // overflow protection
        value = (value << 7) | (data[i] & 0x7F);
        if ((data[i] & 0x80) == 0) {
            result += "." + std::to_string(value);
            value = 0;
        }
    }
    return result;
}

static std::vector<uint8_t> oidStringToBytes(const std::string& oid)
{
    std::vector<unsigned long> components;
    size_t start = 0;
    while (start < oid.size()) {
        size_t dot = oid.find('.', start);
        if (dot == std::string::npos)
            dot = oid.size();
        components.push_back(std::stoul(oid.substr(start, dot - start)));
        start = dot + 1;
    }

    if (components.size() < 2)
        return {};
    if (components[0] > 2 || (components[0] < 2 && components[1] > 39))
        return {};

    std::vector<uint8_t> bytes;
    unsigned long firstByte = components[0] * 40 + components[1];
    if (firstByte > 255)
        return {};
    bytes.push_back(static_cast<uint8_t>(firstByte));

    for (size_t i = 2; i < components.size(); ++i) {
        unsigned long val = components[i];
        std::vector<uint8_t> encoded;
        encoded.push_back(static_cast<uint8_t>(val & 0x7F));
        val >>= 7;
        while (val > 0) {
            encoded.push_back(static_cast<uint8_t>((val & 0x7F) | 0x80));
            val >>= 7;
        }
        std::reverse(encoded.begin(), encoded.end());
        bytes.insert(bytes.end(), encoded.begin(), encoded.end());
    }
    return bytes;
}

static std::vector<uint8_t> buildTLV(uint8_t tag, const std::vector<uint8_t>& value)
{
    std::vector<uint8_t> result;
    result.push_back(tag);
    size_t len = value.size();
    if (len < 0x80) {
        result.push_back(static_cast<uint8_t>(len));
    } else if (len <= 0xFF) {
        result.push_back(0x81);
        result.push_back(static_cast<uint8_t>(len));
    } else {
        result.push_back(0x82);
        result.push_back(static_cast<uint8_t>((len >> 8) & 0xFF));
        result.push_back(static_cast<uint8_t>(len & 0xFF));
    }
    result.insert(result.end(), value.begin(), value.end());
    return result;
}

// ---------------------------------------------------------------------------
// OID constants for Chip Authentication
// ---------------------------------------------------------------------------

// id-PK-ECDH: 0.4.0.127.0.7.2.2.1.2
static const std::string OID_PK_ECDH = "0.4.0.127.0.7.2.2.1.2";

// id-CA prefix: 0.4.0.127.0.7.2.2.3
static const std::string OID_CA_PREFIX = "0.4.0.127.0.7.2.2.3";

// id-PK prefix: 0.4.0.127.0.7.2.2.1
static const std::string OID_PK_PREFIX = "0.4.0.127.0.7.2.2.1";

static bool isCAOID(const std::string& oid)
{
    return oid.size() > OID_CA_PREFIX.size() && oid.substr(0, OID_CA_PREFIX.size()) == OID_CA_PREFIX &&
           oid[OID_CA_PREFIX.size()] == '.';
}

static bool isPKOID(const std::string& oid)
{
    return oid.size() > OID_PK_PREFIX.size() && oid.substr(0, OID_PK_PREFIX.size()) == OID_PK_PREFIX &&
           oid[OID_PK_PREFIX.size()] == '.';
}

// ---------------------------------------------------------------------------
// parseDG14 — parse SecurityInfos from DG14 (tag 0x6E, SET OF SecurityInfo)
// ---------------------------------------------------------------------------

bool parseDG14(const std::vector<uint8_t>& dg14Raw, std::vector<ChipAuthInfo>& caInfos,
               std::vector<ChipAuthPublicKey>& caKeys)
{
    if (dg14Raw.size() < 4)
        return false;

    // DG14 starts with tag 0x6E
    size_t pos = 0;
    if (dg14Raw[pos] != 0x6E)
        return false;
    pos++;

    auto [outerLen, outerLenBytes] = parseBERLength(dg14Raw, pos);
    pos += outerLenBytes;
    if (outerLen == 0 || pos + outerLen > dg14Raw.size())
        return false;

    // Inside 0x6E: SET (0x31) OF SecurityInfo
    if (pos >= dg14Raw.size() || dg14Raw[pos] != 0x31)
        return false;
    pos++;

    auto [setLen, setLenBytes] = parseBERLength(dg14Raw, pos);
    pos += setLenBytes;
    size_t setEnd = pos + setLen;
    if (setEnd > dg14Raw.size())
        setEnd = dg14Raw.size();

    // Iterate SEQUENCE entries in the SET
    while (pos + 2 <= setEnd) {
        if (dg14Raw[pos] != 0x30) {
            // Skip non-SEQUENCE
            pos++;
            auto [skipLen, skipLenBytes] = parseBERLength(dg14Raw, pos);
            pos += skipLenBytes + skipLen;
            continue;
        }
        pos++; // skip 0x30 tag

        auto [seqLen, seqLenBytes] = parseBERLength(dg14Raw, pos);
        pos += seqLenBytes;
        size_t seqEnd = pos + seqLen;
        if (seqEnd > setEnd)
            break;

        // First element: OID (0x06)
        std::string oid;
        std::vector<uint8_t> oidRawBytes;
        if (pos < seqEnd && dg14Raw[pos] == 0x06) {
            pos++; // skip 0x06 tag
            auto [oidLen, oidLenBytes] = parseBERLength(dg14Raw, pos);
            pos += oidLenBytes;
            if (pos + oidLen <= seqEnd) {
                oid = oidBytesToString(dg14Raw.data() + pos, oidLen);
                oidRawBytes.assign(dg14Raw.begin() + static_cast<ptrdiff_t>(pos),
                                   dg14Raw.begin() + static_cast<ptrdiff_t>(pos + oidLen));
            }
            pos += oidLen;
        }

        if (isCAOID(oid)) {
            // ChipAuthenticationInfo: OID, version INTEGER, optional keyId INTEGER
            ChipAuthInfo info;
            info.oid = oidRawBytes;

            // Parse version INTEGER
            if (pos < seqEnd && dg14Raw[pos] == 0x02) {
                pos++;
                auto [intLen, intLenBytes] = parseBERLength(dg14Raw, pos);
                pos += intLenBytes;
                int val = 0;
                for (size_t i = 0; i < intLen && pos + i < seqEnd; ++i) {
                    val = (val << 8) | dg14Raw[pos + i];
                }
                info.version = val;
                pos += intLen;
            }

            // Parse optional keyId INTEGER
            if (pos < seqEnd && dg14Raw[pos] == 0x02) {
                pos++;
                auto [intLen, intLenBytes] = parseBERLength(dg14Raw, pos);
                pos += intLenBytes;
                int val = 0;
                for (size_t i = 0; i < intLen && pos + i < seqEnd; ++i) {
                    val = (val << 8) | dg14Raw[pos + i];
                }
                info.keyId = val;
                pos += intLen;
            }

            caInfos.push_back(std::move(info));
        } else if (isPKOID(oid)) {
            // ChipAuthenticationPublicKeyInfo: OID, SubjectPublicKeyInfo, optional keyId
            ChipAuthPublicKey key;
            key.oid = oidRawBytes;

            // The SubjectPublicKeyInfo is a SEQUENCE (tag 0x30)
            if (pos < seqEnd && dg14Raw[pos] == 0x30) {
                size_t spkiStart = pos;
                pos++; // skip 0x30 tag
                auto [spkiLen, spkiLenBytes] = parseBERLength(dg14Raw, pos);
                // SubjectPublicKeyInfo DER = tag + length bytes + content
                size_t spkiTotalLen = 1 + spkiLenBytes + spkiLen;
                if (spkiStart + spkiTotalLen <= seqEnd) {
                    key.publicKey.assign(dg14Raw.begin() + static_cast<ptrdiff_t>(spkiStart),
                                         dg14Raw.begin() + static_cast<ptrdiff_t>(spkiStart + spkiTotalLen));
                }
                pos = spkiStart + spkiTotalLen;
            }

            // Parse optional keyId INTEGER
            if (pos < seqEnd && dg14Raw[pos] == 0x02) {
                pos++;
                auto [intLen, intLenBytes] = parseBERLength(dg14Raw, pos);
                pos += intLenBytes;
                int val = 0;
                for (size_t i = 0; i < intLen && pos + i < seqEnd; ++i) {
                    val = (val << 8) | dg14Raw[pos + i];
                }
                key.keyId = val;
                pos += intLen;
            }

            caKeys.push_back(std::move(key));
        }

        pos = seqEnd;
    }

    return !caInfos.empty() || !caKeys.empty();
}

// ---------------------------------------------------------------------------
// Helper: determine CA algorithm properties from OID
// ---------------------------------------------------------------------------

struct CAAlgoInfo
{
    SMAlgorithm smAlgo = SMAlgorithm::AES;
    size_t keyLen = 16;
    bool isDES3 = false;
};

static CAAlgoInfo caAlgoFromOID(const std::string& oid)
{
    CAAlgoInfo info;

    // BSI TR-03110 Part 3, Table A.1:
    //   id-CA         = 0.4.0.127.0.7.2.2.3
    //   id-CA-DH      = {id-CA}.1          id-CA-ECDH      = {id-CA}.2
    //   ...DH-3DES    = {id-CA-DH}.1       ...ECDH-3DES    = {id-CA-ECDH}.1
    //   ...DH-AES-128 = {id-CA-DH}.2       ...ECDH-AES-128 = {id-CA-ECDH}.2
    //   ...DH-AES-192 = {id-CA-DH}.3       ...ECDH-AES-192 = {id-CA-ECDH}.3
    //   ...DH-AES-256 = {id-CA-DH}.4       ...ECDH-AES-256 = {id-CA-ECDH}.4
    //
    // The last OID component selects the cipher suite regardless of DH/ECDH.

    auto lastDot = oid.rfind('.');
    if (lastDot == std::string::npos || lastDot + 1 >= oid.size())
        return info;

    auto variant = oid.substr(lastDot + 1);

    if (variant == "1") {
        // 3DES-CBC-CBC
        info.smAlgo = SMAlgorithm::DES3;
        info.keyLen = 16;
        info.isDES3 = true;
    } else if (variant == "2") {
        // AES-CBC-CMAC-128
        info.smAlgo = SMAlgorithm::AES;
        info.keyLen = 16;
    } else if (variant == "3") {
        // AES-CBC-CMAC-192
        info.smAlgo = SMAlgorithm::AES;
        info.keyLen = 24;
    } else if (variant == "4") {
        // AES-CBC-CMAC-256
        info.smAlgo = SMAlgorithm::AES;
        info.keyLen = 32;
    }
    return info;
}

// ---------------------------------------------------------------------------
// Helper: parse SubjectPublicKeyInfo to extract EC group and public point
// ---------------------------------------------------------------------------

struct ParsedSPKI
{
    EVPPKeyPtr pkey;
    int nid = 0;
};

static std::optional<ParsedSPKI> parseSPKI(const std::vector<uint8_t>& der)
{
    if (der.empty())
        return std::nullopt;

    const uint8_t* p = der.data();
    EVP_PKEY* raw = d2i_PUBKEY(nullptr, &p, static_cast<long>(der.size()));
    if (!raw)
        return std::nullopt;

    EVPPKeyPtr pkey(raw);
    if (EVP_PKEY_id(pkey.get()) != EVP_PKEY_EC)
        return std::nullopt;

    // Extract EC group NID
    char curveName[64] = {};
    size_t curveNameLen = 0;
    if (!EVP_PKEY_get_utf8_string_param(pkey.get(), "group", curveName, sizeof(curveName), &curveNameLen))
        return std::nullopt;

    int nid = OBJ_txt2nid(curveName);
    if (nid == NID_undef)
        return std::nullopt;

    ParsedSPKI result;
    result.pkey = std::move(pkey);
    result.nid = nid;
    return result;
}

// ---------------------------------------------------------------------------
// Helper: extract uncompressed EC point bytes from EVP_PKEY
// ---------------------------------------------------------------------------

static std::vector<uint8_t> extractECPoint(EVP_PKEY* pkey)
{
    size_t len = 0;
    if (!EVP_PKEY_get_octet_string_param(pkey, "pub", nullptr, 0, &len))
        return {};

    std::vector<uint8_t> buf(len);
    if (!EVP_PKEY_get_octet_string_param(pkey, "pub", buf.data(), buf.size(), &len))
        return {};

    buf.resize(len);
    return buf;
}

// ---------------------------------------------------------------------------
// performChipAuth
// ---------------------------------------------------------------------------

ChipAuthResult performChipAuth(smartcard::PCSCConnection& conn, const std::vector<uint8_t>& dg14Raw,
                               SecureMessaging& currentSM)
{
    ChipAuthResult result;

    // --- Parse DG14 ---
    std::vector<ChipAuthInfo> caInfos;
    std::vector<ChipAuthPublicKey> caKeys;
    if (!parseDG14(dg14Raw, caInfos, caKeys)) {
        result.chipAuthentication = ChipAuthResult::NOT_SUPPORTED;
        result.errorDetail = "DG14 parsing failed or no CA data found";
        return result;
    }

    if (caKeys.empty()) {
        result.chipAuthentication = ChipAuthResult::NOT_SUPPORTED;
        result.errorDetail = "No ChipAuthenticationPublicKeyInfo found in DG14";
        return result;
    }

    // Select the first matching CA info and key pair (match by keyId if available)
    const ChipAuthPublicKey* selectedKey = &caKeys[0];
    std::string caOID;
    CAAlgoInfo algoInfo;

    if (!caInfos.empty()) {
        // Try to match by keyId
        for (const auto& info : caInfos) {
            std::string infoOID = oidBytesToString(info.oid.data(), info.oid.size());
            for (const auto& key : caKeys) {
                if (info.keyId == key.keyId || (!info.keyId.has_value() && !key.keyId.has_value())) {
                    selectedKey = &key;
                    caOID = infoOID;
                    algoInfo = caAlgoFromOID(caOID);
                    break;
                }
            }
            if (!caOID.empty())
                break;
        }
        if (caOID.empty()) {
            // Fallback: use first CA info
            caOID = oidBytesToString(caInfos[0].oid.data(), caInfos[0].oid.size());
            algoInfo = caAlgoFromOID(caOID);
        }
    } else {
        // No CA info, use default AES-128 CA OID
        caOID = OID_CA_PREFIX + ".2.1"; // id-CA-ECDH-AES-CBC-CMAC-128
        algoInfo = caAlgoFromOID(caOID);
    }

    result.protocol = caOID;
    result.newAlgorithm = algoInfo.smAlgo;

    // --- Parse the chip's public key from SubjectPublicKeyInfo ---
    auto parsed = parseSPKI(selectedKey->publicKey);
    if (!parsed) {
        result.chipAuthentication = ChipAuthResult::FAILED;
        result.errorDetail = "Failed to parse chip's SubjectPublicKeyInfo";
        return result;
    }

    // --- Generate ephemeral ECDH key pair on same curve ---
    EVPPKeyCtxPtr paramCtx(EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr));
    if (!paramCtx) {
        result.chipAuthentication = ChipAuthResult::FAILED;
        result.errorDetail = "EVP_PKEY_CTX_new_id failed";
        return result;
    }

    if (EVP_PKEY_keygen_init(paramCtx.get()) <= 0) {
        result.chipAuthentication = ChipAuthResult::FAILED;
        result.errorDetail = "EVP_PKEY_keygen_init failed";
        return result;
    }

    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(paramCtx.get(), parsed->nid) <= 0) {
        result.chipAuthentication = ChipAuthResult::FAILED;
        result.errorDetail = "EVP_PKEY_CTX_set_ec_paramgen_curve_nid failed";
        return result;
    }

    EVP_PKEY* ephRaw = nullptr;
    if (EVP_PKEY_keygen(paramCtx.get(), &ephRaw) <= 0 || !ephRaw) {
        result.chipAuthentication = ChipAuthResult::FAILED;
        result.errorDetail = "Ephemeral key generation failed";
        return result;
    }
    EVPPKeyPtr ephKey(ephRaw);

    // Extract terminal's public key bytes (uncompressed EC point)
    auto terminalPubBytes = extractECPoint(ephKey.get());
    if (terminalPubBytes.empty()) {
        result.chipAuthentication = ChipAuthResult::FAILED;
        result.errorDetail = "Failed to extract ephemeral public key";
        return result;
    }

    // --- MSE:Set AT ---
    auto caOIDBytes = oidStringToBytes(caOID);
    auto oidTLV = buildTLV(0x80, caOIDBytes);

    std::vector<uint8_t> mseData;
    mseData.insert(mseData.end(), oidTLV.begin(), oidTLV.end());

    // Add keyId if present
    if (selectedKey->keyId.has_value()) {
        auto keyIdTLV = buildTLV(0x84, {static_cast<uint8_t>(selectedKey->keyId.value())});
        mseData.insert(mseData.end(), keyIdTLV.begin(), keyIdTLV.end());
    }

    smartcard::APDUCommand mseCmd{0x00, 0x22, 0x41, 0xA4, mseData, 0, false};
    auto mseApdu = currentSM.protect(mseCmd.toBytes());

    auto mseResp = conn.transmitRaw(mseApdu.data(), static_cast<unsigned long>(mseApdu.size()));

    // Reconstruct response for SM unprotect
    std::vector<uint8_t> mseRespBytes;
    mseRespBytes.insert(mseRespBytes.end(), mseResp.data.begin(), mseResp.data.end());
    mseRespBytes.push_back(mseResp.sw1);
    mseRespBytes.push_back(mseResp.sw2);

    auto mseUnprot = currentSM.unprotect(mseRespBytes);
    if (!mseUnprot && mseResp.sw1 != 0x90) {
        result.chipAuthentication = ChipAuthResult::FAILED;
        result.errorDetail = "MSE:Set AT failed";
        return result;
    }

    // --- General Authenticate ---
    // Command: 00 86 00 00 Lc {7C {80 <terminal_pubkey>}} 00
    auto pubKeyDO = buildTLV(0x80, terminalPubBytes);
    auto gaData = buildTLV(0x7C, pubKeyDO);
    smartcard::APDUCommand gaCmd{0x00, 0x86, 0x00, 0x00, gaData, 0x00, true};
    auto gaApdu = currentSM.protect(gaCmd.toBytes());
    auto gaResp = conn.transmitRaw(gaApdu.data(), static_cast<unsigned long>(gaApdu.size()));

    std::vector<uint8_t> gaRespBytes;
    gaRespBytes.insert(gaRespBytes.end(), gaResp.data.begin(), gaResp.data.end());
    gaRespBytes.push_back(gaResp.sw1);
    gaRespBytes.push_back(gaResp.sw2);

    auto gaUnprot = currentSM.unprotect(gaRespBytes);
    if (!gaUnprot) {
        result.chipAuthentication = ChipAuthResult::FAILED;
        result.errorDetail = "General Authenticate response MAC verification failed";
        return result;
    }

    // --- Compute shared secret via ECDH ---
    EVPPKeyCtxPtr deriveCtx(EVP_PKEY_CTX_new(ephKey.get(), nullptr));
    if (!deriveCtx || EVP_PKEY_derive_init(deriveCtx.get()) <= 0) {
        result.chipAuthentication = ChipAuthResult::FAILED;
        result.errorDetail = "ECDH derive init failed";
        return result;
    }

    if (EVP_PKEY_derive_set_peer(deriveCtx.get(), parsed->pkey.get()) <= 0) {
        result.chipAuthentication = ChipAuthResult::FAILED;
        result.errorDetail = "ECDH set peer failed";
        return result;
    }

    size_t secretLen = 0;
    if (EVP_PKEY_derive(deriveCtx.get(), nullptr, &secretLen) <= 0) {
        result.chipAuthentication = ChipAuthResult::FAILED;
        result.errorDetail = "ECDH derive size query failed";
        return result;
    }

    std::vector<uint8_t> sharedSecret(secretLen);
    if (EVP_PKEY_derive(deriveCtx.get(), sharedSecret.data(), &secretLen) <= 0) {
        result.chipAuthentication = ChipAuthResult::FAILED;
        result.errorDetail = "ECDH derive failed";
        return result;
    }
    sharedSecret.resize(secretLen);

    // Scope guard to cleanse key material
    struct KeyCleaner
    {
        std::vector<uint8_t>& secret;
        ~KeyCleaner()
        {
            if (!secret.empty())
                OPENSSL_cleanse(secret.data(), secret.size());
        }
    } cleaner{sharedSecret};

    // --- Derive new session keys using KDF ---
    auto kEnc = detail::kdf(sharedSecret, 1, algoInfo.isDES3, algoInfo.keyLen);
    auto kMAC = detail::kdf(sharedSecret, 2, algoInfo.isDES3, algoInfo.keyLen);

    // Scope guard: cleanse derived keys on all exit paths
    struct DerivedKeyCleaner
    {
        std::vector<uint8_t>& enc;
        std::vector<uint8_t>& mac;
        ~DerivedKeyCleaner()
        {
            if (!enc.empty())
                OPENSSL_cleanse(enc.data(), enc.size());
            if (!mac.empty())
                OPENSSL_cleanse(mac.data(), mac.size());
        }
    } derivedCleaner{kEnc, kMAC};

    // --- Build new SessionKeys ---
    SessionKeys newKeys;
    newKeys.encKey = kEnc;
    newKeys.macKey = kMAC;
    // SSC for CA starts at 0
    size_t blockSize = algoInfo.isDES3 ? 8 : 16;
    newKeys.ssc.resize(blockSize, 0x00);

    result.chipAuthentication = ChipAuthResult::PASSED;
    result.newSessionKeys = std::move(newKeys);
    return result;
}

} // namespace emrtd::crypto
