// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "pace.h"

#include "tlv_bounds.h"
#include <ber.h>
#include "crypto_utils.h"

#include <LibreSCRS_internal/Crypto/CleanseGuard.h>

#include <apdu.h>
#include <smartcard/i_connection.h>

#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>

#include <array>
#include <cstring>
#include <expected>
#include <memory>
#include <stdexcept>
#include <LibreSCRS_internal/Crypto/OpenSslPtr.h>

using LibreSCRS::Internal::Crypto::BnPtr;

namespace emrtd::crypto {

// ---------------------------------------------------------------------------
// RAII wrappers for OpenSSL types
// ---------------------------------------------------------------------------

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
        // Cleansing free: zeroises affine coordinate buffers before
        // release. EC_POINT_free leaks PACE ephemeral / shared-point
        // coordinates on the heap.
        EC_POINT_clear_free(p);
    }
};

using BNCtxPtr = std::unique_ptr<BN_CTX, BNCtxDeleter>;
using ECGroupPtr = std::unique_ptr<EC_GROUP, ECGroupDeleter>;
using ECPointPtr = std::unique_ptr<EC_POINT, ECPointDeleter>;

// ---------------------------------------------------------------------------
// BER-TLV helpers: the middleware's one encoder and this library's bounds-checked
// length reads, plus the OID codec PACE shares with Chip Authentication.
// ---------------------------------------------------------------------------

using detail::oidBytesToString;
using detail::oidStringToBytes;
using detail::readLength;
using detail::readLengthClamped;
using LibreSCRS::SmartCard::Internal::buildTlv;

// Build a BSI TR-03110 Public Key Data Object (tag 0x7F49) for authentication token.
// When context is known (PACE mutual auth), contains only OID (tag 0x06) + EC point (tag 0x86).
static std::vector<uint8_t> buildPublicKeyDataObject(const std::string& paceOID,
                                                     const std::vector<uint8_t>& ecPointBytes)
{
    // OID tag 0x06 with DER-encoded OID bytes
    auto oidBytes = oidStringToBytes(paceOID);
    auto oidTLV = buildTlv(0x06, oidBytes);

    // EC public point tag 0x86
    auto pointTLV = buildTlv(0x86, ecPointBytes);

    // Concatenate OID + point as the 0x7F49 value
    std::vector<uint8_t> inner;
    inner.insert(inner.end(), oidTLV.begin(), oidTLV.end());
    inner.insert(inner.end(), pointTLV.begin(), pointTLV.end());

    return buildTlv(0x7F49, inner);
}

// Extract the value of a specific data object tag from a TLV(0x7C, ...) response
static std::vector<uint8_t> extractDO(const std::vector<uint8_t>& data, uint8_t tag)
{
    // Response is TLV: 0x7C || length || contents
    // Contents contain nested TLVs with tags 0x80, 0x81, 0x82, etc.
    if (data.size() < 2 || data[0] != 0x7C)
        return {};

    auto [outerLen, outerLenBytes] = readLength(data, 1);
    size_t pos = 1 + outerLenBytes;
    size_t end = pos + outerLen;
    if (end > data.size())
        end = data.size();

    while (pos + 2 <= end) {
        uint8_t t = data[pos++];
        auto [len, lenBytes] = readLength(data, pos);
        pos += lenBytes;
        if (pos + len > end)
            break;
        if (t == tag) {
            return std::vector<uint8_t>(data.begin() + static_cast<ptrdiff_t>(pos),
                                        data.begin() + static_cast<ptrdiff_t>(pos + len));
        }
        pos += len;
    }
    return {};
}

// ---------------------------------------------------------------------------
// PACE OID prefix: 0.4.0.127.0.7.2.2.4
// ---------------------------------------------------------------------------

static const std::string PACE_OID_PREFIX = "0.4.0.127.0.7.2.2.4";

static bool isPACEOID(const std::string& oid)
{
    return oid.size() > PACE_OID_PREFIX.size() && oid.substr(0, PACE_OID_PREFIX.size()) == PACE_OID_PREFIX &&
           oid[PACE_OID_PREFIX.size()] == '.';
}

// ---------------------------------------------------------------------------
// parseCardAccess
// ---------------------------------------------------------------------------

std::vector<std::string> parseCardAccess(const std::vector<uint8_t>& cardAccess)
{
    std::vector<std::string> result;
    if (cardAccess.size() < 2)
        return result;

    // Expect SET (0x31)
    if (cardAccess[0] != 0x31)
        return result;

    // The outer SET may legitimately declare more than one READ BINARY block
    // returned, so its length is clamped rather than refused; every length
    // inside it must be contained.
    auto [setLen, setLenBytes] = readLengthClamped(cardAccess, 1);
    if (setLenBytes == 0)
        return result;
    size_t pos = 1 + setLenBytes;
    size_t end = pos + setLen;

    // Iterate SEQUENCE entries
    while (pos + 2 <= end) {
        if (cardAccess[pos] != 0x30) {
            // Not a SEQUENCE, skip
            pos++;
            auto [skipLen, skipLenBytes] = readLength(cardAccess, pos);
            if (skipLenBytes == 0)
                break; // unusable length: stop, do not treat it as empty
            pos += skipLenBytes + skipLen;
            continue;
        }
        pos++; // skip 0x30 tag

        auto [seqLen, seqLenBytes] = readLength(cardAccess, pos);
        if (seqLenBytes == 0)
            break;
        pos += seqLenBytes;
        size_t seqEnd = pos + seqLen;
        if (seqEnd > end)
            break;

        // First element should be OID (0x06)
        if (pos < seqEnd && cardAccess[pos] == 0x06) {
            pos++; // skip 0x06 tag
            auto [oidLen, oidLenBytes] = readLength(cardAccess, pos);
            pos += oidLenBytes;
            if (pos + oidLen <= seqEnd) {
                std::string oid = oidBytesToString(cardAccess.data() + pos, oidLen);
                if (isPACEOID(oid)) {
                    result.push_back(oid);
                }
            }
        }
        pos = seqEnd;
    }
    return result;
}

// ---------------------------------------------------------------------------
// paceOIDToSMAlgorithm
// ---------------------------------------------------------------------------

SMAlgorithm paceOIDToSMAlgorithm(const std::string& oid)
{
    // OIDs ending in .1.x → 3DES, .2.x → AES
    if (oid == pace_oid::ECDH_GM_3DES_CBC_CBC) {
        return SMAlgorithm::DES3;
    }
    return SMAlgorithm::AES;
}

// ---------------------------------------------------------------------------
// Helper: determine key length from PACE OID
// ---------------------------------------------------------------------------

static size_t keyLengthFromOID(const std::string& oid)
{
    // Key length is determined by the last component of the OID:
    // .1.1 = 3DES (16), .2.2 = AES-128 (16), .2.3 = AES-192 (24), .2.4 = AES-256 (32)
    // Same pattern for GM (.4.N.x), IM (.4.3.x), and CAM (.4.6.x)
    if (oid.ends_with(".1"))
        return 16; // 3DES
    if (oid.ends_with(".2"))
        return 16; // AES-128
    if (oid.ends_with(".3"))
        return 24; // AES-192
    if (oid.ends_with(".4"))
        return 32; // AES-256
    return 16;     // default
}

// ---------------------------------------------------------------------------
// Helper: determine OpenSSL NID from parameter ID
// ---------------------------------------------------------------------------

static int paramIdToNID(int paramId)
{
    switch (paramId) {
    case 8:
        return NID_X9_62_prime192v1; // secp192r1
    case 9:
        return NID_brainpoolP192r1;
    case 10:
        return NID_secp224r1;
    case 11:
        return NID_brainpoolP224r1;
    case 12:
        return NID_X9_62_prime256v1; // secp256r1
    case 13:
        return NID_brainpoolP256r1;
    case 14:
        return NID_brainpoolP384r1;
    case 15:
        return NID_brainpoolP512r1;
    case 16:
        return NID_secp521r1;
    default:
        return 0;
    }
}

// ---------------------------------------------------------------------------
// Helper: parse parameter ID from CardAccess SecurityInfo for a given PACE OID
// Returns -1 if not found.
// ---------------------------------------------------------------------------

static int parseParameterIdFromCardAccess(const std::vector<uint8_t>& cardAccess, const std::string& targetOid)
{
    if (cardAccess.size() < 2 || cardAccess[0] != 0x31)
        return -1;

    // The outer SET may legitimately declare more than one READ BINARY block
    // returned, so its length is clamped rather than refused; every length
    // inside it must be contained.
    auto [setLen, setLenBytes] = readLengthClamped(cardAccess, 1);
    if (setLenBytes == 0)
        return -1;
    size_t pos = 1 + setLenBytes;
    size_t end = pos + setLen;

    while (pos + 2 <= end) {
        if (cardAccess[pos] != 0x30) {
            pos++;
            auto [skipLen, skipLenBytes] = readLength(cardAccess, pos);
            if (skipLenBytes == 0)
                break; // unusable length: stop, do not treat it as empty
            pos += skipLenBytes + skipLen;
            continue;
        }
        pos++;

        auto [seqLen, seqLenBytes] = readLength(cardAccess, pos);
        if (seqLenBytes == 0)
            break;
        pos += seqLenBytes;
        size_t seqEnd = pos + seqLen;
        if (seqEnd > end)
            break;

        // Parse OID
        std::string oid;
        if (pos < seqEnd && cardAccess[pos] == 0x06) {
            pos++;
            auto [oidLen, oidLenBytes] = readLength(cardAccess, pos);
            pos += oidLenBytes;
            if (pos + oidLen <= seqEnd) {
                oid = oidBytesToString(cardAccess.data() + pos, oidLen);
            }
            pos += oidLen;
        }

        if (oid == targetOid) {
            // Skip version INTEGER
            if (pos < seqEnd && cardAccess[pos] == 0x02) {
                pos++;
                auto [intLen, intLenBytes] = readLength(cardAccess, pos);
                pos += intLenBytes + intLen;
            }
            // Read parameter ID INTEGER (if present)
            if (pos < seqEnd && cardAccess[pos] == 0x02) {
                pos++;
                auto [intLen, intLenBytes] = readLength(cardAccess, pos);
                pos += intLenBytes;
                if (intLen > 0 && pos + intLen <= seqEnd) {
                    int paramId = 0;
                    for (size_t i = 0; i < intLen; ++i) {
                        paramId = (paramId << 8) | cardAccess[pos + i];
                    }
                    return paramId;
                }
            }
            return -1; // OID found but no parameter ID
        }
        pos = seqEnd;
    }
    return -1;
}

// ---------------------------------------------------------------------------
// parseCardAccessWithParams
// ---------------------------------------------------------------------------

std::vector<std::pair<std::string, int>> parseCardAccessWithParams(const std::vector<uint8_t>& cardAccess)
{
    std::vector<std::pair<std::string, int>> result;
    if (cardAccess.size() < 2 || cardAccess[0] != 0x31)
        return result;

    // The outer SET may legitimately declare more than one READ BINARY block
    // returned, so its length is clamped rather than refused; every length
    // inside it must be contained.
    auto [setLen, setLenBytes] = readLengthClamped(cardAccess, 1);
    if (setLenBytes == 0)
        return result;
    size_t pos = 1 + setLenBytes;
    size_t end = pos + setLen;

    while (pos + 2 <= end) {
        if (cardAccess[pos] != 0x30) {
            pos++;
            auto [skipLen, skipLenBytes] = readLength(cardAccess, pos);
            if (skipLenBytes == 0)
                break; // unusable length: stop, do not treat it as empty
            pos += skipLenBytes + skipLen;
            continue;
        }
        pos++;

        auto [seqLen, seqLenBytes] = readLength(cardAccess, pos);
        if (seqLenBytes == 0)
            break;
        pos += seqLenBytes;
        size_t seqEnd = pos + seqLen;
        if (seqEnd > end)
            break;

        // Parse OID
        std::string oid;
        size_t afterOid = pos;
        if (pos < seqEnd && cardAccess[pos] == 0x06) {
            afterOid = pos + 1;
            auto [oidLen, oidLenBytes] = readLength(cardAccess, afterOid);
            afterOid += oidLenBytes;
            if (afterOid + oidLen <= seqEnd) {
                oid = oidBytesToString(cardAccess.data() + afterOid, oidLen);
            }
            afterOid += oidLen;
        }

        if (isPACEOID(oid)) {
            // Use the dedicated helper to extract paramId for this OID
            int paramId = parseParameterIdFromCardAccess(cardAccess, oid);
            result.emplace_back(oid, paramId);
        }

        pos = seqEnd;
    }
    return result;
}

// ---------------------------------------------------------------------------
// EC point serialization helpers
// ---------------------------------------------------------------------------

static std::vector<uint8_t> pointToBytes(const EC_GROUP* group, const EC_POINT* point, BN_CTX* ctx)
{
    size_t len = EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED, nullptr, 0, ctx);
    if (len == 0)
        throw std::runtime_error("PACE: EC_POINT_point2oct size query failed");
    std::vector<uint8_t> buf(len);
    if (EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED, buf.data(), buf.size(), ctx) == 0)
        throw std::runtime_error("PACE: EC_POINT_point2oct failed");
    return buf;
}

static ECPointPtr bytesToPoint(const EC_GROUP* group, const std::vector<uint8_t>& bytes, BN_CTX* ctx)
{
    ECPointPtr point(EC_POINT_new(group));
    if (!point)
        throw std::runtime_error("PACE: EC_POINT_new failed");
    if (!EC_POINT_oct2point(group, point.get(), bytes.data(), bytes.size(), ctx))
        throw std::runtime_error("PACE: EC_POINT_oct2point failed");
    // Validate that the decoded point lies on the curve to prevent invalid-curve attacks
    if (EC_POINT_is_on_curve(group, point.get(), ctx) != 1)
        throw std::runtime_error("PACE: EC point not on curve");
    return point;
}

// ---------------------------------------------------------------------------
// Generate a random private key in [1, order-1]
// ---------------------------------------------------------------------------

static BnPtr generatePrivateKey(const EC_GROUP* group, BN_CTX* ctx)
{
    BnPtr order(BN_new());
    if (!EC_GROUP_get_order(group, order.get(), ctx))
        throw std::runtime_error("PACE: EC_GROUP_get_order failed");

    BnPtr privKey(BN_new());
    if (!BN_rand_range(privKey.get(), order.get()))
        throw std::runtime_error("PACE: BN_rand_range failed");

    // Ensure non-zero
    while (BN_is_zero(privKey.get())) {
        if (!BN_rand_range(privKey.get(), order.get()))
            throw std::runtime_error("PACE: BN_rand_range failed");
    }
    return privKey;
}

// ---------------------------------------------------------------------------
// Compute public key = privKey * generator
// ---------------------------------------------------------------------------

static ECPointPtr computePublicKey(const EC_GROUP* group, const BIGNUM* privKey, BN_CTX* ctx)
{
    ECPointPtr pubKey(EC_POINT_new(group));
    if (!pubKey)
        throw std::runtime_error("PACE: EC_POINT_new failed");
    // EC_POINT_mul(group, r, n, q, m, ctx) computes r = n*G + m*q
    // For pubKey = privKey*G: set n=privKey, q=NULL, m=NULL
    if (!EC_POINT_mul(group, pubKey.get(), privKey, nullptr, nullptr, ctx))
        throw std::runtime_error("PACE: EC_POINT_mul failed");
    return pubKey;
}

// ---------------------------------------------------------------------------
// ECDH: compute shared secret x-coordinate = (privKey * otherPub).x
// Padded to field element size (e.g., 32 bytes for 256-bit curves).
// ---------------------------------------------------------------------------

static std::vector<uint8_t> ecdhSharedSecret(const EC_GROUP* group, const BIGNUM* privKey, const EC_POINT* otherPub,
                                             BN_CTX* ctx)
{
    ECPointPtr shared(EC_POINT_new(group));
    if (!shared)
        throw std::runtime_error("PACE: EC_POINT_new failed");
    // r = 0*G + privKey*otherPub
    if (!EC_POINT_mul(group, shared.get(), nullptr, otherPub, privKey, ctx))
        throw std::runtime_error("PACE: EC_POINT_mul (ECDH) failed");

    BnPtr x(BN_new());
    if (!EC_POINT_get_affine_coordinates(group, shared.get(), x.get(), nullptr, ctx))
        throw std::runtime_error("PACE: EC_POINT_get_affine_coordinates failed");

    // Pad x-coordinate to field element size (BN_bn2bin strips leading zeros)
    BnPtr p(BN_new());
    if (!EC_GROUP_get_curve(group, p.get(), nullptr, nullptr, ctx))
        throw std::runtime_error("PACE: EC_GROUP_get_curve failed");
    size_t fieldSize = static_cast<size_t>(BN_num_bytes(p.get()));

    std::vector<uint8_t> result(fieldSize, 0x00);
    int numBytes = BN_num_bytes(x.get());
    BN_bn2bin(x.get(), result.data() + (fieldSize - static_cast<size_t>(numBytes)));
    return result;
}

// ---------------------------------------------------------------------------
// ECDH: compute shared secret as a full EC_POINT (for Generic Mapping)
// ---------------------------------------------------------------------------

static ECPointPtr ecdhSharedPoint(const EC_GROUP* group, const BIGNUM* privKey, const EC_POINT* otherPub, BN_CTX* ctx)
{
    ECPointPtr shared(EC_POINT_new(group));
    if (!shared)
        throw std::runtime_error("PACE: EC_POINT_new failed");
    if (!EC_POINT_mul(group, shared.get(), nullptr, otherPub, privKey, ctx))
        throw std::runtime_error("PACE: EC_POINT_mul (ECDH point) failed");
    return shared;
}

// ---------------------------------------------------------------------------
// derivePaceKpiSeed
// ---------------------------------------------------------------------------

std::optional<std::vector<uint8_t>> derivePaceKpiSeed(PACEPasswordType passwordType,
                                                      const std::vector<uint8_t>& password)
{
    if (passwordType != PACEPasswordType::MRZ) {
        // CAN / PIN / PUK use the raw password bytes as the seed (ICAO 9303
        // Part 11 §9.7.1.1). No pre-hash, no truncation.
        return password;
    }
    // PACE-MRZ: π = SHA-1(MRZ_info), full 20 bytes. Critical: BAC truncates
    // to 16 here (BSI TR-03110-3 §A.3.3), PACE does NOT. Truncating yields a
    // wrong K_π and a silent GA4 token mismatch (SW=6300) — covered by
    // PACETest::KpiSeedMrzMatchesSha1Kat regression vector.
    unsigned char pwSha1[20] = {};
    size_t sha1Len = 0;
    if (!EVP_Q_digest(nullptr, "SHA1", nullptr, password.data(), password.size(), pwSha1, &sha1Len)) {
        // Cleanse even the partial buffer — EVP leaves output unspecified on
        // failure, treat as sensitive intermediate state.
        OPENSSL_cleanse(pwSha1, sizeof(pwSha1));
        return std::nullopt;
    }
    std::vector<uint8_t> seed(pwSha1, pwSha1 + sha1Len);
    // Zeroise the stack copy now that ownership has transferred into the
    // returned vector. The caller is responsible for zeroising the vector
    // when it has consumed the seed (KeyCleaner RAII in performPACE).
    OPENSSL_cleanse(pwSha1, sizeof(pwSha1));
    return seed;
}

// ---------------------------------------------------------------------------
// performPACE
// ---------------------------------------------------------------------------

std::expected<SessionKeys, PaceFailure> performPACE(LibreSCRS::SmartCard::IConnection& conn, const PACEParams& params)
{
    bool isDES3 = (paceOIDToSMAlgorithm(params.oid) == SMAlgorithm::DES3);
    size_t keyLen = keyLengthFromOID(params.oid);
    size_t blockSize = isDES3 ? 8 : 16;

    // --- Step 1: MSE:Set AT ---
    std::vector<uint8_t> oidBytes = oidStringToBytes(params.oid);
    auto oidTLV = buildTlv(0x80, oidBytes);
    auto pwdTypeTLV = buildTlv(0x83, std::array{static_cast<uint8_t>(params.passwordType)});

    std::vector<uint8_t> mseData;
    mseData.insert(mseData.end(), oidTLV.begin(), oidTLV.end());
    mseData.insert(mseData.end(), pwdTypeTLV.begin(), pwdTypeTLV.end());

    // Add standardized domain parameter ID (tag 0x84) if specified
    if (params.paramId >= 0) {
        auto paramIdTLV = buildTlv(0x84, std::array{static_cast<uint8_t>(params.paramId)});
        mseData.insert(mseData.end(), paramIdTLV.begin(), paramIdTLV.end());
    }

    LibreSCRS::SmartCard::Internal::APDUCommand mseCmd{0x00, 0x22, 0xC1, 0xA4, mseData, 0, false};
    auto resp = conn.transmit(mseCmd);
    if (!resp.isSuccess()) {
        // No secret has reached the card yet, so a refusal here is about the
        // mechanism -- unless the card is reporting on the password itself
        // (63Cx tries left, 6983 blocked, 6984 deactivated), which it may do
        // for a PIN before any General Authenticate.
        const auto sw = resp.statusWord();
        const bool aboutThePassword = (sw & 0xFFF0) == 0x63C0 || sw == 0x6983 || sw == 0x6984;
        return std::unexpected{aboutThePassword ? PaceFailure::Failed : PaceFailure::MechanismRefused};
    }

    // --- Step 2: General Authenticate Step 1 — get encrypted nonce ---
    LibreSCRS::SmartCard::Internal::APDUCommand ga1Cmd{0x10, 0x86, 0x00, 0x00, {0x7C, 0x00}, 0x00, true};
    resp = conn.transmit(ga1Cmd);
    if (!resp.isSuccess())
        return std::unexpected{PaceFailure::Failed};

    auto encryptedNonce = extractDO(resp.data, 0x80);
    if (encryptedNonce.empty())
        return std::unexpected{PaceFailure::Failed};

    // --- Step 3: Decrypt nonce ---
    // BSI TR-03110 Part 3, Table A.2:
    //   MRZ: keySeed = SHA-1(MRZ_info), the FULL 20 bytes (NOT truncated to 16
    //        as BAC does — see bac.cpp). derivePaceKpiSeed() is the single
    //        source of truth for this derivation.
    //   CAN/PIN/PUK: keySeed = raw password bytes (ICAO 9303)
    // Then K_pi = KDF(keySeed, 3) where KDF uses cipher-appropriate hash.
    std::vector<uint8_t> kpiSeed;
    std::vector<uint8_t> kPi;
    std::vector<uint8_t> nonce;
    std::vector<uint8_t> sharedK;
    std::vector<uint8_t> kEnc;
    std::vector<uint8_t> kMAC;

    // Scope guard to cleanse key material on all exit paths
    LibreSCRS::Internal::Crypto::CleanseGuard keyCleaner{kpiSeed, kPi, nonce, sharedK, kEnc, kMAC};

    if (auto seed = derivePaceKpiSeed(params.passwordType, params.password)) {
        kpiSeed = std::move(*seed);
    } else {
        return std::unexpected{PaceFailure::Failed};
    }
    kPi = detail::kdf(kpiSeed, 3, isDES3, keyLen);

    // Decrypt the nonce
    if (isDES3) {
        nonce = detail::des3Decrypt(kPi, encryptedNonce);
    } else {
        nonce = detail::aesDecrypt(kPi, encryptedNonce);
    }

    // --- Step 4: Determine EC parameters ---
    int nid = paramIdToNID(params.paramId);
    if (nid == 0)
        return std::unexpected{PaceFailure::Failed};

    ECGroupPtr baseGroup(EC_GROUP_new_by_curve_name(nid));
    if (!baseGroup)
        return std::unexpected{PaceFailure::Failed};

    BNCtxPtr bnCtx(BN_CTX_new());
    if (!bnCtx)
        return std::unexpected{PaceFailure::Failed};

    // Convert nonce to BIGNUM
    BnPtr sNonce(BN_bin2bn(nonce.data(), static_cast<int>(nonce.size()), nullptr));
    if (!sNonce)
        return std::unexpected{PaceFailure::Failed};

    // --- Step 5: Generic Mapping ---
    // Generate ephemeral mapping key pair
    auto skMap = generatePrivateKey(baseGroup.get(), bnCtx.get());
    auto pkMap = computePublicKey(baseGroup.get(), skMap.get(), bnCtx.get());
    auto pkMapBytes = pointToBytes(baseGroup.get(), pkMap.get(), bnCtx.get());

    // Send PK_map to card, receive PK_map_ICC
    auto ga2Data = buildTlv(0x7C, buildTlv(0x81, pkMapBytes));
    LibreSCRS::SmartCard::Internal::APDUCommand ga2Cmd{0x10, 0x86, 0x00, 0x00, ga2Data, 0x00, true};
    resp = conn.transmit(ga2Cmd);
    if (!resp.isSuccess())
        return std::unexpected{PaceFailure::Failed};

    auto pkMapICCBytes = extractDO(resp.data, 0x82);
    if (pkMapICCBytes.empty())
        return std::unexpected{PaceFailure::Failed};

    auto pkMapICC = bytesToPoint(baseGroup.get(), pkMapICCBytes, bnCtx.get());

    // Compute shared secret H = ECDH(sk_map, PK_map_ICC) as a point
    auto hPoint = ecdhSharedPoint(baseGroup.get(), skMap.get(), pkMapICC.get(), bnCtx.get());

    // Compute mapped generator: G' = s * G + H
    ECPointPtr mappedG(EC_POINT_new(baseGroup.get()));
    if (!mappedG)
        return std::unexpected{PaceFailure::Failed};

    // EC_POINT_mul(group, r, n, q, m, ctx) computes r = n*G + m*q
    // We want s*G + 1*H, but EC_POINT_mul requires: r = sNonce*G + 1*hPoint
    // Unfortunately EC_POINT_mul's scalar for generator and scalar for arbitrary point
    // are separate. We need: s*baseG + H
    // Use: EC_POINT_mul with n=sNonce (for generator), q=hPoint, m=BN_one
    BnPtr one(BN_new());
    BN_one(one.get());
    if (!EC_POINT_mul(baseGroup.get(), mappedG.get(), sNonce.get(), hPoint.get(), one.get(), bnCtx.get()))
        return std::unexpected{PaceFailure::Failed};

    // --- Step 6: Key agreement on mapped generator ---
    // Use explicit multiplication with G' (mappedG) instead of EC_GROUP_set_generator,
    // because EC_GROUP_dup may carry stale precomputed tables that cause EC_POINT_mul
    // to use the original generator G instead of G'.

    // Generate ephemeral agreement private key on base group (same order)
    auto skAgree = generatePrivateKey(baseGroup.get(), bnCtx.get());

    // pkAgree = skAgree * G' (explicit multiplication with mapped generator)
    ECPointPtr pkAgree(EC_POINT_new(baseGroup.get()));
    if (!pkAgree)
        return std::unexpected{PaceFailure::Failed};
    if (!EC_POINT_mul(baseGroup.get(), pkAgree.get(), nullptr, mappedG.get(), skAgree.get(), bnCtx.get()))
        return std::unexpected{PaceFailure::Failed};
    auto pkAgreeBytes = pointToBytes(baseGroup.get(), pkAgree.get(), bnCtx.get());

    // Send PK_agree, receive PK_agree_ICC
    auto ga3Data = buildTlv(0x7C, buildTlv(0x83, pkAgreeBytes));
    LibreSCRS::SmartCard::Internal::APDUCommand ga3Cmd{0x10, 0x86, 0x00, 0x00, ga3Data, 0x00, true};
    resp = conn.transmit(ga3Cmd);
    if (!resp.isSuccess())
        return std::unexpected{PaceFailure::Failed};

    auto pkAgreeICCBytes = extractDO(resp.data, 0x84);
    if (pkAgreeICCBytes.empty())
        return std::unexpected{PaceFailure::Failed};

    auto pkAgreeICC = bytesToPoint(baseGroup.get(), pkAgreeICCBytes, bnCtx.get());

    // Compute shared secret K = skAgree * PK_agree_ICC — x-coordinate
    sharedK = ecdhSharedSecret(baseGroup.get(), skAgree.get(), pkAgreeICC.get(), bnCtx.get());

    // Derive session keys
    kEnc = detail::kdf(sharedK, 1, isDES3, keyLen);
    kMAC = detail::kdf(sharedK, 2, isDES3, keyLen);

    // --- Step 7: Mutual authentication ---
    // BSI TR-03110: authentication token = MAC(K_MAC, 0x7F49 Public Key Data Object)
    // The 0x7F49 structure contains: OID (tag 0x06) + EC point (tag 0x86)

    // T_IFD = MAC(K_MAC, PKDO(card's ephemeral public key))
    // For 3DES: ISO 9797-1 Method 2 padding + retail MAC (MAC needs block-aligned input)
    // For AES: AES-CMAC handles padding internally — do NOT pre-pad
    auto pkdoICC = buildPublicKeyDataObject(params.oid, pkAgreeICCBytes);
    std::vector<uint8_t> tIFD;
    if (isDES3) {
        auto macInputIFD = detail::pad(pkdoICC, blockSize);
        tIFD = detail::retailMAC(kMAC, macInputIFD);
    } else {
        tIFD = detail::aesCMAC(kMAC, pkdoICC);
    }

    // Send T_IFD, receive T_ICC
    auto ga4Data = buildTlv(0x7C, buildTlv(0x85, tIFD));
    LibreSCRS::SmartCard::Internal::APDUCommand ga4Cmd{0x00, 0x86, 0x00, 0x00, ga4Data, 0x00, true};
    resp = conn.transmit(ga4Cmd);
    if (!resp.isSuccess())
        return std::unexpected{PaceFailure::Failed};

    auto tICC = extractDO(resp.data, 0x86);
    if (tICC.empty())
        return std::unexpected{PaceFailure::Failed};

    // T_ICC should equal MAC(K_MAC, PKDO(our ephemeral public key))
    auto pkdoIFD = buildPublicKeyDataObject(params.oid, pkAgreeBytes);
    std::vector<uint8_t> expectedTICC;
    if (isDES3) {
        auto macInputICC = detail::pad(pkdoIFD, blockSize);
        expectedTICC = detail::retailMAC(kMAC, macInputICC);
    } else {
        expectedTICC = detail::aesCMAC(kMAC, pkdoIFD);
    }

    if (tICC.size() != expectedTICC.size() || CRYPTO_memcmp(tICC.data(), expectedTICC.data(), tICC.size()) != 0)
        return std::unexpected{PaceFailure::Failed};

    // --- Step 8: Build SessionKeys ---
    SessionKeys session;
    session.encKey = kEnc;
    session.macKey = kMAC;
    // SSC starts at 0 — length depends on cipher
    session.ssc.resize(blockSize, 0x00);

    return session;
}

} // namespace emrtd::crypto
