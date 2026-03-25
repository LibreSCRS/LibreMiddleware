// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <emrtd/crypto/active_auth.h>

#include <smartcard/apdu.h>
#include <smartcard/pcsc_connection.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/x509.h>

#include <memory>
#include <stdexcept>

namespace emrtd::crypto {

// ---------------------------------------------------------------------------
// RAII wrappers for OpenSSL types
// ---------------------------------------------------------------------------

struct EVPPKeyDeleterAA {
    void operator()(EVP_PKEY* p) const { EVP_PKEY_free(p); }
};
struct EVPMDCtxDeleter {
    void operator()(EVP_MD_CTX* p) const { EVP_MD_CTX_free(p); }
};

using EVPPKeyPtr = std::unique_ptr<EVP_PKEY, EVPPKeyDeleterAA>;
using EVPMDCtxPtr = std::unique_ptr<EVP_MD_CTX, EVPMDCtxDeleter>;

// ---------------------------------------------------------------------------
// BER-TLV helpers (minimal)
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

// ---------------------------------------------------------------------------
// parseDG15 — extract SubjectPublicKeyInfo from DG15 (tag 0x6F)
// ---------------------------------------------------------------------------

AAPublicKey parseDG15(const std::vector<uint8_t>& dg15Raw)
{
    AAPublicKey result;

    if (dg15Raw.size() < 4)
        return result;

    // DG15 starts with tag 0x6F
    size_t pos = 0;
    if (dg15Raw[pos] != 0x6F)
        return result;
    pos++;

    auto [outerLen, outerLenBytes] = parseBERLength(dg15Raw, pos);
    pos += outerLenBytes;
    if (outerLen == 0 || pos + outerLen > dg15Raw.size())
        return result;

    // The content inside 0x6F is a SubjectPublicKeyInfo (SEQUENCE)
    const uint8_t* spkiData = dg15Raw.data() + pos;
    size_t spkiLen = outerLen;

    // Parse using OpenSSL d2i_PUBKEY
    const uint8_t* p = spkiData;
    EVP_PKEY* raw = d2i_PUBKEY(nullptr, &p, static_cast<long>(spkiLen));
    if (!raw)
        return result;

    EVPPKeyPtr pkey(raw);
    result.publicKeyDER.assign(spkiData, spkiData + spkiLen);

    int keyType = EVP_PKEY_id(pkey.get());
    if (keyType == EVP_PKEY_RSA) {
        result.algorithm = AAPublicKey::RSA;
    } else if (keyType == EVP_PKEY_EC) {
        result.algorithm = AAPublicKey::ECDSA;
    }

    return result;
}

// ---------------------------------------------------------------------------
// performActiveAuth
// ---------------------------------------------------------------------------

ChipAuthResult performActiveAuth(smartcard::PCSCConnection& conn,
                                 const std::vector<uint8_t>& dg15Raw,
                                 SecureMessaging& currentSM)
{
    ChipAuthResult result;

    // --- Parse DG15 ---
    auto aaKey = parseDG15(dg15Raw);
    if (aaKey.algorithm == AAPublicKey::UNKNOWN) {
        result.activeAuthentication = ChipAuthResult::NOT_SUPPORTED;
        result.errorDetail = "DG15 parsing failed or unsupported key type";
        return result;
    }

    if (aaKey.algorithm == AAPublicKey::RSA) {
        // RSA Active Authentication requires ISO 9796-2 signature verification
        // which is non-trivial; defer to a future implementation
        result.activeAuthentication = ChipAuthResult::NOT_SUPPORTED;
        result.protocol = "RSA";
        result.errorDetail = "RSA Active Authentication (ISO 9796-2) not yet implemented";
        return result;
    }

    result.protocol = "ECDSA";

    // --- Generate 8-byte random challenge ---
    std::vector<uint8_t> challenge(8);
    if (RAND_bytes(challenge.data(), static_cast<int>(challenge.size())) != 1) {
        result.activeAuthentication = ChipAuthResult::FAILED;
        result.errorDetail = "RAND_bytes failed";
        return result;
    }

    // --- Send INTERNAL AUTHENTICATE via Secure Messaging ---
    // Command: 00 88 00 00 08 <challenge> 00
    smartcard::APDUCommand iaCmd{0x00, 0x88, 0x00, 0x00, challenge, 0x00, true};
    auto iaApdu = currentSM.protect(iaCmd.toBytes());
    auto iaResp = conn.transmitRaw(iaApdu.data(), static_cast<unsigned long>(iaApdu.size()));

    std::vector<uint8_t> iaRespBytes;
    iaRespBytes.insert(iaRespBytes.end(), iaResp.data.begin(), iaResp.data.end());
    iaRespBytes.push_back(iaResp.sw1);
    iaRespBytes.push_back(iaResp.sw2);

    auto iaUnprot = currentSM.unprotect(iaRespBytes);
    if (!iaUnprot || iaUnprot->empty()) {
        result.activeAuthentication = ChipAuthResult::FAILED;
        result.errorDetail = "INTERNAL AUTHENTICATE failed or empty response";
        return result;
    }

    const auto& signature = *iaUnprot;

    // --- Verify ECDSA signature over the challenge ---
    // Reconstruct the public key from DER
    const uint8_t* p = aaKey.publicKeyDER.data();
    EVP_PKEY* pubRaw = d2i_PUBKEY(nullptr, &p, static_cast<long>(aaKey.publicKeyDER.size()));
    if (!pubRaw) {
        result.activeAuthentication = ChipAuthResult::FAILED;
        result.errorDetail = "Failed to reconstruct public key for verification";
        return result;
    }
    EVPPKeyPtr pubKey(pubRaw);

    EVPMDCtxPtr mdCtx(EVP_MD_CTX_new());
    if (!mdCtx) {
        result.activeAuthentication = ChipAuthResult::FAILED;
        result.errorDetail = "EVP_MD_CTX_new failed";
        return result;
    }

    // ICAO 9303: Active Authentication uses SHA-256 for ECDSA
    if (EVP_DigestVerifyInit(mdCtx.get(), nullptr, EVP_sha256(), nullptr, pubKey.get()) <= 0) {
        result.activeAuthentication = ChipAuthResult::FAILED;
        result.errorDetail = "EVP_DigestVerifyInit failed";
        return result;
    }

    int verifyResult = EVP_DigestVerify(mdCtx.get(), signature.data(), signature.size(),
                                        challenge.data(), challenge.size());

    if (verifyResult == 1) {
        result.activeAuthentication = ChipAuthResult::PASSED;
    } else {
        result.activeAuthentication = ChipAuthResult::FAILED;
        result.errorDetail = "ECDSA signature verification failed";
    }

    return result;
}

} // namespace emrtd::crypto
