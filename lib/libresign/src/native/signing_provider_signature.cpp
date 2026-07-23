// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// OpenSSL 3 provider — signature callbacks (sign / digest_sign_update /
// digest_sign_final) plus the raw-r||s -> DER conversion for ECDSA. The
// dispatch table assembled here is consumed by the provider's
// query_operation in signing_provider.cpp.

#include "native/signing_provider_signature.h"
#include "native/pkcs11_token.h"
#include "native/signing_provider_keymgmt.h"
#include "native_utils.h"

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/params.h>

// Padding mode constants (avoid #include <openssl/rsa.h> which pulls
// deprecated APIs).
constexpr int kPadPKCS1v15 = 1; // RSA_PKCS1_PADDING
constexpr int kPadNone = 3;     // RSA_NO_PADDING
constexpr int kPadPSS = 6;      // RSA_PKCS1_PSS_PADDING

#include <cstdint>
#include <cstring>
#include <iostream>
#include <span>
#include <string>
#include <vector>

namespace libresign::detail {

namespace {

using native_utils::digestInfoPrefixForAlgo;
using native_utils::tokenAlgorithm;

// PKCS#11 CKM_ECDSA returns the signature as the raw concatenation r||s
// (each zero-padded to the curve's field-size). CMS/CAdES/PAdES/ASiC-CAdES
// (RFC 5753) require the signature as DER-encoded `Ecdsa-Sig-Value
// SEQUENCE { r INTEGER, s INTEGER }`. Wrap before returning to OpenSSL's
// CMS pipeline. XAdES and JAdES call Pkcs11Token::sign() directly via
// signHashWithToken() — those paths keep raw r||s, which is the correct
// form for XMLDSig (ECDSASignatureValue) and JWS (RFC 7518 §3.4).
std::vector<uint8_t> ecdsaRawToDer(const std::vector<uint8_t>& raw)
{
    if (raw.empty() || (raw.size() % 2) != 0)
        return {};
    const size_t half = raw.size() / 2;

    BIGNUM* rawR = BN_bin2bn(raw.data(), static_cast<int>(half), nullptr);
    BIGNUM* rawS = BN_bin2bn(raw.data() + half, static_cast<int>(half), nullptr);
    if (!rawR || !rawS) {
        BN_free(rawR);
        BN_free(rawS);
        return {};
    }

    // ECDSA_SIG_set0 takes ownership of r and s on success only.
    ECDSA_SIG* sig = ECDSA_SIG_new();
    if (!sig) {
        BN_free(rawR);
        BN_free(rawS);
        return {};
    }
    if (!ECDSA_SIG_set0(sig, rawR, rawS)) {
        BN_free(rawR);
        BN_free(rawS);
        ECDSA_SIG_free(sig);
        return {};
    }

    unsigned char* der = nullptr;
    int derLen = i2d_ECDSA_SIG(sig, &der);
    ECDSA_SIG_free(sig);
    if (derLen <= 0 || !der)
        return {};
    std::vector<uint8_t> out(der, der + derLen);
    OPENSSL_free(der);
    return out;
}

// ---------------------------------------------------------------------------
// Signature context
// ---------------------------------------------------------------------------

struct SignCtx
{
    ProviderKeyData* keyData = nullptr; // non-owning (owned by keymgmt)
    EVP_MD_CTX* mdCtx = nullptr;
    std::string mdName;
    int padMode = kPadPKCS1v15;

    /// Accumulator for the raw bytes streamed into the digest via
    /// digest_sign_update. Captured so the sign-final callback can
    /// forward them to Pkcs11Token alongside the computed hash — certain
    /// IAS-ECC hash-on-card SSCDs (German nPA) need this raw view
    /// to drive the combined CKM_SHA*_RSA_PKCS mechanism. Memory cost is
    /// the signed-attributes / PDF-byte-range size (≤ a few KB per
    /// CMS_signerInfo), reset between signs by sigInitNewDigestSign.
    std::vector<uint8_t> rawAccumulator;

    ~SignCtx()
    {
        if (mdCtx)
            EVP_MD_CTX_free(mdCtx);
    }
};

void* sigNewCtx(void* /*provctx*/, const char* /*propq*/)
{
    return new SignCtx();
}

void sigFreeCtx(void* ctx)
{
    delete static_cast<SignCtx*>(ctx);
}

// sign_init: store the key reference for later use by sign()
int sigSignInit(void* ctx, void* provkey, const OSSL_PARAM /*params*/[])
{
    auto* sc = static_cast<SignCtx*>(ctx);
    sc->keyData = static_cast<ProviderKeyData*>(provkey);
    return 1;
}

// sign: raw sign (receives pre-hashed data with DigestInfo for RSA).
// Note: mdName may be empty here (set_ctx_params not always called before sign).
// tokenAlgorithm defaults to SHA256withRSA/ECDSA, which is benign for RSA
// (CKM_RSA_PKCS is digest-agnostic) and matches the CMS pipeline's default.
int sigSign(void* ctx, unsigned char* sig, size_t* siglen, size_t sigsize, const unsigned char* tbs, size_t tbslen)
{
    auto* sc = static_cast<SignCtx*>(ctx);
    if (!sc->keyData || !sc->keyData->token)
        return 0;

    // Query for size only
    if (sig == nullptr) {
        *siglen = static_cast<size_t>(sc->keyData->maxSigSize);
        return 1;
    }

    try {
        std::span<const uint8_t> input(tbs, tbslen);
        std::string algo = tokenAlgorithm(sc->keyData->keyType, sc->mdName);
        auto result = sc->keyData->token->sign(input, algo);

        if (result.empty())
            return 0;

        // EC output from PKCS#11 is raw r||s — wrap in DER Ecdsa-Sig-Value
        // so CMS gets the RFC 5753 form.
        if (sc->keyData->keyType == EVP_PKEY_EC) {
            result = ecdsaRawToDer(result);
            if (result.empty())
                return 0;
        }

        if (result.size() > sigsize)
            return 0;

        std::memcpy(sig, result.data(), result.size());
        *siglen = result.size();
        return 1;
    } catch (const std::exception& e) {
        // Swallowing the exception silently produced a 0-byte signature
        // return code and the upstream CMS / PAdES path then surfaced
        // an opaque "signing failed" with no Pkcs11Token diagnostic.
        // Surface the message so the field has something actionable.
        std::cerr << "libresign: sigSign exception: " << e.what() << std::endl;
        return 0;
    } catch (...) {
        std::cerr << "libresign: sigSign unknown exception" << std::endl;
        return 0;
    }
}

// digest_sign_init: set up digest context for streaming sign
int sigDigestSignInit(void* ctx, const char* mdname, void* provkey, const OSSL_PARAM /*params*/[])
{
    auto* sc = static_cast<SignCtx*>(ctx);
    sc->keyData = static_cast<ProviderKeyData*>(provkey);

    if (mdname != nullptr)
        sc->mdName = mdname;
    else
        sc->mdName = "SHA2-256"; // default

    // Create digest context
    if (sc->mdCtx)
        EVP_MD_CTX_free(sc->mdCtx);
    sc->mdCtx = EVP_MD_CTX_new();
    sc->rawAccumulator.clear();
    if (!sc->mdCtx)
        return 0;

    const EVP_MD* md = EVP_get_digestbyname(sc->mdName.c_str());
    if (!md) {
        // Try canonical OpenSSL names
        if (sc->mdName == "SHA2-256")
            md = EVP_sha256();
        else if (sc->mdName == "SHA2-384")
            md = EVP_sha384();
        else if (sc->mdName == "SHA2-512")
            md = EVP_sha512();
        else if (sc->mdName == "SHA1")
            md = EVP_sha1();
    }

    if (!md)
        return 0;

    return EVP_DigestInit_ex(sc->mdCtx, md, nullptr);
}

// digest_sign_update: feed data into the digest AND mirror it into the
// raw accumulator so digest_sign_final has both views (hash + original
// bytes). The mirror is bounded by the CMS_signerInfo / PDF byte-range
// size — typically a few KB per sign — so the memory cost is negligible
// against the keep-bytes-around win for hash-on-card SSCDs.
int sigDigestSignUpdate(void* ctx, const unsigned char* data, size_t datalen)
{
    auto* sc = static_cast<SignCtx*>(ctx);
    if (!sc->mdCtx)
        return 0;
    try {
        sc->rawAccumulator.insert(sc->rawAccumulator.end(), data, data + datalen);
    } catch (const std::bad_alloc& e) {
        std::cerr << "libresign: sigDigestSignUpdate bad_alloc: " << e.what() << std::endl;
        return 0;
    }
    return EVP_DigestUpdate(sc->mdCtx, data, datalen);
}

// digest_sign_final: finalize digest and sign via PKCS#11 token
int sigDigestSignFinal(void* ctx, unsigned char* sig, size_t* siglen, size_t sigsize)
{
    auto* sc = static_cast<SignCtx*>(ctx);
    if (!sc->keyData || !sc->keyData->token || !sc->mdCtx)
        return 0;

    // Size query
    if (sig == nullptr) {
        *siglen = static_cast<size_t>(sc->keyData->maxSigSize);
        return 1;
    }

    // Finalize the digest
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hashLen = 0;
    if (!EVP_DigestFinal_ex(sc->mdCtx, hash, &hashLen))
        return 0;

    try {
        // NOTE: Cannot use native_utils::signHashWithToken() here because this
        // runs inside an OpenSSL provider callback with pre-computed hash bytes
        // (not a vector), variable digest algorithm, and must return 0/1 status.
        std::vector<uint8_t> signInput;

        if (sc->keyData->keyType == EVP_PKEY_RSA) {
            // RSA: prepend DigestInfo ASN.1 prefix, then send to card
            // CKM_RSA_PKCS expects DigestInfo || hash
            auto prefix = digestInfoPrefixForAlgo(sc->mdName);
            if (prefix.empty())
                return 0;

            signInput.reserve(prefix.size() + hashLen);
            signInput.insert(signInput.end(), prefix.begin(), prefix.end());
            signInput.insert(signInput.end(), hash, hash + hashLen);
        } else {
            // EC: send raw hash — CKM_ECDSA operates on raw hash
            signInput.assign(hash, hash + hashLen);
        }

        std::string algo = tokenAlgorithm(sc->keyData->keyType, sc->mdName);
        // Pass the accumulated raw bytes so Pkcs11Token can use the combined
        // CKM_SHA*_RSA_PKCS mechanism on hash-on-card SSCDs. Empty for ECDSA
        // (raw-hash mechanism is already correct on every supported card).
        std::span<const uint8_t> rawSpan;
        if (sc->keyData->keyType == EVP_PKEY_RSA)
            rawSpan = std::span<const uint8_t>{sc->rawAccumulator};
        auto result = sc->keyData->token->sign(signInput, algo, rawSpan);

        if (result.empty())
            return 0;

        // EC output from PKCS#11 is raw r||s — wrap in DER Ecdsa-Sig-Value
        // so CMS gets the RFC 5753 form.
        if (sc->keyData->keyType == EVP_PKEY_EC) {
            result = ecdsaRawToDer(result);
            if (result.empty())
                return 0;
        }

        if (result.size() > sigsize)
            return 0;

        std::memcpy(sig, result.data(), result.size());
        *siglen = result.size();
        return 1;
    } catch (const std::exception& e) {
        std::cerr << "libresign: sigDigestSignFinal exception: " << e.what() << std::endl;
        return 0;
    } catch (...) {
        std::cerr << "libresign: sigDigestSignFinal unknown exception" << std::endl;
        return 0;
    }
}

// set_ctx_params: handle digest and padding mode settings from OpenSSL
int sigSetCtxParams(void* ctx, const OSSL_PARAM params[])
{
    auto* sc = static_cast<SignCtx*>(ctx);

    const OSSL_PARAM* p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_DIGEST);
    if (p != nullptr) {
        const char* mdName = nullptr;
        if (!OSSL_PARAM_get_utf8_string_ptr(p, &mdName))
            return 0;
        if (mdName)
            sc->mdName = mdName;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_PAD_MODE);
    if (p != nullptr) {
        int mode = kPadPKCS1v15;
        if (p->data_type == OSSL_PARAM_INTEGER) {
            OSSL_PARAM_get_int(p, &mode);
        } else if (p->data_type == OSSL_PARAM_UTF8_STRING) {
            const char* padStr = nullptr;
            if (OSSL_PARAM_get_utf8_string_ptr(p, &padStr) && padStr) {
                if (std::strcmp(padStr, OSSL_PKEY_RSA_PAD_MODE_PKCSV15) == 0)
                    mode = kPadPKCS1v15;
                else if (std::strcmp(padStr, OSSL_PKEY_RSA_PAD_MODE_NONE) == 0)
                    mode = kPadNone;
                else
                    return 0; // PSS and other modes not supported
            }
        }
        if (mode == kPadPSS)
            return 0; // PSS not supported by PKCS#11 CKM_RSA_PKCS
        sc->padMode = mode;
    }

    return 1;
}

int sigGetCtxParams(void* ctx, OSSL_PARAM params[])
{
    auto* sc = static_cast<SignCtx*>(ctx);

    OSSL_PARAM* p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_DIGEST);
    if (p != nullptr) {
        if (!OSSL_PARAM_set_utf8_string(p, sc->mdName.c_str()))
            return 0;
    }

    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_PAD_MODE);
    if (p != nullptr) {
        if (!OSSL_PARAM_set_int(p, sc->padMode))
            return 0;
    }

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE);
    if (p != nullptr && sc->keyData) {
        if (!OSSL_PARAM_set_int(p, sc->keyData->maxSigSize))
            return 0;
    }

    return 1;
}

const OSSL_PARAM* sigSettableCtxParams(void* /*ctx*/, void* /*provctx*/)
{
    static const OSSL_PARAM settable[] = {OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, nullptr, 0),
                                          OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PAD_MODE, nullptr, 0),
                                          OSSL_PARAM_END};
    return settable;
}

const OSSL_PARAM* sigGettableCtxParams(void* /*ctx*/, void* /*provctx*/)
{
    static const OSSL_PARAM gettable[] = {OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, nullptr, 0),
                                          OSSL_PARAM_int(OSSL_SIGNATURE_PARAM_PAD_MODE, nullptr),
                                          OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, nullptr), OSSL_PARAM_END};
    return gettable;
}

} // anonymous namespace

// ---------------------------------------------------------------------------
// Signature dispatch + algorithm tables (shared by RSA and EC)
// ---------------------------------------------------------------------------
const OSSL_DISPATCH sigDispatch[] = {{OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))sigNewCtx},
                                     {OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))sigFreeCtx},
                                     {OSSL_FUNC_SIGNATURE_SIGN_INIT, (void (*)(void))sigSignInit},
                                     {OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void))sigSign},
                                     {OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT, (void (*)(void))sigDigestSignInit},
                                     {OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE, (void (*)(void))sigDigestSignUpdate},
                                     {OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL, (void (*)(void))sigDigestSignFinal},
                                     {OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS, (void (*)(void))sigSetCtxParams},
                                     {OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS, (void (*)(void))sigGetCtxParams},
                                     {OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS, (void (*)(void))sigSettableCtxParams},
                                     {OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS, (void (*)(void))sigGettableCtxParams},
                                     OSSL_DISPATCH_END};

const OSSL_ALGORITHM sigAlgorithms[] = {
    {"RSA:rsaEncryption", "provider=librescrs", sigDispatch, "LibreSCRS RSA signature"},
    {"ECDSA", "provider=librescrs", sigDispatch, "LibreSCRS ECDSA signature"},
    {nullptr, nullptr, nullptr, nullptr}};

} // namespace libresign::detail
