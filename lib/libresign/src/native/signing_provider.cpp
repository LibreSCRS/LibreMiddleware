// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// OpenSSL 3 provider for PKCS#11-backed signing.
// Replaces the deprecated RSA_METHOD approach (pkcs11_evp_key.cpp) with a
// proper provider that implements keymgmt + signature dispatch tables.
// This allows EVP_DigestSign* (used by CMS_sign/CMS_final) to transparently
// route private key operations to Pkcs11Token::sign().

#include "libresign/native/signing_provider.h"
#include "libresign/native/pkcs11_token.h"
#include "native_utils.h"

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/provider.h>
#include <openssl/x509.h>

// Padding mode constants (avoid #include <openssl/rsa.h> which pulls deprecated APIs)
constexpr int kPadPKCS1v15 = 1; // RSA_PKCS1_PADDING
constexpr int kPadNone = 3;     // RSA_NO_PADDING
constexpr int kPadPSS = 6;      // RSA_PKCS1_PSS_PADDING

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <memory>
#include <mutex>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

namespace libresign {

void EvpPkeyPublicDeleter::operator()(EVP_PKEY* p) const
{
    EVP_PKEY_free(p);
}

namespace {

// ---------------------------------------------------------------------------
// Custom OSSL_PARAM key for passing the token pointer through keymgmt_import
// ---------------------------------------------------------------------------
constexpr const char* kParamTokenPtr = "libresc-token-ptr";

// DigestInfo prefixes are in native_utils (kDigestInfoSha256Prefix etc.)

// Delegate to shared implementations in native_utils
using native_utils::digestInfoPrefixForAlgo;
using native_utils::tokenAlgorithm;

// PKCS#11 CKM_ECDSA returns the signature as the raw concatenation r||s
// (each zero-padded to the curve's field-size). CMS/CAdES/PAdES/ASiC-CAdES
// (RFC 5753) require the signature as DER-encoded `Ecdsa-Sig-Value
// SEQUENCE { r INTEGER, s INTEGER }`. Wrap before returning to OpenSSL's
// CMS pipeline. XAdES and JAdES call Pkcs11Token::sign() directly via
// signHashWithToken() — those paths keep raw r||s, which is the correct
// form for XMLDSig (ECDSASignatureValue) and JWS (RFC 7518 §3.4).
static std::vector<uint8_t> ecdsaRawToDer(const std::vector<uint8_t>& raw)
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
// ProviderKeyData — opaque key data stored by our keymgmt
// ---------------------------------------------------------------------------
struct ProviderKeyData
{
    Pkcs11Token* token = nullptr; // non-owning
    int keyType = 0;              // EVP_PKEY_RSA or EVP_PKEY_EC
    int keyBits = 0;
    int maxSigSize = 0;

    // Public key components for export (needed by EVP_PKEY_eq / CMS_sign)
    std::vector<uint8_t> rsaN;  // RSA modulus (unsigned big-endian)
    std::vector<uint8_t> rsaE;  // RSA public exponent (unsigned big-endian)
    std::vector<uint8_t> ecPub; // EC public key point (uncompressed)
    std::string ecGroup;        // EC curve name (e.g., "prime256v1")
};

// ---------------------------------------------------------------------------
// KeyReference — passed from createPkcs11EvpKey through keymgmt_import
// ---------------------------------------------------------------------------
struct KeyReference
{
    Pkcs11Token* token;
    X509* cert;
};

// ===========================================================================
// keymgmt dispatch
// ===========================================================================

static void* kmNew(void* /*provctx*/)
{
    return new ProviderKeyData();
}

static void kmFree(void* keydata)
{
    delete static_cast<ProviderKeyData*>(keydata);
}

static int kmHas(const void* keydata, int selection)
{
    auto* kd = static_cast<const ProviderKeyData*>(keydata);
    if (!kd || !kd->token)
        return 0;

    // We always claim to have both public and private key parts.
    // The private key is on the card, but we need OpenSSL to believe
    // it is present so that CMS_add1_signer accepts the key.
    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY)
        return 1;
    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY)
        return 1;
    if (selection & OSSL_KEYMGMT_SELECT_KEYPAIR)
        return 1;

    return 1; // domain params, other — always OK
}

static int kmGetParams(void* keydata, OSSL_PARAM params[])
{
    auto* kd = static_cast<ProviderKeyData*>(keydata);
    if (!kd)
        return 0;

    OSSL_PARAM* p;

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS);
    if (p != nullptr && !OSSL_PARAM_set_int(p, kd->keyBits))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS);
    if (p != nullptr) {
        // Rough approximation
        int secBits = kd->keyBits / 2;
        if (kd->keyType == EVP_PKEY_RSA) {
            if (kd->keyBits >= 4096)
                secBits = 152;
            else if (kd->keyBits >= 3072)
                secBits = 128;
            else if (kd->keyBits >= 2048)
                secBits = 112;
            else
                secBits = 80;
        }
        if (!OSSL_PARAM_set_int(p, secBits))
            return 0;
    }

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE);
    if (p != nullptr && !OSSL_PARAM_set_int(p, kd->maxSigSize))
        return 0;

    return 1;
}

static const OSSL_PARAM* kmGettableParams(void* /*provctx*/)
{
    static const OSSL_PARAM gettable[] = {OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, nullptr),
                                          OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, nullptr),
                                          OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, nullptr), OSSL_PARAM_END};
    return gettable;
}

// keymgmt_import: receives public key params from EVP_PKEY_fromdata,
// plus our custom "libresc-token-ptr" param with the Pkcs11Token pointer.
static int kmImport(void* keydata, int /*selection*/, const OSSL_PARAM params[])
{
    auto* kd = static_cast<ProviderKeyData*>(keydata);
    if (!kd)
        return 0;

    // Extract token pointer from our custom param
    const OSSL_PARAM* p = OSSL_PARAM_locate_const(params, kParamTokenPtr);
    if (p != nullptr) {
        void* ptr = nullptr;
        if (!OSSL_PARAM_get_octet_ptr(p, (const void**)&ptr, nullptr))
            return 0;
        kd->token = static_cast<Pkcs11Token*>(ptr);
    }

    // Extract key type
    p = OSSL_PARAM_locate_const(params, "libresc-key-type");
    if (p != nullptr)
        OSSL_PARAM_get_int(p, &kd->keyType);

    // Extract key bits
    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_BITS);
    if (p != nullptr)
        OSSL_PARAM_get_int(p, &kd->keyBits);

    // Compute max signature size from bits
    if (kd->keyType == EVP_PKEY_RSA) {
        kd->maxSigSize = (kd->keyBits + 7) / 8;
    } else if (kd->keyType == EVP_PKEY_EC) {
        // ECDSA DER-encoded signature: up to 2*(field_size + extra) + overhead
        int fieldSize = (kd->keyBits + 7) / 8;
        kd->maxSigSize = 2 * (fieldSize + 1) + 8;
    }

    // Extract RSA public key components (modulus + exponent).
    // BNPtr wraps each BIGNUM so rsaN/rsaE resize() throwing bad_alloc
    // cannot leak the BIGNUM.
    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_N);
    if (p != nullptr) {
        BIGNUM* rawBn = nullptr;
        if (OSSL_PARAM_get_BN(p, &rawBn)) {
            BNPtr bn(rawBn);
            int len = BN_num_bytes(bn.get());
            kd->rsaN.resize(static_cast<size_t>(len));
            BN_bn2bin(bn.get(), kd->rsaN.data());
        }
    }

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_E);
    if (p != nullptr) {
        BIGNUM* rawBn = nullptr;
        if (OSSL_PARAM_get_BN(p, &rawBn)) {
            BNPtr bn(rawBn);
            int len = BN_num_bytes(bn.get());
            kd->rsaE.resize(static_cast<size_t>(len));
            BN_bn2bin(bn.get(), kd->rsaE.data());
        }
    }

    // Extract EC public key components (group name + public point)
    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_GROUP_NAME);
    if (p != nullptr) {
        const char* groupName = nullptr;
        if (OSSL_PARAM_get_utf8_string_ptr(p, &groupName) && groupName)
            kd->ecGroup = groupName;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY);
    if (p != nullptr) {
        size_t len = 0;
        const void* ptr = nullptr;
        if (OSSL_PARAM_get_octet_string_ptr(p, &ptr, &len) && ptr && len > 0) {
            kd->ecPub.assign(static_cast<const uint8_t*>(ptr), static_cast<const uint8_t*>(ptr) + len);
        }
    }

    return 1;
}

static const OSSL_PARAM* kmImportTypes(int /*selection*/)
{
    static const OSSL_PARAM importable[] = {OSSL_PARAM_octet_ptr(kParamTokenPtr, nullptr, 0),
                                            OSSL_PARAM_int("libresc-key-type", nullptr),
                                            OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, nullptr),
                                            OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_N, nullptr, 0),
                                            OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_E, nullptr, 0),
                                            OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, nullptr, 0),
                                            OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, nullptr, 0),
                                            OSSL_PARAM_END};
    return importable;
}

// Populate RSA/EC public-key components (and derived maxSigSize) from an
// existing EVP_PKEY into a ProviderKeyData. Shared by kmLoad() and
// createPkcs11EvpKey() — the only two EVP_PKEY→component paths we have.
// BNPtr wraps each BIGNUM so a subsequent vector resize that throws bad_alloc
// cannot leak the BIGNUM. kmImport() has a different shape (OSSL_PARAM input)
// and is not merged here.
static void populateKeyDataFromPkey(ProviderKeyData& kd, EVP_PKEY* pubKey)
{
    kd.keyType = EVP_PKEY_base_id(pubKey);
    kd.keyBits = EVP_PKEY_get_bits(pubKey);

    if (kd.keyType == EVP_PKEY_RSA) {
        kd.maxSigSize = (kd.keyBits + 7) / 8;
        BIGNUM* rawN = nullptr;
        if (EVP_PKEY_get_bn_param(pubKey, OSSL_PKEY_PARAM_RSA_N, &rawN)) {
            BNPtr n(rawN);
            kd.rsaN.resize(static_cast<size_t>(BN_num_bytes(n.get())));
            BN_bn2bin(n.get(), kd.rsaN.data());
        }
        BIGNUM* rawE = nullptr;
        if (EVP_PKEY_get_bn_param(pubKey, OSSL_PKEY_PARAM_RSA_E, &rawE)) {
            BNPtr e(rawE);
            kd.rsaE.resize(static_cast<size_t>(BN_num_bytes(e.get())));
            BN_bn2bin(e.get(), kd.rsaE.data());
        }
    } else if (kd.keyType == EVP_PKEY_EC) {
        int fieldSize = (kd.keyBits + 7) / 8;
        kd.maxSigSize = 2 * (fieldSize + 1) + 8;
        char groupBuf[64] = {};
        size_t groupLen = 0;
        if (EVP_PKEY_get_utf8_string_param(pubKey, OSSL_PKEY_PARAM_GROUP_NAME, groupBuf, sizeof(groupBuf), &groupLen))
            kd.ecGroup.assign(groupBuf, groupLen);
        // Two-call sizing: query required length first, then fill.
        size_t pubLen = 0;
        EVP_PKEY_get_octet_string_param(pubKey, OSSL_PKEY_PARAM_PUB_KEY, nullptr, 0, &pubLen);
        if (pubLen > 0) {
            kd.ecPub.resize(pubLen);
            EVP_PKEY_get_octet_string_param(pubKey, OSSL_PKEY_PARAM_PUB_KEY, kd.ecPub.data(), kd.ecPub.size(), &pubLen);
            kd.ecPub.resize(pubLen);
        }
    }
}

// keymgmt_load: alternative loading path via opaque reference.
// Used when a STORE loader passes a KeyReference.
static void* kmLoad(const void* reference, size_t referenceSz)
{
    if (referenceSz != sizeof(KeyReference))
        return nullptr;

    auto* ref = static_cast<const KeyReference*>(reference);
    if (!ref->token || !ref->cert)
        return nullptr;

    EVP_PKEY* pubKey = X509_get0_pubkey(ref->cert);
    if (!pubKey)
        return nullptr;

    auto kd = std::make_unique<ProviderKeyData>();
    kd->token = ref->token;
    populateKeyDataFromPkey(*kd, pubKey);
    return kd.release();
}

// keymgmt_export: return stored public key components so EVP_PKEY_eq can
// compare our provider key against the certificate's public key.
// IMPORTANT: we only export the public key portion. If the caller asks
// for private key data (e.g., for key migration), we refuse — the private
// key lives on the hardware token and cannot be exported.
static int kmExport(void* keydata, int selection, OSSL_CALLBACK* param_cb, void* cbarg)
{
    auto* kd = static_cast<ProviderKeyData*>(keydata);
    if (!kd)
        return 0;

    // Refuse if private key export is requested — our private key is on
    // the hardware token and cannot be exported. This prevents OpenSSL
    // from migrating our key to the default provider for signing.
    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY)
        return 0;

    if (!(selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY))
        return 0;

    if (kd->keyType == EVP_PKEY_RSA && !kd->rsaN.empty() && !kd->rsaE.empty()) {
        OSSL_PARAM params[3];
        params[0] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_N, kd->rsaN.data(), kd->rsaN.size());
        params[1] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_E, kd->rsaE.data(), kd->rsaE.size());
        params[2] = OSSL_PARAM_construct_end();
        return param_cb(params, cbarg);
    }

    if (kd->keyType == EVP_PKEY_EC && !kd->ecPub.empty() && !kd->ecGroup.empty()) {
        OSSL_PARAM params[3];
        params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, const_cast<char*>(kd->ecGroup.c_str()),
                                                     kd->ecGroup.size());
        params[1] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, kd->ecPub.data(), kd->ecPub.size());
        params[2] = OSSL_PARAM_construct_end();
        return param_cb(params, cbarg);
    }

    return 0;
}

static const OSSL_PARAM* kmExportTypes(int selection)
{
    // Only advertise public key export capability
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) && !(selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY)) {
        static const OSSL_PARAM types[] = {
            OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_N, nullptr, 0), OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_E, nullptr, 0),
            OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, nullptr, 0),
            OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, nullptr, 0), OSSL_PARAM_END};
        return types;
    }
    return nullptr;
}

// ---------------------------------------------------------------------------
// keymgmt dispatch tables
// ---------------------------------------------------------------------------
// Shared dispatch table for both RSA and EC keymgmt — the callbacks are
// algorithm-agnostic (they dispatch on kd->keyType internally). Having a
// single table avoids the drift risk of two identical copies.
static const OSSL_DISPATCH kmDispatch[] = {{OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))kmNew},
                                           {OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))kmFree},
                                           {OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))kmHas},
                                           {OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))kmLoad},
                                           {OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))kmImport},
                                           {OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))kmImportTypes},
                                           {OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))kmExport},
                                           {OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))kmExportTypes},
                                           {OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void))kmGetParams},
                                           {OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*)(void))kmGettableParams},
                                           OSSL_DISPATCH_END};

// ===========================================================================
// Signature dispatch
// ===========================================================================

struct SignCtx
{
    ProviderKeyData* keyData = nullptr; // non-owning (owned by keymgmt)
    EVP_MD_CTX* mdCtx = nullptr;
    std::string mdName;
    int padMode = kPadPKCS1v15;

    ~SignCtx()
    {
        if (mdCtx)
            EVP_MD_CTX_free(mdCtx);
    }
};

static void* sigNewCtx(void* /*provctx*/, const char* /*propq*/)
{
    return new SignCtx();
}

static void sigFreeCtx(void* ctx)
{
    delete static_cast<SignCtx*>(ctx);
}

// sign_init: store the key reference for later use by sign()
static int sigSignInit(void* ctx, void* provkey, const OSSL_PARAM /*params*/[])
{
    auto* sc = static_cast<SignCtx*>(ctx);
    sc->keyData = static_cast<ProviderKeyData*>(provkey);
    return 1;
}

// sign: raw sign (receives pre-hashed data with DigestInfo for RSA).
// Note: mdName may be empty here (set_ctx_params not always called before sign).
// tokenAlgorithm defaults to SHA256withRSA/ECDSA, which is benign for RSA
// (CKM_RSA_PKCS is digest-agnostic) and matches the CMS pipeline's default.
static int sigSign(void* ctx, unsigned char* sig, size_t* siglen, size_t sigsize, const unsigned char* tbs,
                   size_t tbslen)
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
    } catch (...) {
        return 0;
    }
}

// digest_sign_init: set up digest context for streaming sign
static int sigDigestSignInit(void* ctx, const char* mdname, void* provkey, const OSSL_PARAM /*params*/[])
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

// digest_sign_update: feed data into the digest
static int sigDigestSignUpdate(void* ctx, const unsigned char* data, size_t datalen)
{
    auto* sc = static_cast<SignCtx*>(ctx);
    if (!sc->mdCtx)
        return 0;

    return EVP_DigestUpdate(sc->mdCtx, data, datalen);
}

// digest_sign_final: finalize digest and sign via PKCS#11 token
static int sigDigestSignFinal(void* ctx, unsigned char* sig, size_t* siglen, size_t sigsize)
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
        auto result = sc->keyData->token->sign(signInput, algo);

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
    } catch (...) {
        return 0;
    }
}

// set_ctx_params: handle digest and padding mode settings from OpenSSL
static int sigSetCtxParams(void* ctx, const OSSL_PARAM params[])
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

static int sigGetCtxParams(void* ctx, OSSL_PARAM params[])
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

static const OSSL_PARAM* sigSettableCtxParams(void* /*ctx*/, void* /*provctx*/)
{
    static const OSSL_PARAM settable[] = {OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, nullptr, 0),
                                          OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PAD_MODE, nullptr, 0),
                                          OSSL_PARAM_END};
    return settable;
}

static const OSSL_PARAM* sigGettableCtxParams(void* /*ctx*/, void* /*provctx*/)
{
    static const OSSL_PARAM gettable[] = {OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, nullptr, 0),
                                          OSSL_PARAM_int(OSSL_SIGNATURE_PARAM_PAD_MODE, nullptr),
                                          OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, nullptr), OSSL_PARAM_END};
    return gettable;
}

// ---------------------------------------------------------------------------
// Signature dispatch table (shared by RSA and EC)
// ---------------------------------------------------------------------------
static const OSSL_DISPATCH sigDispatch[] = {
    {OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))sigNewCtx},
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

// ===========================================================================
// Algorithm tables
// ===========================================================================

static const OSSL_ALGORITHM kmAlgorithms[] = {
    {"RSA:rsaEncryption", "provider=libresc", kmDispatch, "LibreSCRS RSA keymgmt"},
    {"EC:id-ecPublicKey", "provider=libresc", kmDispatch, "LibreSCRS EC keymgmt"},
    {nullptr, nullptr, nullptr, nullptr}};

static const OSSL_ALGORITHM sigAlgorithms[] = {
    {"RSA:rsaEncryption", "provider=libresc", sigDispatch, "LibreSCRS RSA signature"},
    {"ECDSA", "provider=libresc", sigDispatch, "LibreSCRS ECDSA signature"},
    {nullptr, nullptr, nullptr, nullptr}};

// ===========================================================================
// Provider dispatch
// ===========================================================================

static const OSSL_ALGORITHM* provQueryOperation(void* /*provctx*/, int operationId, int* noStore)
{
    *noStore = 0;
    switch (operationId) {
    case OSSL_OP_KEYMGMT:
        return kmAlgorithms;
    case OSSL_OP_SIGNATURE:
        return sigAlgorithms;
    default:
        return nullptr;
    }
}

static void provTeardown(void* /*provctx*/)
{
    // Nothing to clean up — we use no per-provider state
}

static const OSSL_DISPATCH providerDispatch[] = {
    {OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))provQueryOperation},
    {OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))provTeardown},
    OSSL_DISPATCH_END};

} // anonymous namespace

// ===========================================================================
// Provider init entry point (extern "C" linkage via OSSL_provider_init_fn)
// ===========================================================================

static int librescProviderInit(const OSSL_CORE_HANDLE* /*handle*/, const OSSL_DISPATCH* /*in*/,
                               const OSSL_DISPATCH** out, void** provctx)
{
    *out = providerDispatch;
    *provctx = nullptr; // no per-provider state needed
    return 1;
}

// ===========================================================================
// Public API
// ===========================================================================

static std::once_flag g_providerInitFlag;

void initSigningProvider()
{
    std::call_once(g_providerInitFlag, []() {
        // Load default provider FIRST so it has priority for standard RSA/EC
        // operations (X509_get0_pubkey, EVP_DigestVerify, etc.). Our provider
        // is only used when explicitly requested via "provider=libresc" query.
        if (!OSSL_PROVIDER_available(nullptr, "default"))
            OSSL_PROVIDER_load(nullptr, "default");

        if (!OSSL_PROVIDER_add_builtin(nullptr, "libresc", librescProviderInit))
            throw std::runtime_error("Failed to register libresc provider");

        // Provider handles are intentionally not stored — they live for the
        // process lifetime and are owned by the default OSSL_LIB_CTX.
        if (!OSSL_PROVIDER_load(nullptr, "libresc"))
            throw std::runtime_error("Failed to load libresc provider");
    });
}

EvpPkeyPublicPtr createPkcs11EvpKey(Pkcs11Token& token, X509* cert)
{
    if (!cert)
        throw std::runtime_error("Certificate must not be null");

    initSigningProvider();

    // Get public key info from certificate
    EVP_PKEY* certPubKey = X509_get0_pubkey(cert);
    if (!certPubKey)
        throw std::runtime_error("Certificate does not contain a public key");

    // Extract key type, size, and RSA/EC public components via the shared
    // helper. A local ProviderKeyData acts as the out-struct; only token/
    // maxSigSize fields are unused here.
    ProviderKeyData tempKd;
    populateKeyDataFromPkey(tempKd, certPubKey);
    if (tempKd.keyType != EVP_PKEY_RSA && tempKd.keyType != EVP_PKEY_EC)
        throw std::runtime_error("Unsupported key type (need RSA or EC)");
    int keyType = tempKd.keyType;
    int keyBits = tempKd.keyBits;
    // Non-const refs because OSSL_PARAM_construct_BN / _octet_string / _utf8_string
    // take non-const void*/char* even though they don't mutate.
    auto& rsaN = tempKd.rsaN;
    auto& rsaE = tempKd.rsaE;
    auto& ecGroup = tempKd.ecGroup;
    auto& ecPub = tempKd.ecPub;

    // Determine algorithm name for our provider
    const char* algoName = (keyType == EVP_PKEY_RSA) ? "RSA" : "EC";

    // Create EVP_PKEY_CTX targeting our provider via property query.
    // Wrapped in RAII so a std::bad_alloc from the params vector below
    // (or any other throw) can't leak the context.
    EvpPkeyCtxPtr pctx(EVP_PKEY_CTX_new_from_name(nullptr, algoName, "provider=libresc"));
    if (!pctx)
        throw std::runtime_error("EVP_PKEY_CTX_new_from_name failed for libresc");

    // Build OSSL_PARAM array with token pointer, key metadata, and public
    // key components. The token pointer is passed as an OCTET_PTR so it goes
    // through our keymgmt_import as an opaque pointer value.
    void* tokenPtr = &token;

    // Use a vector to build params dynamically based on key type
    std::vector<OSSL_PARAM> params;
    params.push_back(OSSL_PARAM_construct_octet_ptr(kParamTokenPtr, &tokenPtr, sizeof(void*)));
    params.push_back(OSSL_PARAM_construct_int("libresc-key-type", &keyType));
    params.push_back(OSSL_PARAM_construct_int(OSSL_PKEY_PARAM_BITS, &keyBits));

    if (keyType == EVP_PKEY_RSA && !rsaN.empty() && !rsaE.empty()) {
        params.push_back(OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_N, rsaN.data(), rsaN.size()));
        params.push_back(OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_E, rsaE.data(), rsaE.size()));
    } else if (keyType == EVP_PKEY_EC && !ecPub.empty() && !ecGroup.empty()) {
        params.push_back(OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
                                                          const_cast<char*>(ecGroup.c_str()), ecGroup.size()));
        params.push_back(OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, ecPub.data(), ecPub.size()));
    }

    params.push_back(OSSL_PARAM_construct_end());

    if (!EVP_PKEY_fromdata_init(pctx.get()))
        throw std::runtime_error("EVP_PKEY_fromdata_init failed");

    EVP_PKEY* pkey = nullptr;
    if (!EVP_PKEY_fromdata(pctx.get(), &pkey, OSSL_KEYMGMT_SELECT_ALL, params.data()))
        throw std::runtime_error("EVP_PKEY_fromdata failed — "
                                 "could not create provider-backed EVP_PKEY");

    if (!pkey)
        throw std::runtime_error("EVP_PKEY_fromdata returned null key");

    return EvpPkeyPublicPtr(pkey);
}

} // namespace libresign
