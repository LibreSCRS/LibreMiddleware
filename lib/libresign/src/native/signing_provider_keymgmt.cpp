// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// OpenSSL 3 provider — keymgmt callbacks (key import/export, parameter
// queries, load-by-reference). The dispatch table assembled here is
// consumed by the provider's query_operation in signing_provider.cpp.

#include "native/signing_provider_keymgmt.h"
#include "native/openssl_raii.h"
#include "native/pkcs11_token.h"

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/x509.h>

#include <cstdint>
#include <memory>

namespace libresign::detail {

void populateKeyDataFromPkey(ProviderKeyData& kd, EVP_PKEY* pubKey)
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

namespace {

// ---------------------------------------------------------------------------
// keymgmt callbacks
// ---------------------------------------------------------------------------

void* kmNew(void* /*provctx*/)
{
    return new ProviderKeyData();
}

void kmFree(void* keydata)
{
    delete static_cast<ProviderKeyData*>(keydata);
}

int kmHas(const void* keydata, int selection)
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

int kmGetParams(void* keydata, OSSL_PARAM params[])
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

const OSSL_PARAM* kmGettableParams(void* /*provctx*/)
{
    static const OSSL_PARAM gettable[] = {OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, nullptr),
                                          OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, nullptr),
                                          OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, nullptr), OSSL_PARAM_END};
    return gettable;
}

// keymgmt_import: receives public key params from EVP_PKEY_fromdata,
// plus our custom "librescrs-token-ptr" param with the Pkcs11Token pointer.
int kmImport(void* keydata, int /*selection*/, const OSSL_PARAM params[])
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
    p = OSSL_PARAM_locate_const(params, "librescrs-key-type");
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

const OSSL_PARAM* kmImportTypes(int /*selection*/)
{
    static const OSSL_PARAM importable[] = {OSSL_PARAM_octet_ptr(kParamTokenPtr, nullptr, 0),
                                            OSSL_PARAM_int("librescrs-key-type", nullptr),
                                            OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, nullptr),
                                            OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_N, nullptr, 0),
                                            OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_E, nullptr, 0),
                                            OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, nullptr, 0),
                                            OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, nullptr, 0),
                                            OSSL_PARAM_END};
    return importable;
}

// keymgmt_load: alternative loading path via opaque reference.
// Used when a STORE loader passes a KeyReference.
void* kmLoad(const void* reference, size_t referenceSz)
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
int kmExport(void* keydata, int selection, OSSL_CALLBACK* param_cb, void* cbarg)
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

const OSSL_PARAM* kmExportTypes(int selection)
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

} // anonymous namespace

// ---------------------------------------------------------------------------
// keymgmt dispatch + algorithm tables
// ---------------------------------------------------------------------------
// Shared dispatch table for both RSA and EC keymgmt — the callbacks are
// algorithm-agnostic (they dispatch on kd->keyType internally). Having a
// single table avoids the drift risk of two identical copies.
const OSSL_DISPATCH kmDispatch[] = {{OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))kmNew},
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

const OSSL_ALGORITHM kmAlgorithms[] = {{"RSA:rsaEncryption", "provider=librescrs", kmDispatch, "LibreSCRS RSA keymgmt"},
                                       {"EC:id-ecPublicKey", "provider=librescrs", kmDispatch, "LibreSCRS EC keymgmt"},
                                       {nullptr, nullptr, nullptr, nullptr}};

} // namespace libresign::detail
