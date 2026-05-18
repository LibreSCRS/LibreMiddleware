// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// OpenSSL 3 provider for PKCS#11-backed signing — public entry points and
// provider dispatch assembly. The keymgmt and signature dispatch tables
// live in signing_provider_keymgmt.cpp and signing_provider_signature.cpp
// respectively; this TU only wires them up under the provider's
// query_operation callback.

#include "native/signing_provider.h"
#include "native/openssl_raii.h"
#include "native/pkcs11_token.h"
#include "native/signing_provider_keymgmt.h"
#include "native/signing_provider_signature.h"

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/provider.h>
#include <openssl/x509.h>

#include <mutex>
#include <stdexcept>
#include <vector>

namespace libresign {

void EvpPkeyPublicDeleter::operator()(EVP_PKEY* p) const
{
    EVP_PKEY_free(p);
}

namespace {

// ---------------------------------------------------------------------------
// Provider dispatch
// ---------------------------------------------------------------------------

const OSSL_ALGORITHM* provQueryOperation(void* /*provctx*/, int operationId, int* noStore)
{
    *noStore = 0;
    switch (operationId) {
    case OSSL_OP_KEYMGMT:
        return detail::kmAlgorithms;
    case OSSL_OP_SIGNATURE:
        return detail::sigAlgorithms;
    default:
        return nullptr;
    }
}

void provTeardown(void* /*provctx*/)
{
    // Nothing to clean up — we use no per-provider state
}

const OSSL_DISPATCH providerDispatch[] = {{OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))provQueryOperation},
                                          {OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))provTeardown},
                                          OSSL_DISPATCH_END};

// ---------------------------------------------------------------------------
// Provider init entry point (extern "C" linkage via OSSL_provider_init_fn)
// ---------------------------------------------------------------------------

int librescrsProviderInit(const OSSL_CORE_HANDLE* /*handle*/, const OSSL_DISPATCH* /*in*/, const OSSL_DISPATCH** out,
                          void** provctx)
{
    *out = providerDispatch;
    *provctx = nullptr; // no per-provider state needed
    return 1;
}

std::once_flag g_providerInitFlag;

} // anonymous namespace

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

void initSigningProvider()
{
    std::call_once(g_providerInitFlag, []() {
        // Load default provider FIRST so it has priority for standard RSA/EC
        // operations (X509_get0_pubkey, EVP_DigestVerify, etc.). Our provider
        // is only used when explicitly requested via "provider=librescrs" query.
        if (!OSSL_PROVIDER_available(nullptr, "default"))
            OSSL_PROVIDER_load(nullptr, "default");

        if (!OSSL_PROVIDER_add_builtin(nullptr, "librescrs", librescrsProviderInit))
            throw std::runtime_error("Failed to register librescrs provider");

        // Provider handles are intentionally not stored — they live for the
        // process lifetime and are owned by the default OSSL_LIB_CTX.
        if (!OSSL_PROVIDER_load(nullptr, "librescrs"))
            throw std::runtime_error("Failed to load librescrs provider");
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
    detail::ProviderKeyData tempKd;
    detail::populateKeyDataFromPkey(tempKd, certPubKey);
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
    EvpPkeyCtxPtr pctx(EVP_PKEY_CTX_new_from_name(nullptr, algoName, "provider=librescrs"));
    if (!pctx)
        throw std::runtime_error("EVP_PKEY_CTX_new_from_name failed for librescrs");

    // Build OSSL_PARAM array with token pointer, key metadata, and public
    // key components. The token pointer is passed as an OCTET_PTR so it goes
    // through our keymgmt_import as an opaque pointer value.
    void* tokenPtr = &token;

    // Use a vector to build params dynamically based on key type
    std::vector<OSSL_PARAM> params;
    params.push_back(OSSL_PARAM_construct_octet_ptr(detail::kParamTokenPtr, &tokenPtr, sizeof(void*)));
    params.push_back(OSSL_PARAM_construct_int("librescrs-key-type", &keyType));
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
