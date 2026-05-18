// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

#include <cstdint>
#include <string>
#include <vector>

typedef struct evp_pkey_st EVP_PKEY;
typedef struct x509_st X509;
typedef struct ossl_dispatch_st OSSL_DISPATCH;
typedef struct ossl_algorithm_st OSSL_ALGORITHM;

namespace libresign {

class Pkcs11Token;

namespace detail {

// Custom OSSL_PARAM key for passing the token pointer through keymgmt_import.
inline constexpr const char* kParamTokenPtr = "librescrs-token-ptr";

// Opaque key data stored by our keymgmt.
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

// KeyReference — passed from createPkcs11EvpKey through keymgmt_import.
struct KeyReference
{
    Pkcs11Token* token;
    X509* cert;
};

// Populate RSA/EC public-key components (and derived maxSigSize) from an
// existing EVP_PKEY into a ProviderKeyData. Shared by kmLoad() and
// createPkcs11EvpKey() — the only two EVP_PKEY→component paths we have.
// BNPtr wraps each BIGNUM so a subsequent vector resize that throws
// bad_alloc cannot leak the BIGNUM. kmImport() has a different shape
// (OSSL_PARAM input) and is not merged here.
void populateKeyDataFromPkey(ProviderKeyData& kd, EVP_PKEY* pubKey);

// Dispatch + algorithm tables for keymgmt — assembled in
// signing_provider_keymgmt.cpp, consumed by the provider's
// query_operation callback.
extern const OSSL_DISPATCH kmDispatch[];
extern const OSSL_ALGORITHM kmAlgorithms[];

} // namespace detail
} // namespace libresign
