// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

#include <memory>

typedef struct evp_pkey_st EVP_PKEY;
typedef struct x509_st X509;

namespace libresign {

class Pkcs11Token;

// RAII wrapper for EVP_PKEY — defined here (separately from openssl_raii.h)
// because this is a public header that must not include internal OpenSSL headers.
// The deleter body lives in the .cpp file so we don't need <openssl/evp.h> here.
// openssl_raii.h has an identical alias for internal use; they are ABI-compatible.
struct EvpPkeyPublicDeleter
{
    void operator()(EVP_PKEY* p) const;
};
using EvpPkeyPublicPtr = std::unique_ptr<EVP_PKEY, EvpPkeyPublicDeleter>;

void initSigningProvider();

EvpPkeyPublicPtr createPkcs11EvpKey(Pkcs11Token& token, X509* cert);

} // namespace libresign
