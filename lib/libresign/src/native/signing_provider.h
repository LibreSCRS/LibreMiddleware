// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

#include <memory>

typedef struct evp_pkey_st EVP_PKEY;
typedef struct x509_st X509;

namespace libresign {

class Pkcs11Token;

// RAII wrapper for EVP_PKEY — declared here rather than taken from the shared
// internal set, because this header must not include an OpenSSL header at all:
// the deleter body lives in the .cpp, so <openssl/evp.h> stays out of every
// consumer of this file. The shared set's EvpPkeyPtr is the same shape and the
// two are ABI-compatible; this one exists for the include boundary, which is a
// reason the registry carries rather than a duplicate it tolerates.
struct EvpPkeyPublicDeleter
{
    void operator()(EVP_PKEY* p) const;
};
using EvpPkeyPublicPtr = std::unique_ptr<EVP_PKEY, EvpPkeyPublicDeleter>;

void initSigningProvider();

EvpPkeyPublicPtr createPkcs11EvpKey(Pkcs11Token& token, X509* cert);

} // namespace libresign
