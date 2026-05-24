// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

/// @file
/// @brief Project-shared @c std::unique_ptr aliases for OpenSSL handles.
///
/// Mirrors @c lib/libresign/src/native/openssl_raii.h for OpenSSL types
/// used outside @c libresign (rs-eid card-data verification, pkcs15
/// SPKI parsing). Two separate definitions are tolerated because
/// @c openssl_raii.h pulls in @c openssl/cms.h, @c openssl/ts.h, and
/// @c openssl/ocsp.h that the leaner consumers do not need; the
/// aliases here include only @c x509.h, @c x509_vfy.h, @c bio.h,
/// @c bn.h, @c evp.h, @c pkcs7.h.
///
/// Both header families live under separate namespaces
/// (@c libresign vs. @c LibreSCRS::Internal::Crypto) so a TU that
/// transitively pulls in both does not run into ambiguous-alias
/// resolution at the use site.

#include <memory>

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/pkcs7.h>
#include <openssl/safestack.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

namespace LibreSCRS::Internal::Crypto {

struct X509Deleter
{
    void operator()(X509* p) const noexcept
    {
        X509_free(p);
    }
};
struct EvpPkeyDeleter
{
    void operator()(EVP_PKEY* p) const noexcept
    {
        EVP_PKEY_free(p);
    }
};
struct BioDeleter
{
    void operator()(BIO* p) const noexcept
    {
        BIO_free(p);
    }
};
struct EvpMdCtxDeleter
{
    void operator()(EVP_MD_CTX* p) const noexcept
    {
        EVP_MD_CTX_free(p);
    }
};
struct EvpCipherCtxDeleter
{
    void operator()(EVP_CIPHER_CTX* p) const noexcept
    {
        EVP_CIPHER_CTX_free(p);
    }
};
struct BnDeleter
{
    void operator()(BIGNUM* p) const noexcept
    {
        BN_free(p);
    }
};
struct Pkcs7Deleter
{
    void operator()(PKCS7* p) const noexcept
    {
        PKCS7_free(p);
    }
};
struct X509StoreCtxDeleter
{
    void operator()(X509_STORE_CTX* p) const noexcept
    {
        X509_STORE_CTX_free(p);
    }
};
struct StackX509Deleter
{
    void operator()(STACK_OF(X509) * p) const noexcept
    {
        // sk_X509_free releases the stack without touching the members;
        // PKCS7_get0_signers returns borrowed certs owned by the parent
        // PKCS7 structure, so the deeper sk_X509_pop_free path would
        // double-free.
        sk_X509_free(p);
    }
};

using X509Ptr = std::unique_ptr<X509, X509Deleter>;
using EvpPkeyPtr = std::unique_ptr<EVP_PKEY, EvpPkeyDeleter>;
using BioPtr = std::unique_ptr<BIO, BioDeleter>;
using EvpMdCtxPtr = std::unique_ptr<EVP_MD_CTX, EvpMdCtxDeleter>;
using EvpCipherCtxPtr = std::unique_ptr<EVP_CIPHER_CTX, EvpCipherCtxDeleter>;
using BnPtr = std::unique_ptr<BIGNUM, BnDeleter>;
using Pkcs7Ptr = std::unique_ptr<PKCS7, Pkcs7Deleter>;
using X509StoreCtxPtr = std::unique_ptr<X509_STORE_CTX, X509StoreCtxDeleter>;
using StackX509Ptr = std::unique_ptr<STACK_OF(X509), StackX509Deleter>;

} // namespace LibreSCRS::Internal::Crypto
