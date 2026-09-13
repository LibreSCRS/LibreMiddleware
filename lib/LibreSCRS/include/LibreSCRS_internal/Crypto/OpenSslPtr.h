// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

/// @file
/// @brief Project-shared @c std::unique_ptr aliases for OpenSSL handles.
///
/// One set, for every internal consumer: the signing engine, the card-data
/// verification paths, the trust store, PKCS#15 SPKI parsing. There used to be
/// two, in two namespaces, and the reason given for the split was the include
/// cost -- one of them pulled in @c cms.h, @c ts.h and @c ocsp.h that the
/// leaner consumers did not need. That reason is answered by @c OpenSslPtrCms.h
/// beside this file, which is where those three live now: this header includes
/// only @c x509.h, @c x509_vfy.h, @c bio.h, @c bn.h, @c evp.h, @c pkcs7.h and
/// @c safestack.h, and a consumer that needs the CMS family says so.
///
/// @warning The two X509 STACK deleters below do OPPOSITE things to the same
///          argument, and that is why neither is called what either used to be
///          called. See their own documentation.

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
struct X509CrlDeleter
{
    void operator()(X509_CRL* p) const noexcept
    {
        X509_CRL_free(p);
    }
};
struct X509AttributeDeleter
{
    void operator()(X509_ATTRIBUTE* p) const noexcept
    {
        X509_ATTRIBUTE_free(p);
    }
};
struct EvpPkeyDeleter
{
    void operator()(EVP_PKEY* p) const noexcept
    {
        EVP_PKEY_free(p);
    }
};
struct EvpPkeyCtxDeleter
{
    void operator()(EVP_PKEY_CTX* p) const noexcept
    {
        EVP_PKEY_CTX_free(p);
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
/// @brief Frees a BIGNUM, zeroing its limb buffer first.
///
/// Cleansing, for every BIGNUM this tree releases through a deleter and not
/// only the secret ones, because it has already been through the other
/// arrangement. PACE holds three secrets that exist ONLY as a BIGNUM -- the
/// ephemeral private keys skMap and skAgree, the x-coordinate of the ECDH
/// shared secret K, and the decrypted nonce s -- and @c CleanseGuard cannot
/// reach any of them: it wipes @c std::vector, and the ephemeral private key
/// has no vector copy at all. Plain @c BN_free hands the limb buffer back with
/// the secret still in it, where a core dump, a swap page or the next
/// allocation of that size can read it.
///
/// One deleter, not two, and it cleanses for every caller -- including the ones
/// holding nothing secret. A second, plain deleter for public values saves a
/// single @c OPENSSL_cleanse over the limb buffer, negligible beside the free it
/// sits in front of, and buys a choice at every call site in exchange: two
/// deleters that differ only in whether they wipe are one wrong pick away from
/// handing a secret back intact, with no diagnostic anywhere.
///
/// @see ci/scripts/check-cleansing-deleters.sh, which fails if this call or
///      this reason goes missing again, and if a BIGNUM anywhere in this tree
///      is released through a deleter that does not cleanse -- written as a
///      struct, a function pointer or a lambda -- outside the sites recorded
///      in ci/cleansing-deleter-exceptions.txt.
struct BnDeleter
{
    void operator()(BIGNUM* p) const noexcept
    {
        BN_clear_free(p);
    }
};
struct Pkcs7Deleter
{
    void operator()(PKCS7* p) const noexcept
    {
        PKCS7_free(p);
    }
};
struct X509StoreDeleter
{
    void operator()(X509_STORE* p) const noexcept
    {
        X509_STORE_free(p);
    }
};
struct X509StoreCtxDeleter
{
    void operator()(X509_STORE_CTX* p) const noexcept
    {
        X509_STORE_CTX_free(p);
    }
};
struct Asn1IntegerDeleter
{
    void operator()(ASN1_INTEGER* p) const noexcept
    {
        ASN1_INTEGER_free(p);
    }
};
struct Asn1ObjectDeleter
{
    void operator()(ASN1_OBJECT* p) const noexcept
    {
        ASN1_OBJECT_free(p);
    }
};
struct Asn1StringDeleter
{
    void operator()(ASN1_STRING* p) const noexcept
    {
        ASN1_STRING_free(p);
    }
};

/// @brief Frees the stack AND every certificate in it.
///
/// For a stack this code built or was handed ownership of -- a chain read out
/// of a signature, a set of anchors loaded from disk. The name says "owning"
/// because the alternative below is one character away in meaning and was one
/// word away in spelling: two structures with the SAME name lived in this tree,
/// in two namespaces, doing opposite things to the same argument, so a line
/// copied from one file into the other was a double free or a leak with no
/// diagnostic anywhere.
struct X509StackOwningDeleter
{
    void operator()(STACK_OF(X509) * p) const noexcept
    {
        sk_X509_pop_free(p, X509_free);
    }
};

/// @brief Frees the stack and NOTHING in it.
///
/// For a stack whose members belong to something else. @c PKCS7_get0_signers
/// returns certificates owned by the parent @c PKCS7 structure -- the @c get0
/// in the name is the whole contract -- so running the owning deleter above
/// over that stack frees certificates the parent will free again.
struct X509StackBorrowedDeleter
{
    void operator()(STACK_OF(X509) * p) const noexcept
    {
        sk_X509_free(p);
    }
};

using X509Ptr = std::unique_ptr<X509, X509Deleter>;
using X509CrlPtr = std::unique_ptr<X509_CRL, X509CrlDeleter>;
using X509AttributePtr = std::unique_ptr<X509_ATTRIBUTE, X509AttributeDeleter>;
using EvpPkeyPtr = std::unique_ptr<EVP_PKEY, EvpPkeyDeleter>;
using EvpPkeyCtxPtr = std::unique_ptr<EVP_PKEY_CTX, EvpPkeyCtxDeleter>;
using BioPtr = std::unique_ptr<BIO, BioDeleter>;
using EvpMdCtxPtr = std::unique_ptr<EVP_MD_CTX, EvpMdCtxDeleter>;
using BnPtr = std::unique_ptr<BIGNUM, BnDeleter>;
using Pkcs7Ptr = std::unique_ptr<PKCS7, Pkcs7Deleter>;
using X509StorePtr = std::unique_ptr<X509_STORE, X509StoreDeleter>;
using X509StoreCtxPtr = std::unique_ptr<X509_STORE_CTX, X509StoreCtxDeleter>;
using Asn1IntegerPtr = std::unique_ptr<ASN1_INTEGER, Asn1IntegerDeleter>;
using Asn1ObjectPtr = std::unique_ptr<ASN1_OBJECT, Asn1ObjectDeleter>;
using Asn1StringPtr = std::unique_ptr<ASN1_STRING, Asn1StringDeleter>;

/// @see X509StackOwningDeleter -- frees the members too.
using X509StackOwningPtr = std::unique_ptr<STACK_OF(X509), X509StackOwningDeleter>;
/// @see X509StackBorrowedDeleter -- frees only the stack.
using X509StackBorrowedPtr = std::unique_ptr<STACK_OF(X509), X509StackBorrowedDeleter>;

} // namespace LibreSCRS::Internal::Crypto
