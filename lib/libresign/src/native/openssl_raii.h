// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

#include <memory>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/cms.h>
#include <openssl/evp.h>
#include <openssl/ocsp.h>
#include <openssl/ts.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>

namespace libresign {

// OpenSSL RAII deleters — one canonical definition for the entire project.
// Each struct + using alias follows the pattern: TypeDeleter + TypePtr.

struct X509Deleter
{
    void operator()(X509* p) const
    {
        X509_free(p);
    }
};
struct BioDeleter
{
    void operator()(BIO* p) const
    {
        BIO_free(p);
    }
};
struct CmsDeleter
{
    void operator()(CMS_ContentInfo* p) const
    {
        CMS_ContentInfo_free(p);
    }
};
struct EvpPkeyDeleter
{
    void operator()(EVP_PKEY* p) const
    {
        EVP_PKEY_free(p);
    }
};
struct EvpPkeyCtxDeleter
{
    void operator()(EVP_PKEY_CTX* p) const
    {
        EVP_PKEY_CTX_free(p);
    }
};
struct BNDeleter
{
    void operator()(BIGNUM* p) const
    {
        BN_free(p);
    }
};

struct StackX509Deleter
{
    void operator()(STACK_OF(X509) * p) const
    {
        sk_X509_pop_free(p, X509_free);
    }
};
struct StackX509CrlDeleter
{
    void operator()(STACK_OF(X509_CRL) * p) const
    {
        sk_X509_CRL_pop_free(p, X509_CRL_free);
    }
};

struct X509CrlDeleter
{
    void operator()(X509_CRL* p) const
    {
        X509_CRL_free(p);
    }
};
struct OcspReqDeleter
{
    void operator()(OCSP_REQUEST* p) const
    {
        OCSP_REQUEST_free(p);
    }
};
struct OcspRespDeleter
{
    void operator()(OCSP_RESPONSE* p) const
    {
        OCSP_RESPONSE_free(p);
    }
};
struct OcspBasicDeleter
{
    void operator()(OCSP_BASICRESP* p) const
    {
        OCSP_BASICRESP_free(p);
    }
};
struct TSReqDeleter
{
    void operator()(TS_REQ* p) const
    {
        TS_REQ_free(p);
    }
};
struct TSRespDeleter
{
    void operator()(TS_RESP* p) const
    {
        TS_RESP_free(p);
    }
};
struct ASN1IntDeleter
{
    void operator()(ASN1_INTEGER* p) const
    {
        ASN1_INTEGER_free(p);
    }
};
struct Asn1ObjectDeleter
{
    void operator()(ASN1_OBJECT* p) const
    {
        ASN1_OBJECT_free(p);
    }
};
struct Asn1StringDeleter
{
    void operator()(ASN1_STRING* p) const
    {
        ASN1_STRING_free(p);
    }
};
struct X509AttributeDeleter
{
    void operator()(X509_ATTRIBUTE* p) const
    {
        X509_ATTRIBUTE_free(p);
    }
};
struct X509AlgorDeleter
{
    void operator()(X509_ALGOR* p) const
    {
        X509_ALGOR_free(p);
    }
};
struct TSMsgImprintDeleter
{
    void operator()(TS_MSG_IMPRINT* p) const
    {
        TS_MSG_IMPRINT_free(p);
    }
};
struct OcspCertIdDeleter
{
    void operator()(OCSP_CERTID* p) const
    {
        OCSP_CERTID_free(p);
    }
};
struct EvpMdCtxDeleter
{
    void operator()(EVP_MD_CTX* p) const
    {
        EVP_MD_CTX_free(p);
    }
};
struct AuthorityInfoAccessDeleter
{
    void operator()(AUTHORITY_INFO_ACCESS* p) const
    {
        AUTHORITY_INFO_ACCESS_free(p);
    }
};
struct CrlDistPointsDeleter
{
    void operator()(STACK_OF(DIST_POINT) * p) const
    {
        CRL_DIST_POINTS_free(p);
    }
};
using X509Ptr = std::unique_ptr<X509, X509Deleter>;
using BioPtr = std::unique_ptr<BIO, BioDeleter>;
using CmsPtr = std::unique_ptr<CMS_ContentInfo, CmsDeleter>;
using EvpPkeyPtr = std::unique_ptr<EVP_PKEY, EvpPkeyDeleter>;
using EvpPkeyCtxPtr = std::unique_ptr<EVP_PKEY_CTX, EvpPkeyCtxDeleter>;
using BNPtr = std::unique_ptr<BIGNUM, BNDeleter>;
using StackX509Ptr = std::unique_ptr<STACK_OF(X509), StackX509Deleter>;
using StackX509CrlPtr = std::unique_ptr<STACK_OF(X509_CRL), StackX509CrlDeleter>;
using X509CrlPtr = std::unique_ptr<X509_CRL, X509CrlDeleter>;
using OcspReqPtr = std::unique_ptr<OCSP_REQUEST, OcspReqDeleter>;
using OcspRespPtr = std::unique_ptr<OCSP_RESPONSE, OcspRespDeleter>;
using OcspBasicPtr = std::unique_ptr<OCSP_BASICRESP, OcspBasicDeleter>;
using TSReqPtr = std::unique_ptr<TS_REQ, TSReqDeleter>;
using TSRespPtr = std::unique_ptr<TS_RESP, TSRespDeleter>;
using ASN1IntPtr = std::unique_ptr<ASN1_INTEGER, ASN1IntDeleter>;
using Asn1ObjectPtr = std::unique_ptr<ASN1_OBJECT, Asn1ObjectDeleter>;
using Asn1StringPtr = std::unique_ptr<ASN1_STRING, Asn1StringDeleter>;
using X509AttributePtr = std::unique_ptr<X509_ATTRIBUTE, X509AttributeDeleter>;
using X509AlgorPtr = std::unique_ptr<X509_ALGOR, X509AlgorDeleter>;
using TSMsgImprintPtr = std::unique_ptr<TS_MSG_IMPRINT, TSMsgImprintDeleter>;
using OcspCertIdPtr = std::unique_ptr<OCSP_CERTID, OcspCertIdDeleter>;
using EvpMdCtxPtr = std::unique_ptr<EVP_MD_CTX, EvpMdCtxDeleter>;
using AuthorityInfoAccessPtr = std::unique_ptr<AUTHORITY_INFO_ACCESS, AuthorityInfoAccessDeleter>;
using CrlDistPointsPtr = std::unique_ptr<STACK_OF(DIST_POINT), CrlDistPointsDeleter>;
// X509_STORE deleter, defined inline here. Self-contained — no #include cycles.
struct X509StoreDeleter
{
    void operator()(X509_STORE* p) const
    {
        X509_STORE_free(p);
    }
};
using X509StorePtr = std::unique_ptr<X509_STORE, X509StoreDeleter>;

} // namespace libresign
