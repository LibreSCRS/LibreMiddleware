// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

/// @file
/// @brief The CMS / timestamp / OCSP half of the OpenSSL handle aliases.
///
/// Split out of @c OpenSslPtr.h rather than folded into it, because the split
/// IS the reason the tree carried two sets of these for so long: one of the two
/// pulled in @c cms.h, @c ts.h and @c ocsp.h, and the consumers that only parse
/// a certificate did not want them. Including this header is how a translation
/// unit says it does want them.

#include <LibreSCRS_internal/Crypto/OpenSslPtr.h>

#include <memory>

#include <openssl/cms.h>
#include <openssl/ocsp.h>
#include <openssl/ts.h>

namespace LibreSCRS::Internal::Crypto {

struct CmsDeleter
{
    void operator()(CMS_ContentInfo* p) const noexcept
    {
        CMS_ContentInfo_free(p);
    }
};
struct OcspReqDeleter
{
    void operator()(OCSP_REQUEST* p) const noexcept
    {
        OCSP_REQUEST_free(p);
    }
};
struct OcspRespDeleter
{
    void operator()(OCSP_RESPONSE* p) const noexcept
    {
        OCSP_RESPONSE_free(p);
    }
};
struct OcspBasicDeleter
{
    void operator()(OCSP_BASICRESP* p) const noexcept
    {
        OCSP_BASICRESP_free(p);
    }
};
struct TsReqDeleter
{
    void operator()(TS_REQ* p) const noexcept
    {
        TS_REQ_free(p);
    }
};
struct TsRespDeleter
{
    void operator()(TS_RESP* p) const noexcept
    {
        TS_RESP_free(p);
    }
};

using CmsPtr = std::unique_ptr<CMS_ContentInfo, CmsDeleter>;
using OcspReqPtr = std::unique_ptr<OCSP_REQUEST, OcspReqDeleter>;
using OcspRespPtr = std::unique_ptr<OCSP_RESPONSE, OcspRespDeleter>;
using OcspBasicPtr = std::unique_ptr<OCSP_BASICRESP, OcspBasicDeleter>;
using TsReqPtr = std::unique_ptr<TS_REQ, TsReqDeleter>;
using TsRespPtr = std::unique_ptr<TS_RESP, TsRespDeleter>;

} // namespace LibreSCRS::Internal::Crypto
