// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace libresign {

struct TrustedServiceEntry
{
    std::string providerName;
    std::string serviceName;
    std::string serviceType;      // e.g., "http://uri.etsi.org/TrstSvc/Svctype/CA/QC"
    std::string status;           // e.g., "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted"
    std::vector<uint8_t> certDer; // DER-encoded X.509 certificate
};

struct TslPointer
{
    std::string url;
    std::vector<uint8_t> signingCertDer; // certificate to verify this TL
};

struct TrustedListInfo
{
    std::string schemeTerritory; // e.g., "RS", "EE", "DE"
    std::string schemeName;
    std::string issueDate;
    std::string nextUpdate;
    std::vector<TrustedServiceEntry> services;
    std::vector<TslPointer> pointersToOtherTSL; // LOTL: URLs of member state TLs
};

// This parser handles structural XML extraction of trust services from
// TL/LOTL documents. It does NOT verify XML-DSig signatures itself —
// signature verification is the caller's responsibility.
//
// NativeSigningService::configure() uses TlSignatureVerifier (libxml2 C14N +
// OpenSSL EVP) to authenticate each TL before passing it to this parser.
// Pinned signing certificates and LoTL-derived certs provide the trust
// anchors. See tl_signature_verifier.h and pinned_tl_certs.h.
class TrustedListParser
{
public:
    // Parse a TL or LOTL XML document.
    // Returns empty TrustedListInfo on parse failure.
    //
    // Structural extraction only — caller must verify XML-DSig before trusting output.
    static TrustedListInfo parse(const std::vector<uint8_t>& xmlData);
    static TrustedListInfo parse(const std::string& xmlString);

    // Fetch and parse a TL from URL. SECURITY: see warning above.
    TrustedListInfo fetch(const std::string& url, int timeoutSeconds = 30);

    /// Result of a fetchRaw() call with HTTP metadata for caching.
    struct FetchResult
    {
        std::vector<uint8_t> data;
        std::string etag;
        std::string lastModified;
        bool notModified = false; ///< true when server returned 304
    };

    // Fetch raw XML bytes from a URL without parsing.
    // Returns empty vector on failure (HTTP error or empty body).
    static std::vector<uint8_t> fetchRaw(const std::string& url, int timeoutSeconds = 30);

    /// Fetch raw XML bytes with HTTP conditional request support.
    /// If etag/lastModified are non-empty, sends If-None-Match / If-Modified-Since.
    /// On 304, returns FetchResult with notModified=true and empty data.
    static FetchResult fetchRawConditional(const std::string& url, const std::string& etag = {},
                                           const std::string& lastModified = {}, int timeoutSeconds = 30);

    // Fetch LOTL, then fetch each member state TL.
    // Returns all entries from all member state TLs.
    // Structural extraction only — caller must verify XML-DSig before trusting output.
    std::vector<TrustedServiceEntry> fetchLotl(const std::string& lotlUrl, int timeoutSeconds = 30);

    /// SSRF validation for Trusted-List pointers: reject non-HTTPS,
    /// private/loopback IP literals. Thin https-only wrapper over
    /// @ref isSafeFetchUrl.
    static bool isSafeTslUrl(const std::string& url);

    /// Scheme-agnostic SSRF guard shared by the TSL fetch path and the
    /// revocation (CRL/OCSP) fetch path. Validates the URL length, extracts the
    /// host, and rejects loopback / link-local / RFC1918 / ULA / multicast IP
    /// literals (IPv4 and IPv6, including IPv4-mapped). @p allowPlainHttp selects
    /// the accepted scheme set: false = https-only (Trusted Lists); true = http
    /// OR https (RFC 5280 CRL CDPs and OCSP/AIA endpoints are legitimately served
    /// over plain http). DNS names that resolve to private addresses are not
    /// caught here — curl's protocol allow-list + resolution are the last line of
    /// defense; this is defense-in-depth against literal-IP SSRF vectors.
    static bool isSafeFetchUrl(const std::string& url, bool allowPlainHttp);
};

} // namespace libresign
