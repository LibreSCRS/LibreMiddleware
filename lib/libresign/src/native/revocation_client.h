// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

#include <cstdint>
#include <string>
#include <vector>

typedef struct x509_st X509;

namespace libresign {

struct RevocationData
{
    std::vector<std::vector<uint8_t>> crls;          // DER-encoded CRLs
    std::vector<std::vector<uint8_t>> ocspResponses; // DER-encoded OCSP responses
};

class RevocationClient
{
public:
    bool crlEnabled = true;
    bool ocspEnabled = true;

    // Extract CRL Distribution Point URLs from certificate
    static std::vector<std::string> extractCrlUrls(X509* cert);

    // Extract OCSP responder URLs from AIA extension
    static std::vector<std::string> extractOcspUrls(X509* cert);

    // Fetch a CRL from URL and verify its signature against the issuer's
    // public key. Returns DER bytes on success (signature verified), empty on
    // any failure including verification failure.
    //
    // Per ETSI EN 319 102-1 §6, revocation information embedded in long-term
    // signatures (B-LT/B-LTA) MUST be authenticated before being incorporated.
    // Without verification, an attacker controlling the CRL endpoint could
    // inject a "valid" claim for an actually-revoked signing cert.
    std::vector<uint8_t> fetchCrl(const std::string& url, X509* issuer, int timeoutSeconds = 10);

    // Fetch an OCSP response for cert/issuer and verify both that the signature
    // chain validates against `chain` and that the response is for the cert ID
    // we asked about. Returns DER bytes on success, empty on failure.
    //
    // See fetchCrl for the rationale; the same ETSI clause applies.
    std::vector<uint8_t> fetchOcsp(X509* cert, X509* issuer, const std::vector<X509*>& chain,
                                   const std::string& ocspUrl, int timeoutSeconds = 10);

    // Collect all revocation data for a certificate chain.
    // chain[0] = signer cert, chain[1] = intermediate, ..., chain[n] = root
    RevocationData collectForChain(const std::vector<X509*>& chain);
};

} // namespace libresign
