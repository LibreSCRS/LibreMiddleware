// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

#include <cstdint>
#include <ctime>
#include <string>
#include <vector>

typedef struct x509_st X509;
typedef struct asn1_string_st ASN1_TIME;

namespace libresign {

struct RevocationData
{
    std::vector<std::vector<uint8_t>> crls;          // DER-encoded CRLs
    std::vector<std::vector<uint8_t>> ocspResponses; // DER-encoded OCSP responses

    // Indices (into the chain passed to collectForChain) of the non-root certs
    // for which NO revocation information could be obtained — neither a
    // signature-verified CRL nor a "good" OCSP response. Empty means every
    // non-root cert is covered. A long-term signature (B-LT/B-LTA) MUST treat a
    // non-empty value as fail-closed: embedding a chain with unrevocable links
    // produces a signature that cannot reach the LT validation level.
    std::vector<std::size_t> certsWithoutRevocation;
};

class RevocationClient
{
public:
    bool crlEnabled = true;
    bool ocspEnabled = true;

    // True iff a CRL's validity window is currently usable for embedding in a
    // long-term signature: @p thisUpdate is not in the future and, when
    // present, @p nextUpdate has not already elapsed — both within @p
    // skewSeconds of @p now to tolerate clock skew. A null @p nextUpdate is
    // accepted (freshness cannot be bounded but is not proven stale), mirroring
    // OCSP_check_validity with an unbounded max-age. A null @p thisUpdate is
    // rejected. @p now/@p skewSeconds are explicit for deterministic testing.
    static bool crlWindowValid(const ASN1_TIME* thisUpdate, const ASN1_TIME* nextUpdate, std::time_t now,
                               long skewSeconds);

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
