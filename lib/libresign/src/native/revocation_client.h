// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

#include "../types.h" // ChainTermination

#include <cstdint>
#include <ctime>
#include <string>
#include <vector>

typedef struct x509_st X509;
typedef struct X509_crl_st X509_CRL;
typedef struct asn1_string_st ASN1_TIME;

namespace libresign {

struct RevocationData
{
    std::vector<std::vector<uint8_t>> crls;          // DER-encoded CRLs
    std::vector<std::vector<uint8_t>> ocspResponses; // DER-encoded OCSP responses

    // Indices (into the chain passed to collectForChain) of the certs with a
    // known issuer for which NO revocation information could be obtained —
    // neither a signature-verified CRL nor a "good" OCSP response. Empty means
    // every such cert is covered. A long-term signature (B-LT/B-LTA) MUST
    // treat a non-empty value as fail-closed: embedding a chain with
    // unrevocable links produces a signature that cannot reach the LT
    // validation level.
    std::vector<std::size_t> certsWithoutRevocation;

    // The chain has NO proven terminal (deliberately a bare flag, not a cert
    // reference — the empty-chain case has nothing to point at): the caller
    // did not assert a Trusted-List anchor termination and the last element
    // is not a self-verifying self-signed root reached through at least one
    // issuer hop. Revocation evidence for such a tail cannot be
    // signature-verified AT ALL, so a long-term signature MUST fail closed
    // with the chain-incomplete (not fetch-failed) failure.
    bool unverifiableTail = false;
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

    // True iff @p crl lists @p cert (by serial) as revoked. fetchCrl calls this
    // after signature + freshness verification and fails closed when it returns
    // true — symmetric with the OCSP path's V_OCSP_CERTSTATUS_GOOD gate so a CRL
    // that revokes the signer is never embedded as positive evidence. Exposed
    // static for deterministic unit testing (mirrors @ref crlWindowValid).
    static bool crlRevokesCert(X509_CRL* crl, X509* cert);

    // Extract CRL Distribution Point URLs from certificate
    static std::vector<std::string> extractCrlUrls(X509* cert);

    // Extract OCSP responder URLs from AIA extension
    static std::vector<std::string> extractOcspUrls(X509* cert);

    // Fetch a CRL from URL and verify its signature against the issuer's
    // public key, then confirm @p cert is NOT listed as revoked. Returns DER
    // bytes on success (signature verified + freshness OK + cert not revoked),
    // empty on any failure including verification failure or a REVOKED entry.
    //
    // Per ETSI EN 319 102-1 §6, revocation information embedded in long-term
    // signatures (B-LT/B-LTA) MUST be authenticated before being incorporated.
    // Without verification, an attacker controlling the CRL endpoint could
    // inject a "valid" claim for an actually-revoked signing cert. The revoked-
    // serial check keeps this path symmetric with the OCSP path's
    // V_OCSP_CERTSTATUS_GOOD gate — a CRL that revokes the cert must NOT be
    // embedded as positive evidence.
    std::vector<uint8_t> fetchCrl(const std::string& url, X509* cert, X509* issuer, int timeoutSeconds = 10);

    // Fetch an OCSP response for cert/issuer and verify both that the signature
    // chain validates against `chain` and that the response is for the cert ID
    // we asked about. Returns DER bytes on success, empty on failure.
    //
    // See fetchCrl for the rationale; the same ETSI clause applies.
    std::vector<uint8_t> fetchOcsp(X509* cert, X509* issuer, const std::vector<X509*>& chain,
                                   const std::string& ocspUrl, int timeoutSeconds = 10);

    // Collect all revocation data for a certificate chain.
    // chain[0] = signer cert, chain[1] = intermediate, ..., chain[n] = terminal.
    //
    // The LAST element is exempt from evidence collection ONLY when the
    // termination is PROVEN: either @p termination says the caller completed
    // the chain against a Trusted List (AnchorTerminated — assert it only at
    // that proof point), or the last element is a self-signed,
    // self-verifying root reached through at least one issuer hop (a
    // self-signed SIGNER alone never self-exempts). Otherwise the tail —
    // including the whole chain when it is empty or a bare signer — is
    // recorded as RevocationData::unverifiableTail and the long-term caller
    // fails closed with the chain-incomplete failure.
    RevocationData collectForChain(const std::vector<X509*>& chain, ChainTermination termination);
};

} // namespace libresign
