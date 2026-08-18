// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "native/revocation_client.h"
#include "http_client.h"
#include "native/issuer_resolution.h"   // isSelfSignedSelfVerifying — the tail-exemption proof
#include "native/trusted_list_parser.h" // isSafeFetchUrl — shared SSRF host/IP-literal gate
#include "native_utils.h"
#include "openssl_raii.h"

#include <openssl/err.h>
#include <openssl/ocsp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <climits>
#include <memory>

namespace libresign {

namespace {

using namespace libresign::native_utils;

} // namespace

bool RevocationClient::crlWindowValid(const ASN1_TIME* thisUpdate, const ASN1_TIME* nextUpdate, std::time_t now,
                                      long skewSeconds)
{
    // A CRL must carry a thisUpdate; without it the window is undefined.
    if (!thisUpdate)
        return false;

    // thisUpdate must not be in the future: reject if it is later than
    // now + skew. X509_cmp_time returns >0 when the first arg is later than
    // the reference time, <0 when earlier, and 0 on a parse error — treat that
    // error as a reject (fail-closed), matching OCSP_check_validity, rather
    // than letting an unparseable-but-signed time slip through the window.
    std::time_t future = now + skewSeconds;
    int thisCmp = X509_cmp_time(thisUpdate, &future);
    if (thisCmp == 0 || thisCmp > 0)
        return false;

    // nextUpdate, when present, must not have already elapsed: reject if it is
    // earlier than now - skew (or unparseable). A null nextUpdate is accepted —
    // freshness can't be bounded but the CRL is not proven stale (mirrors
    // OCSP_check_validity with an unbounded max-age, which the OCSP path uses).
    if (nextUpdate) {
        std::time_t past = now - skewSeconds;
        int nextCmp = X509_cmp_time(nextUpdate, &past);
        if (nextCmp == 0 || nextCmp < 0)
            return false;
    }

    return true;
}

bool RevocationClient::crlRevokesCert(X509_CRL* crl, X509* cert)
{
    if (!crl || !cert)
        return false;
    // X509_CRL_get0_by_cert returns 1 when a revoked entry matching cert's
    // serial number is present in the CRL (0 = not found, <0 = error).
    X509_REVOKED* rev = nullptr;
    return X509_CRL_get0_by_cert(crl, &rev, cert) == 1;
}

std::vector<std::string> RevocationClient::extractCrlUrls(X509* cert)
{
    std::vector<std::string> urls;
    if (!cert)
        return urls;

    auto* dps =
        static_cast<STACK_OF(DIST_POINT)*>(X509_get_ext_d2i(cert, NID_crl_distribution_points, nullptr, nullptr));
    if (!dps)
        return urls;

    for (int i = 0; i < sk_DIST_POINT_num(dps); ++i) {
        DIST_POINT* dp = sk_DIST_POINT_value(dps, i);
        if (!dp->distpoint || dp->distpoint->type != 0)
            continue;

        GENERAL_NAMES* names = dp->distpoint->name.fullname;
        for (int j = 0; j < sk_GENERAL_NAME_num(names); ++j) {
            GENERAL_NAME* gen = sk_GENERAL_NAME_value(names, j);
            if (gen->type != GEN_URI)
                continue;

            const unsigned char* data = ASN1_STRING_get0_data(gen->d.uniformResourceIdentifier);
            int len = ASN1_STRING_length(gen->d.uniformResourceIdentifier);
            if (data && len > 0)
                urls.emplace_back(reinterpret_cast<const char*>(data), static_cast<size_t>(len));
        }
    }

    sk_DIST_POINT_pop_free(dps, DIST_POINT_free);
    return urls;
}

std::vector<std::string> RevocationClient::extractOcspUrls(X509* cert)
{
    std::vector<std::string> urls;
    if (!cert)
        return urls;

    auto* aia = static_cast<AUTHORITY_INFO_ACCESS*>(X509_get_ext_d2i(cert, NID_info_access, nullptr, nullptr));
    if (!aia)
        return urls;

    for (int i = 0; i < sk_ACCESS_DESCRIPTION_num(aia); ++i) {
        ACCESS_DESCRIPTION* ad = sk_ACCESS_DESCRIPTION_value(aia, i);
        if (OBJ_obj2nid(ad->method) != NID_ad_OCSP)
            continue;

        GENERAL_NAME* loc = ad->location;
        if (!loc || loc->type != GEN_URI)
            continue;

        const unsigned char* data = ASN1_STRING_get0_data(loc->d.uniformResourceIdentifier);
        int len = ASN1_STRING_length(loc->d.uniformResourceIdentifier);
        if (data && len > 0)
            urls.emplace_back(reinterpret_cast<const char*>(data), static_cast<size_t>(len));
    }

    AUTHORITY_INFO_ACCESS_free(aia);
    return urls;
}

std::vector<uint8_t> RevocationClient::fetchCrl(const std::string& url, X509* cert, X509* issuer, int timeoutSeconds)
{
    if (!cert || !issuer)
        return {};

    // SSRF guard: the CRL Distribution Point URL comes from the cert (attacker-
    // influenceable). Reject loopback/link-local/RFC1918/ULA/multicast IP
    // literals before issuing the request — shared with the TSL fetch path.
    // allowPlainHttp=true: RFC 5280 CRL CDPs are legitimately plain http (the
    // CRL is signature-verified below, so transport confidentiality is moot).
    // HttpClient does not auto-follow redirects, so this initial-URL check
    // covers every URL we actually fetch; a 3xx returns non-200 → empty below.
    if (!TrustedListParser::isSafeFetchUrl(url, /*allowPlainHttp=*/true))
        return {};

    HttpClient http;
    auto response = http.get(url, timeoutSeconds);

    if (response.statusCode != 200 || response.body.empty())
        return {};
    if (response.body.size() > static_cast<size_t>(LONG_MAX))
        return {};

    // Parse to validate it's a proper CRL
    const unsigned char* p = reinterpret_cast<const unsigned char*>(response.body.data());
    X509CrlPtr crl(d2i_X509_CRL(nullptr, &p, static_cast<long>(response.body.size())));
    if (!crl)
        return {};

    // Verify CRL signature against the issuer's public key. Without this,
    // an attacker MITM-ing the CRL endpoint could feed us a forged "this
    // cert is not revoked" claim, which would then be embedded into the
    // signed document and trusted by every downstream verifier.
    EVP_PKEY* issuerKey = X509_get0_pubkey(issuer);
    if (!issuerKey || X509_CRL_verify(crl.get(), issuerKey) != 1)
        return {};

    // Reject a stale (or not-yet-valid) CRL: a long-term signature must embed
    // revocation evidence that is fresh at signing time. The OCSP path already
    // enforces this via OCSP_check_validity; mirror it for CRLs with the same
    // 5-minute clock-skew tolerance. An unfresh CRL is treated as "no evidence"
    // (returns empty), which collectForChain records as a fail-closed gap.
    if (!crlWindowValid(X509_CRL_get0_lastUpdate(crl.get()), X509_CRL_get0_nextUpdate(crl.get()), std::time(nullptr),
                        300L))
        return {};

    // Fail closed if THIS cert is listed as revoked. Symmetric with the OCSP
    // path's `certStatus != V_OCSP_CERTSTATUS_GOOD` gate (see fetchOcsp): a CRL
    // that revokes the signer must NOT be embedded as positive "not revoked"
    // evidence. Keep these two paths in lockstep so they cannot drift.
    if (crlRevokesCert(crl.get(), cert))
        return {};

    // Re-encode to canonical DER
    return derEncode(i2d_X509_CRL, crl.get());
}

std::vector<uint8_t> RevocationClient::fetchOcsp(X509* cert, X509* issuer, const std::vector<X509*>& chain,
                                                 const std::string& ocspUrl, int timeoutSeconds)
{
    if (!cert || !issuer)
        return {};

    // SSRF guard: the OCSP responder URL comes from the cert's AIA extension
    // (attacker-influenceable). Same scheme-agnostic host/IP-literal gate as
    // fetchCrl — AIA/OCSP endpoints are also legitimately plain http.
    if (!TrustedListParser::isSafeFetchUrl(ocspUrl, /*allowPlainHttp=*/true))
        return {};

    // 1. Create OCSP request
    OcspReqPtr req(OCSP_REQUEST_new());
    if (!req)
        return {};

    // Create cert ID (OCSP_request_add0_id takes ownership of certId)
    OCSP_CERTID* certId = OCSP_cert_to_id(EVP_sha256(), cert, issuer);
    if (!certId)
        return {};

    if (!OCSP_request_add0_id(req.get(), certId)) {
        OCSP_CERTID_free(certId);
        return {};
    }
    // certId is now owned by req, do not free

    // 2. Encode request to DER
    auto derReqBytes = derEncode(i2d_OCSP_REQUEST, req.get());
    if (derReqBytes.empty())
        return {};
    std::string reqBody(reinterpret_cast<const char*>(derReqBytes.data()), derReqBytes.size());

    // 3. HTTP POST to OCSP responder
    HttpClient http;
    auto response = http.postBinary(ocspUrl, reqBody, "application/ocsp-request", timeoutSeconds);

    if (response.statusCode != 200 || response.body.empty())
        return {};
    if (response.body.size() > static_cast<size_t>(LONG_MAX))
        return {};

    // 4. Parse response
    const unsigned char* respData = reinterpret_cast<const unsigned char*>(response.body.data());
    OcspRespPtr resp(d2i_OCSP_RESPONSE(nullptr, &respData, static_cast<long>(response.body.size())));
    if (!resp)
        return {};

    // Check status
    int status = OCSP_response_status(resp.get());
    if (status != OCSP_RESPONSE_STATUS_SUCCESSFUL)
        return {};

    // 5. Verify the OCSP response signature against the chain. Without
    // verification, an MITM (or compromised responder URL) could feed us a
    // forged "good" status that would then be embedded into the signature
    // and accepted by every downstream verifier.
    OcspBasicPtr basic(OCSP_response_get1_basic(resp.get()));
    if (!basic)
        return {};

    // Only the root cert (last in chain; see collectForChain comment) goes
    // into the trust store. Earlier revisions added every intermediate as a
    // trust anchor, which would accept an OCSP response signed by any
    // intermediate — a MITM with a compromised (or non-OCSPSigning) CA
    // could forge "good" statuses. Intermediates are passed as additional
    // chain-building material via the certs argument.
    X509StorePtr trustStore(X509_STORE_new());
    if (!trustStore)
        return {};
    if (!chain.empty() && chain.back() != nullptr)
        X509_STORE_add_cert(trustStore.get(), chain.back());

    // Non-owning stack: we push borrowed X509* from `chain` (whose lifetime
    // outlives this call). A lambda deleter frees the stack only — the
    // canonical StackX509Deleter would pop_free the X509 contents, which
    // we don't own.
    struct StackFreeOnly
    {
        void operator()(STACK_OF(X509) * p) const
        {
            sk_X509_free(p);
        }
    };
    std::unique_ptr<STACK_OF(X509), StackFreeOnly> extraCerts(sk_X509_new_null());
    if (!extraCerts)
        return {};
    // Include every non-root chain cert (and the signer itself, in case the
    // responder re-uses it) as additional chain-building material.
    for (size_t i = 0; i + 1 < chain.size(); ++i) {
        if (chain[i])
            sk_X509_push(extraCerts.get(), chain[i]);
    }

    if (OCSP_basic_verify(basic.get(), extraCerts.get(), trustStore.get(), 0) != 1)
        return {};

    // 6. Verify the response actually answers OUR question (matches certId).
    // OpenSSL's OCSP_resp_find_status returns success only if the response
    // contains the requested certID.
    int reason = 0;
    ASN1_GENERALIZEDTIME* thisUpdate = nullptr;
    ASN1_GENERALIZEDTIME* nextUpdate = nullptr;
    int certStatus = -1;
    OCSP_CERTID* lookupId = OCSP_cert_to_id(EVP_sha256(), cert, issuer);
    if (!lookupId)
        return {};
    int found = OCSP_resp_find_status(basic.get(), lookupId, &certStatus, &reason, nullptr, &thisUpdate, &nextUpdate);
    OCSP_CERTID_free(lookupId);
    if (found != 1)
        return {};

    // Reject anything but a definitive "good" status. Previously we embedded
    // the OCSP response into the signature regardless of certStatus — a
    // REVOKED status would then be embedded as a "positive attestation",
    // self-documenting proof that the cert was revoked at signing time.
    // UNKNOWN means the responder has no information and is also not a
    // valid attestation for an LT-level signature.
    if (certStatus != V_OCSP_CERTSTATUS_GOOD)
        return {};

    // Validate freshness (thisUpdate must not be in the future, nextUpdate
    // must not be in the past). OCSP_check_validity does both with a tolerance
    // of 5 minutes for clock skew and a max age of "any" (-1).
    if (OCSP_check_validity(thisUpdate, nextUpdate, 300L, -1L) != 1)
        return {};

    // 7. Re-encode to canonical DER
    return derEncode(i2d_OCSP_RESPONSE, resp.get());
}

RevocationData RevocationClient::collectForChain(const std::vector<X509*>& chain, ChainTermination termination)
{
    RevocationData data;

    // A chain with nothing in it has no verifiable tail by definition; the
    // long-term caller must fail closed as chain-incomplete, never pass
    // silently (the on-token query can transiently return nothing while the
    // signer cert itself resolved).
    if (chain.empty()) {
        data.unverifiableTail = true;
        return data;
    }

    // The last element is exempt from evidence collection ONLY when the
    // termination is proven (see the header contract): a Trusted-List anchor
    // asserted by the completer, or a self-verifying self-signed root reached
    // through at least one issuer hop. A self-signed SIGNER alone (length-1)
    // must NOT self-exempt — no evidence for it could ever be verified, and
    // exempting it would recreate the silent length-1 pass this gate exists
    // to close.
    const bool lastExempt = termination == ChainTermination::AnchorTerminated ||
                            (chain.size() >= 2 && native_utils::isSelfSignedSelfVerifying(chain.back()));
    if (!lastExempt)
        data.unverifiableTail = true;

    // Process every cert that has a known issuer (all but the last).
    for (size_t i = 0; i + 1 < chain.size(); ++i) {
        X509* cert = chain[i];
        X509* issuer = chain[i + 1];
        bool gotRevocation = false;

        // Try CRL — verified against issuer's public key inside fetchCrl
        if (crlEnabled) {
            auto crlUrls = extractCrlUrls(cert);
            for (const auto& url : crlUrls) {
                auto crl = fetchCrl(url, cert, issuer);
                if (!crl.empty()) {
                    data.crls.push_back(std::move(crl));
                    gotRevocation = true;
                    break; // one CRL per cert is sufficient
                }
            }
        }

        // Try OCSP — signature verified against the chain inside fetchOcsp
        if (ocspEnabled) {
            auto ocspUrls = extractOcspUrls(cert);
            for (const auto& url : ocspUrls) {
                auto resp = fetchOcsp(cert, issuer, chain, url);
                if (!resp.empty()) {
                    data.ocspResponses.push_back(std::move(resp));
                    gotRevocation = true;
                    break; // one OCSP response per cert is sufficient
                }
            }
        }

        // Record a fail-closed gap: this non-root cert produced no
        // signature-verified revocation evidence (no endpoint, all endpoints
        // unreachable, or every response failed verification/freshness). The
        // B-LT/B-LTA caller turns a non-empty list into RevocationFetchFailed.
        if (!gotRevocation)
            data.certsWithoutRevocation.push_back(i);
    }

    return data;
}

} // namespace libresign
