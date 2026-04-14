// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "libresign/native/revocation_client.h"
#include "libresign/http_client.h"
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

std::vector<uint8_t> RevocationClient::fetchCrl(const std::string& url, X509* issuer, int timeoutSeconds)
{
    if (!issuer)
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

    // Re-encode to canonical DER
    return derEncode(i2d_X509_CRL, crl.get());
}

std::vector<uint8_t> RevocationClient::fetchOcsp(X509* cert, X509* issuer, const std::vector<X509*>& chain,
                                                 const std::string& ocspUrl, int timeoutSeconds)
{
    if (!cert || !issuer)
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
    struct StackFreeOnly {
        void operator()(STACK_OF(X509)* p) const { sk_X509_free(p); }
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

RevocationData RevocationClient::collectForChain(const std::vector<X509*>& chain)
{
    RevocationData data;

    // Process every cert except the root (last in chain)
    for (size_t i = 0; i + 1 < chain.size(); ++i) {
        X509* cert = chain[i];
        X509* issuer = chain[i + 1];

        // Try CRL — verified against issuer's public key inside fetchCrl
        auto crlUrls = extractCrlUrls(cert);
        for (const auto& url : crlUrls) {
            auto crl = fetchCrl(url, issuer);
            if (!crl.empty()) {
                data.crls.push_back(std::move(crl));
                break; // one CRL per cert is sufficient
            }
        }

        // Try OCSP — signature verified against the chain inside fetchOcsp
        auto ocspUrls = extractOcspUrls(cert);
        for (const auto& url : ocspUrls) {
            auto resp = fetchOcsp(cert, issuer, chain, url);
            if (!resp.empty()) {
                data.ocspResponses.push_back(std::move(resp));
                break; // one OCSP response per cert is sufficient
            }
        }
    }

    return data;
}

} // namespace libresign
