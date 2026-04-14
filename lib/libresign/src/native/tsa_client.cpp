// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "libresign/native/tsa_client.h"
#include "libresign/http_client.h"
#include "native_utils.h"

#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ts.h>

#include <climits>
#include <cstring>
#include <memory>

namespace libresign {

namespace {

using namespace libresign::native_utils;

using ::libresign::ASN1IntPtr;
using ::libresign::BNPtr;
using ::libresign::TSReqPtr;
using ::libresign::TSRespPtr;

} // namespace

TSAResult TSAClient::timestamp(const std::vector<uint8_t>& hash, const std::string& tsaUrl, int timeoutSeconds)
{
    TSAResult result;

    if (hash.size() != 32) {
        result.errorMessage = "TSA request requires a 32-byte SHA-256 hash";
        return result;
    }

    // 1. Create TS_REQ
    TSReqPtr req(TS_REQ_new());
    if (!req) {
        result.errorMessage = "TS_REQ_new() failed: " + opensslError();
        return result;
    }

    if (!TS_REQ_set_version(req.get(), 1)) {
        result.errorMessage = "TS_REQ_set_version() failed: " + opensslError();
        return result;
    }

    TS_REQ_set_cert_req(req.get(), 1);

    // 2. Create message imprint with SHA-256 algorithm and the hash
    TS_MSG_IMPRINT* imprint = TS_MSG_IMPRINT_new();
    if (!imprint) {
        result.errorMessage = "TS_MSG_IMPRINT_new() failed: " + opensslError();
        return result;
    }

    // Set algorithm to SHA-256
    X509_ALGOR* algo = X509_ALGOR_new();
    if (!algo) {
        TS_MSG_IMPRINT_free(imprint);
        result.errorMessage = "X509_ALGOR_new() failed: " + opensslError();
        return result;
    }
    X509_ALGOR_set0(algo, OBJ_nid2obj(NID_sha256), V_ASN1_NULL, nullptr);

    if (!TS_MSG_IMPRINT_set_algo(imprint, algo)) {
        X509_ALGOR_free(algo);
        TS_MSG_IMPRINT_free(imprint);
        result.errorMessage = "TS_MSG_IMPRINT_set_algo() failed: " + opensslError();
        return result;
    }
    X509_ALGOR_free(algo); // set_algo copies it

    if (!TS_MSG_IMPRINT_set_msg(imprint, const_cast<unsigned char*>(hash.data()), static_cast<int>(hash.size()))) {
        TS_MSG_IMPRINT_free(imprint);
        result.errorMessage = "TS_MSG_IMPRINT_set_msg() failed: " + opensslError();
        return result;
    }

    // TS_REQ_set_msg_imprint duplicates the imprint internally
    if (!TS_REQ_set_msg_imprint(req.get(), imprint)) {
        TS_MSG_IMPRINT_free(imprint);
        result.errorMessage = "TS_REQ_set_msg_imprint() failed: " + opensslError();
        return result;
    }
    TS_MSG_IMPRINT_free(imprint);

    // 3. Set random nonce (64-bit)
    unsigned char nonceBytes[8];
    if (RAND_bytes(nonceBytes, sizeof(nonceBytes)) != 1) {
        result.errorMessage = "RAND_bytes() failed: " + opensslError();
        return result;
    }

    BNPtr bn(BN_bin2bn(nonceBytes, sizeof(nonceBytes), nullptr));
    if (!bn) {
        result.errorMessage = "BN_bin2bn() failed: " + opensslError();
        return result;
    }

    ASN1IntPtr nonce(BN_to_ASN1_INTEGER(bn.get(), nullptr));
    if (!nonce) {
        result.errorMessage = "BN_to_ASN1_INTEGER() failed: " + opensslError();
        return result;
    }

    if (!TS_REQ_set_nonce(req.get(), nonce.get())) {
        result.errorMessage = "TS_REQ_set_nonce() failed: " + opensslError();
        return result;
    }

    // 4. Encode request to DER
    auto derReqBytes = derEncode(i2d_TS_REQ, req.get());
    if (derReqBytes.empty()) {
        result.errorMessage = "i2d_TS_REQ() failed: " + opensslError();
        return result;
    }
    std::string reqBody(reinterpret_cast<const char*>(derReqBytes.data()), derReqBytes.size());

    // 5. HTTP POST to TSA
    HttpClient http;
    auto response = http.postBinary(tsaUrl, reqBody, "application/timestamp-query", timeoutSeconds);

    if (response.statusCode != 200) {
        result.errorMessage =
            "TSA HTTP request failed (status " + std::to_string(response.statusCode) + "): " + response.errorMessage;
        return result;
    }

    // 6. Parse TS_RESP
    if (response.body.size() > static_cast<size_t>(LONG_MAX)) {
        result.errorMessage = "TSA response too large";
        return result;
    }
    const unsigned char* respData = reinterpret_cast<const unsigned char*>(response.body.data());
    TSRespPtr resp(d2i_TS_RESP(nullptr, &respData, static_cast<long>(response.body.size())));
    if (!resp) {
        result.errorMessage = "d2i_TS_RESP() failed: " + opensslError();
        return result;
    }

    // Check status
    TS_STATUS_INFO* statusInfo = TS_RESP_get_status_info(resp.get());
    long status = ASN1_INTEGER_get(TS_STATUS_INFO_get0_status(statusInfo));
    if (status != 0 && status != 1) { // 0=granted, 1=grantedWithMods
        result.errorMessage = "TSA returned non-success status: " + std::to_string(status);
        return result;
    }

    // 7. Verify nonce matches (RFC 3161 §2.4.2 replay protection):
    //    the response MUST echo the nonce we sent, otherwise this could be
    //    a replayed token from an earlier exchange.
    TS_TST_INFO* tstInfo = TS_RESP_get_tst_info(resp.get());
    if (!tstInfo) {
        result.errorMessage = "TS_RESP_get_tst_info() returned null: " + opensslError();
        return result;
    }
    const ASN1_INTEGER* respNonce = TS_TST_INFO_get_nonce(tstInfo);
    if (!respNonce || ASN1_INTEGER_cmp(respNonce, nonce.get()) != 0) {
        result.errorMessage = "TSA nonce mismatch (possible replay attack)";
        return result;
    }

    // Verify the response's message imprint matches what we asked to be
    // timestamped. Nonce echo alone prevents replay of old tokens, but a
    // malicious/buggy TSA could still return a valid token over a
    // different hash — we'd embed it as a proof of timestamp for content
    // we never sent. RFC 3161 §2.4.2 requires this check.
    TS_MSG_IMPRINT* respImprint = TS_TST_INFO_get_msg_imprint(tstInfo);
    if (!respImprint) {
        result.errorMessage = "TS_TST_INFO has no message imprint";
        return result;
    }
    // Verify the response's hash algorithm matches what we requested.
    // The byte-length check below catches a swap to a different hash size
    // (SHA-1/SHA-512), but an equal-length algorithm would slip through —
    // so pin the OID explicitly. We always request SHA-256.
    X509_ALGOR* respAlgo = TS_MSG_IMPRINT_get_algo(respImprint);
    if (!respAlgo || !respAlgo->algorithm || OBJ_obj2nid(respAlgo->algorithm) != NID_sha256) {
        result.errorMessage = "TSA response uses a different hash algorithm than requested";
        return result;
    }
    ASN1_OCTET_STRING* respMsg = TS_MSG_IMPRINT_get_msg(respImprint);
    if (!respMsg || respMsg->length != static_cast<int>(hash.size()) ||
        std::memcmp(respMsg->data, hash.data(), hash.size()) != 0) {
        result.errorMessage = "TSA message imprint does not match request (token is for a different hash)";
        return result;
    }

    // 8. Extract token (internal pointer, do not free)
    PKCS7* token = TS_RESP_get_token(resp.get());
    if (!token) {
        result.errorMessage = "TS_RESP_get_token() returned null: " + opensslError();
        return result;
    }

    // Encode token to DER
    result.token = derEncode(i2d_PKCS7, token);
    if (result.token.empty()) {
        result.errorMessage = "i2d_PKCS7() failed: " + opensslError();
        return result;
    }
    result.success = true;

    return result;
}

} // namespace libresign
