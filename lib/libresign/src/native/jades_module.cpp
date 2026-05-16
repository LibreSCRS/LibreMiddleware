// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "native/jades_module.h"
#include "native/pkcs11_token.h"
#include "native/revocation_client.h"
#include "native/tsa_client.h"
#include "native_utils.h"

#include <json.hpp>
#include <openssl/bio.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

#include <cstring>
#include <memory>
#include <stdexcept>

namespace libresign {

namespace {

using namespace libresign::native_utils;

// ---- Base64url encoding (RFC 4648 section 5) ----

std::string base64url(const std::vector<uint8_t>& data)
{
    std::string b64 = base64Encode(data);
    // Replace + with -, / with _, strip trailing =
    for (char& c : b64) {
        if (c == '+')
            c = '-';
        else if (c == '/')
            c = '_';
    }
    // Remove padding
    while (!b64.empty() && b64.back() == '=')
        b64.pop_back();
    return b64;
}

std::string base64url(const std::string& str)
{
    return base64url(std::vector<uint8_t>(str.begin(), str.end()));
}

// ---- Determine JWS algorithm from certificate key ----
//
// JWS (RFC 7518 §3.4) defines exactly three ECDSA "alg" values:
//   ES256 → NIST P-256 (secp256r1 / prime256v1)
//   ES384 → NIST P-384 (secp384r1)
//   ES512 → NIST P-521 (secp521r1)
//
// No standard "alg" exists for Brainpool, sect*, or other curves. Signing
// with a non-NIST curve would require inventing a custom alg value that
// conforming JAdES validators (DSS, ETSI test bench, Adobe) will reject —
// so we throw on unknown curves rather than producing a non-interoperable
// signature. CAdES/PAdES/XAdES paths are unaffected (they go through
// OpenSSL CMS / XMLDSig abstractions that handle any curve OpenSSL knows).
std::string jwsAlgorithm(X509* cert)
{
    EVP_PKEY* pkey = X509_get0_pubkey(cert);
    if (!pkey)
        throw std::runtime_error("Cannot extract public key from certificate");

    int keyType = EVP_PKEY_base_id(pkey);
    if (keyType == EVP_PKEY_RSA)
        return "RS256";
    if (keyType == EVP_PKEY_EC) {
        // Determine curve — explicit match for ES256/384/512. Do NOT
        // fall through to "ES256" on unknown curve: a P-384 or P-521 key
        // signed with alg=ES256 produces a raw signature of the wrong
        // length and an invalid JWS. Throw so the caller sees the
        // misconfiguration instead of shipping a broken signature.
        size_t groupLen = 0;
        char groupName[64] = {};
        if (!EVP_PKEY_get_utf8_string_param(pkey, OSSL_PKEY_PARAM_GROUP_NAME, groupName, sizeof(groupName), &groupLen))
            throw std::runtime_error("JAdES: failed to read EC curve name from public key");

        // OpenSSL's OSSL_PKEY_PARAM_GROUP_NAME returns `P-256` for the SECG
        // friendly name or `prime256v1`/`secp256r1` for the canonical names
        // (see obj_mac.h). `prime384v1` and `prime521v1` aliases do NOT
        // exist in OpenSSL — those curves are only `P-384`/`secp384r1` and
        // `P-521`/`secp521r1` respectively. Tested against OpenSSL 3.5.
        std::string curve(groupName, groupLen);
        if (curve == "P-256" || curve == "secp256r1" || curve == "prime256v1")
            return "ES256";
        if (curve == "P-384" || curve == "secp384r1")
            return "ES384";
        if (curve == "P-521" || curve == "secp521r1")
            return "ES512";
        throw std::runtime_error("JAdES: unsupported EC curve '" + curve + "' (expected P-256, P-384, or P-521)");
    }
    throw std::runtime_error("Unsupported key type for JAdES signing");
}

// ---- Build x5c array: base64 DER certs (standard base64, NOT base64url) ----

nlohmann::json buildX5c(Pkcs11Token& token)
{
    auto chain = token.certificateChain();
    nlohmann::json x5c = nlohmann::json::array();
    for (const auto& certDer : chain)
        x5c.push_back(base64Encode(certDer));
    return x5c;
}

// ---- JWS JSON Serialization ----

struct JwsComponents
{
    std::string protectedHeader;      // base64url-encoded
    std::string payload;              // base64url-encoded (or empty for detached)
    std::string signature;            // base64url-encoded
    nlohmann::json unprotectedHeader; // optional, for etsiU
};

std::string serializeJws(const JwsComponents& jws)
{
    nlohmann::json j;
    // Per RFC 7797 §4.2 and RFC 7515 §7.2, the JWS JSON Serialization
    // "payload" field MUST be omitted (not present-but-empty) when the
    // signed content is detached. Strict JAdES validators (DSS, ETSI
    // test bench) reject empty-string payloads on detached signatures.
    if (!jws.payload.empty())
        j["payload"] = jws.payload;

    nlohmann::json sig;
    sig["protected"] = jws.protectedHeader;
    sig["signature"] = jws.signature;

    if (!jws.unprotectedHeader.empty())
        sig["header"] = jws.unprotectedHeader;

    j["signatures"] = nlohmann::json::array({sig});
    return j.dump();
}

} // namespace

// ---- JAdESModule::sign ----

SigningResult JAdESModule::sign(const std::vector<uint8_t>& data, const std::string& /*fileName*/, Pkcs11Token& token,
                                SignatureLevel level, SignaturePackaging packaging, const TSAConfig& tsa)
{
    if (data.empty())
        return {false, {}, "Input data is empty"};

    try {
        // 1. Get certificate and determine algorithm
        auto certDer = token.certificate();
        if (certDer.empty())
            return {false, {}, "No certificate found on token"};

        X509Ptr cert = parseCert(certDer);
        std::string alg = jwsAlgorithm(cert.get());
        bool isDetached = (packaging == SignaturePackaging::DETACHED);

        // 2. Build protected header
        nlohmann::json header;
        header["alg"] = alg;
        header["x5c"] = buildX5c(token);
        header["sigT"] = iso8601Now();

        if (isDetached) {
            header["b64"] = false;
            header["crit"] = nlohmann::json::array({"sigT", "b64"});
        } else {
            header["crit"] = nlohmann::json::array({"sigT"});
        }

        std::string headerJson = header.dump();
        std::string protectedB64 = base64url(headerJson);

        // 3. Build payload
        std::string payloadB64;
        if (isDetached) {
            // RFC 7797 / ETSI: b64=false means payload is NOT base64url-encoded
            // in the signing input, and empty in serialization
            payloadB64 = "";
        } else {
            payloadB64 = base64url(data);
        }

        // 4. Compute signing input
        //    For detached with b64=false: base64url(header) + "." + raw_payload_octets
        //    For enveloped: base64url(header) + "." + base64url(payload)
        std::string signingInput;
        if (isDetached) {
            signingInput = protectedB64 + ".";
            signingInput.append(reinterpret_cast<const char*>(data.data()), data.size());
        } else {
            signingInput = protectedB64 + "." + payloadB64;
        }

        // 5. Hash the signing input with the algorithm matching the JWS "alg"
        //    (RFC 7518 §3.4: ES256→SHA-256, ES384→SHA-384, ES512→SHA-512)
        std::vector<uint8_t> inputHash;
        std::string hashAlgo;
        if (alg == "ES384") {
            inputHash = sha384(signingInput);
            hashAlgo = "SHA384";
        } else if (alg == "ES512") {
            inputHash = sha512(signingInput);
            hashAlgo = "SHA512";
        } else {
            inputHash = sha256(signingInput);
            hashAlgo = "SHA256";
        }

        // 6. Sign. Pass the JWS signing input as raw "to-be-signed" bytes so
        //    hash-on-card SSCDs can use the combined CKM_SHA*_RSA_PKCS
        //    mechanism; legacy cards fall through to the pre-built DigestInfo
        //    path inside Pkcs11Token.
        const std::span<const uint8_t> signingInputSpan{reinterpret_cast<const uint8_t*>(signingInput.data()),
                                                        signingInput.size()};
        auto signatureBytes = signHashWithToken(token, cert.get(), inputHash, hashAlgo, signingInputSpan);

        if (signatureBytes.empty())
            return {false, {}, "PKCS#11 token signing returned empty signature"};

        // 7. Build JWS JSON Serialization (B-B)
        JwsComponents jws;
        jws.protectedHeader = protectedB64;
        jws.payload = payloadB64;
        jws.signature = base64url(signatureBytes);

        // 8. B-T: add signature timestamp
        if (level >= SignatureLevel::B_T) {
            if (tsa.url.empty())
                return {false, {}, "TSA URL is required for B-T level or above"};

            // Per ETSI TS 119 182-1 §5.1.10, the sigTst message imprint is
            // computed over the base64url-encoded JWS signature value as
            // ASCII octets — NOT the raw decoded signature bytes. We
            // already have `jws.signature` set to base64url(signatureBytes)
            // above; hash those octets.
            auto sigHash = sha256(reinterpret_cast<const uint8_t*>(jws.signature.data()), jws.signature.size());

            TSAClient tsaClient;
            auto tsaResult = tsaClient.timestamp(sigHash, toTsaRequest(tsa));
            if (!tsaResult.success)
                return {false, {}, "TSA timestamp failed: " + tsaResult.errorMessage};

            // Build etsiU with sigTst
            nlohmann::json sigTst;
            sigTst["sigTst"]["tstTokens"] = nlohmann::json::array({{{"val", base64Encode(tsaResult.token)}}});

            nlohmann::json etsiU = nlohmann::json::array({sigTst});
            jws.unprotectedHeader["etsiU"] = etsiU;
        }

        // 9. B-LT: add revocation data
        if (level >= SignatureLevel::B_LT) {
            auto revData = collectRevocationData(token, tsa);

            nlohmann::json rVals;
            if (!revData.crls.empty()) {
                nlohmann::json crlVals = nlohmann::json::array();
                for (const auto& crl : revData.crls)
                    crlVals.push_back(base64Encode(crl));
                rVals["crlVals"] = crlVals;
            }
            if (!revData.ocspResponses.empty()) {
                nlohmann::json ocspVals = nlohmann::json::array();
                for (const auto& ocsp : revData.ocspResponses)
                    ocspVals.push_back(base64Encode(ocsp));
                rVals["ocspVals"] = ocspVals;
            }

            if (!rVals.empty()) {
                nlohmann::json rValsEntry;
                rValsEntry["rVals"] = rVals;

                if (!jws.unprotectedHeader.contains("etsiU"))
                    jws.unprotectedHeader["etsiU"] = nlohmann::json::array();
                jws.unprotectedHeader["etsiU"].push_back(rValsEntry);
            }
        }

        // 10. B-LTA: add archive timestamp per ETSI TS 119 182-1 §5.3.5
        if (level >= SignatureLevel::B_LTA) {
            // The arcTst message imprint is computed over:
            //   base64url(protected) + "." + base64url(payload) + "." + base64url(signature)
            //   + canonicalized (JSON-sorted) etsiU components
            std::string archiveInput = jws.protectedHeader + "." + jws.payload + "." + jws.signature;

            // Append each existing etsiU component as canonicalized JSON
            // (sorted keys, no whitespace — nlohmann::json::dump() default)
            if (jws.unprotectedHeader.contains("etsiU")) {
                for (const auto& entry : jws.unprotectedHeader["etsiU"]) {
                    // Canonicalize: dump with sorted keys
                    archiveInput += entry.dump(-1, ' ', false, nlohmann::json::error_handler_t::strict);
                }
            }

            auto archiveHash = sha256(archiveInput);

            TSAClient tsaClient;
            auto tsaResult = tsaClient.timestamp(archiveHash, toTsaRequest(tsa));
            if (!tsaResult.success)
                return {false, {}, "Archive TSA timestamp failed: " + tsaResult.errorMessage};

            nlohmann::json arcTst;
            arcTst["arcTst"]["tstTokens"] = nlohmann::json::array({{{"val", base64Encode(tsaResult.token)}}});

            if (!jws.unprotectedHeader.contains("etsiU"))
                jws.unprotectedHeader["etsiU"] = nlohmann::json::array();
            jws.unprotectedHeader["etsiU"].push_back(arcTst);
        }

        // 11. Final serialization
        std::string result = serializeJws(jws);
        return {true, std::vector<uint8_t>(result.begin(), result.end()), {}};

    } catch (const std::exception& e) {
        return {false, {}, std::string("JAdES error: ") + e.what()};
    }
}

} // namespace libresign
