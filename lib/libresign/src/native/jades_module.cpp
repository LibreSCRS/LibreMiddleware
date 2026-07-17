// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "native/jades_module.h"
#include "native/jcs.h"
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
#include <ctime>
#include <memory>
#include <optional>
#include <stdexcept>

namespace libresign {

namespace {

using namespace libresign::native_utils;
// Resolve base64urlEncode/base64urlDecode to the shared native_utils
// implementations without prefixing every call site.
using libresign::native_utils::base64urlDecode;
using libresign::native_utils::base64urlEncode;

// ---- Detect a JAdES JWS JSON General Serialization input ----
//
// Returns a parsed nlohmann::json if @p data is well-formed JSON with the
// minimum JWS JSON General Serialization shape — top-level object carrying
// a non-empty "signatures" array whose entries have "protected" and
// "signature" string fields (RFC 7515 §7.2.1). nullopt otherwise. This is
// the gate used to switch to parallel-sequential multi-sign mode.
//
// DoS hardening: input size capped at kMaxJwsInputBytes to bound peak
// memory before nlohmann::json::parse runs; structural depth capped via
// parser_callback_t at kMaxJsonDepth so a `[[[[…]]]]` payload cannot
// overflow the parse stack. The depth cap is intentionally permissive
// (1024) — legitimate JAdES B-LTA documents nest etsiU arrays a few
// levels deep at most; 1024 is several orders of magnitude beyond.
inline constexpr size_t kMaxJwsInputBytes = 64ULL * 1024 * 1024; // 64 MiB
inline constexpr int kMaxJsonDepth = 1024;

std::optional<nlohmann::json> tryParseJwsGeneral(const std::vector<uint8_t>& data)
{
    if (data.empty() || data.front() != '{' || data.size() > kMaxJwsInputBytes)
        return std::nullopt;
    nlohmann::json j;
    int maxObservedDepth = 0;
    auto cb = [&maxObservedDepth](int depth, nlohmann::json::parse_event_t /*event*/,
                                  nlohmann::json& /*parsed*/) -> bool {
        if (depth > maxObservedDepth)
            maxObservedDepth = depth;
        return depth <= kMaxJsonDepth;
    };
    try {
        j = nlohmann::json::parse(data.begin(), data.end(), cb);
    } catch (const nlohmann::json::exception&) {
        return std::nullopt;
    }
    if (maxObservedDepth > kMaxJsonDepth)
        return std::nullopt;
    if (!j.is_object() || !j.contains("signatures") || !j["signatures"].is_array() || j["signatures"].empty())
        return std::nullopt;
    for (const auto& s : j["signatures"]) {
        if (!s.is_object() || !s.contains("protected") || !s["protected"].is_string() || !s.contains("signature") ||
            !s["signature"].is_string())
            return std::nullopt;
    }
    return j;
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

// ---- Core B-B JWS construction (one signer over @p payload) ----
//
// Factored from JAdESModule::sign() so that the multi-signer entry point
// (appendSigner — DETACHED branch) can build a fresh JWS entry over the
// same detached payload without recursing through the prior-JWS detection
// in sign(). Returns `JwsComponents` populated with the new signer's
// protected header (base64url), payload (base64url for ENVELOPED, empty
// for DETACHED), and signature (base64url). Throws std::runtime_error on
// PKCS#11 / certificate / curve failures; callers wrap in try/catch and
// convert to SigningResult.
JwsComponents buildJwsBB(const std::vector<uint8_t>& payload, bool isDetached, Pkcs11Token& token)
{
    auto certDer = token.certificate();
    if (certDer.empty())
        throw std::runtime_error("No certificate found on token");

    X509Ptr cert = parseCert(certDer);
    std::string alg = jwsAlgorithm(cert.get());

    nlohmann::json header;
    header["alg"] = alg;
    header["x5c"] = buildX5c(token);
    // ETSI TS 119 182-1 §5.2.2 — the signing-certificate reference MUST
    // be present in the protected header (either x5t#S256 or sigX5ts) for
    // a JAdES baseline signature. DSS classifies signatures without it
    // as JSON_NOT_ETSI even when x5c carries the same cert; emit the
    // base64url-encoded SHA-256 of the signer cert DER alongside x5c so
    // strict validators promote the signature to JAdES_BASELINE_B.
    auto signerCertHash = sha256(certDer);
    header["x5t#S256"] = base64urlEncode(signerCertHash);

    // ETSI TS 119 182-1 (v1.2.1 2024-07) replaces the previous sigT
    // claimed-signing-time header with the RFC 7519 iat (Issued At)
    // numeric date claim. DSS 6.4 dropped sigT support after
    // 2025-05-15 — emitting sigT classifies the signature as
    // JSON_NOT_ETSI. iat is a registered JWS Claim Name, so it does
    // not need to appear in the crit array.
    header["iat"] = static_cast<int64_t>(std::time(nullptr));

    if (isDetached) {
        header["b64"] = false;
        header["crit"] = nlohmann::json::array({"b64"});
    }

    std::string headerJson = header.dump();
    std::string protectedB64 = base64urlEncode(headerJson);

    // RFC 7797: detached b64=false MUST omit the payload field in serialization;
    // ENVELOPED encodes the payload as base64url.
    std::string payloadB64 = isDetached ? std::string{} : base64urlEncode(payload);

    // Signing input per RFC 7797:
    //   ENVELOPED (b64=true):  base64urlEncode(header) + "." + base64urlEncode(payload)
    //   DETACHED  (b64=false): base64urlEncode(header) + "." + raw_payload_octets
    std::string signingInput;
    if (isDetached) {
        signingInput = protectedB64 + ".";
        signingInput.append(reinterpret_cast<const char*>(payload.data()), payload.size());
    } else {
        signingInput = protectedB64 + "." + payloadB64;
    }

    // Hash with the algorithm matching the JWS "alg" (RFC 7518 §3.4).
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

    // Pass raw to-be-signed bytes so hash-on-card SSCDs can use the combined
    // CKM_SHA*_RSA_PKCS mechanism; legacy cards fall through to the pre-built
    // DigestInfo path inside Pkcs11Token.
    const std::span<const uint8_t> signingInputSpan{reinterpret_cast<const uint8_t*>(signingInput.data()),
                                                    signingInput.size()};
    auto signatureBytes = signHashWithToken(token, cert.get(), inputHash, hashAlgo, signingInputSpan);
    if (signatureBytes.empty())
        throw std::runtime_error("PKCS#11 token signing returned empty signature");

    JwsComponents jws;
    jws.protectedHeader = protectedB64;
    jws.payload = payloadB64;
    jws.signature = base64urlEncode(signatureBytes);
    return jws;
}

} // namespace

// ---- JAdESModule::sign ----

SigningResult JAdESModule::sign(const std::vector<uint8_t>& data, const std::string& fileName, Pkcs11Token& token,
                                SignatureLevel level, SignaturePackaging packaging, const TSAConfig& tsa)
{
    if (data.empty())
        return makeFailure(SignFailureKind::InvalidDocument, "Input data is empty");

    try {
        // ---- Multi-sign branch (ETSI TS 119 182-1 / RFC 7515 §3.2) ----
        //
        // Inputs already shaped as a JWS JSON General Serialization are treated
        // as parallel-sequential signature requests: extract the prior payload,
        // mint a fresh signature over THAT payload, and append it to the
        // existing "signatures" array so the resulting JSON carries every
        // signer.
        //
        // Two prior-shape sub-cases:
        //
        //   (a) payload present + non-empty  → ENVELOPED prior signature.
        //       Recover the original from the payload field, recurse to
        //       sign that same bytes, lift the new signatures[0] entry
        //       into the prior document.
        //
        //   (b) payload absent (RFC 7797 §4.2 detached form) or empty
        //       → DETACHED prior signature. The original document is not
        //       inside the JWS so we cannot recover it from `data` alone
        //       — error explicitly rather than fall through to fresh-sign
        //       (which would silently produce a single-signer JWS over the
        //       prior JSON bytes, erasing the prior signer's meaning).
        //       A DETACHED-multi-sign API that supplies the original
        //       alongside the prior signature is not exposed in this
        //       release; see the public re-sign documentation for status.
        //
        // Recursion depth: bounded at 1 via a thread_local counter. The
        // inner sign() call is invoked with the decoded payload, which in
        // theory could itself be a JWS-shaped JSON (a previously-signed
        // document re-signed as if it were source content). Without the
        // cap, an attacker could craft an N-level nested JWS that triggers
        // N PKCS#11 sign operations + N TSA round-trips on a single
        // user-PIN consent — a wedge for HSM signing quota abuse or paid
        // TSA over-billing.
        static thread_local int multiSignDepth = 0;
        struct DepthGuard
        {
            int& d;
            DepthGuard(int& d) : d(d)
            {
                ++d;
            }
            ~DepthGuard()
            {
                --d;
            }
        };
        if (auto prior = tryParseJwsGeneral(data); prior.has_value()) {
            if (multiSignDepth >= 1) {
                return makeFailure(SignFailureKind::PolicyViolation,
                                   "JAdES multi-sign: recursive depth exceeded (prior payload is itself a JWS — "
                                   "refusing to recurse to bound HSM sign quota and TSA round-trips)");
            }
            const bool hasPayload = prior->contains("payload") && (*prior)["payload"].is_string() &&
                                    !(*prior)["payload"].get<std::string>().empty();
            if (!hasPayload) {
                return makeFailure(SignFailureKind::InvalidDocument,
                                   "JAdES DETACHED multi-sign cannot recover the original document from the prior "
                                   "JWS (RFC 7797 §4.2 detached form omits the payload field). Pass the original "
                                   "alongside the prior signature via SigningService::appendSigner (4.2 API), or "
                                   "re-sign the original document separately as a fresh single-signer JWS.");
            }
            std::string priorPayloadB64 = (*prior)["payload"].get<std::string>();
            std::vector<uint8_t> priorPayload = base64urlDecode(priorPayloadB64);
            if (priorPayload.empty())
                return makeFailure(SignFailureKind::InvalidDocument,
                                   "JAdES multi-sign: failed to decode prior payload (invalid base64url)");

            DepthGuard guard(multiSignDepth);
            // Recurse with the recovered payload as ENVELOPED. The inner call
            // emits a self-contained single-signer JWS over the same payload;
            // lift its sole signatures[0] entry into the prior document.
            SigningResult inner = sign(priorPayload, fileName, token, level, SignaturePackaging::Enveloped, tsa);
            if (!inner.success)
                return inner;
            nlohmann::json newJws;
            try {
                newJws = nlohmann::json::parse(inner.signedDocument.begin(), inner.signedDocument.end());
            } catch (const nlohmann::json::exception& e) {
                return makeFailure(SignFailureKind::JsonSerializationError,
                                   std::string("JAdES multi-sign: inner sign output is not valid JSON: ") + e.what());
            }
            if (!newJws.contains("signatures") || !newJws["signatures"].is_array() || newJws["signatures"].empty())
                return makeFailure(SignFailureKind::JsonSerializationError,
                                   "JAdES multi-sign: inner sign output lacks signatures[]");
            (*prior)["signatures"].push_back(newJws["signatures"][0]);
            std::string out = prior->dump();
            return makeSuccess(std::vector<uint8_t>(out.begin(), out.end()));
        }

        // 1. B-B JWS construction (cert load, algorithm, protected header,
        //    signing input, PKCS#11 sign). Factored into buildJwsBB so the
        //    DETACHED appendSigner branch can reuse the exact same primitive
        //    without recursing through the prior-JWS detection above.
        bool isDetached = (packaging == SignaturePackaging::Detached);
        JwsComponents jws = buildJwsBB(data, isDetached, token);

        // 2. B-T: add signature timestamp
        if (level >= SignatureLevel::B_T) {
            if (tsa.url.empty())
                return makeFailure(SignFailureKind::InvalidInput, "TSA URL is required for B-T level or above");

            // Per ETSI TS 119 182-1 §5.1.10, the sigTst message imprint is
            // computed over the base64url-encoded JWS signature value as
            // ASCII octets — NOT the raw decoded signature bytes. We
            // already have `jws.signature` set to base64urlEncode(signatureBytes)
            // above; hash those octets.
            auto sigHash = sha256(reinterpret_cast<const uint8_t*>(jws.signature.data()), jws.signature.size());

            TSAClient tsaClient;
            auto tsaResult = tsaClient.timestamp(sigHash, toTsaRequest(tsa));
            if (!tsaResult.success)
                return makeFailure(SignFailureKind::TsaUnreachable, "TSA timestamp failed: " + tsaResult.errorMessage);

            // Build etsiU with sigTst
            nlohmann::json sigTst;
            sigTst["sigTst"]["tstTokens"] = nlohmann::json::array({{{"val", base64Encode(tsaResult.token)}}});

            nlohmann::json etsiU = nlohmann::json::array({sigTst});
            jws.unprotectedHeader["etsiU"] = etsiU;
        }

        // 3. B-LT: add revocation data
        if (level >= SignatureLevel::B_LT) {
            auto revData = collectRevocationData(token, tsa);
            if (auto failure = revocationFailClosed(revData))
                return *failure;

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

        // 4. B-LTA: add archive timestamp per ETSI TS 119 182-1 §5.3.5
        if (level >= SignatureLevel::B_LTA) {
            // The arcTst message imprint is computed over:
            //   base64urlEncode(protected) + "." + base64urlEncode(payload) + "." + base64urlEncode(signature)
            //   + canonicalized (JSON-sorted) etsiU components
            std::string archiveInput = jws.protectedHeader + "." + jws.payload + "." + jws.signature;

            // Append each existing etsiU component as RFC 8785 (JCS)
            // canonical JSON so strict validators that recompute the
            // arcTst imprint over JCS-canonical etsiU members agree.
            if (jws.unprotectedHeader.contains("etsiU")) {
                for (const auto& entry : jws.unprotectedHeader["etsiU"]) {
                    archiveInput += jcsDump(entry);
                }
            }

            auto archiveHash = sha256(archiveInput);

            TSAClient tsaClient;
            auto tsaResult = tsaClient.timestamp(archiveHash, toTsaRequest(tsa));
            if (!tsaResult.success)
                return makeFailure(SignFailureKind::TsaUnreachable,
                                   "Archive TSA timestamp failed: " + tsaResult.errorMessage);

            nlohmann::json arcTst;
            arcTst["arcTst"]["tstTokens"] = nlohmann::json::array({{{"val", base64Encode(tsaResult.token)}}});

            if (!jws.unprotectedHeader.contains("etsiU"))
                jws.unprotectedHeader["etsiU"] = nlohmann::json::array();
            jws.unprotectedHeader["etsiU"].push_back(arcTst);
        }

        // 5. Final serialization
        std::string result = serializeJws(jws);
        return makeSuccess(std::vector<uint8_t>(result.begin(), result.end()));

    } catch (const std::exception& e) {
        return makeFailure(SignFailureKind::EngineError, std::string("JAdES error: ") + e.what());
    }
}

// ---- JAdESModule::appendSigner ----

SigningResult JAdESModule::appendSigner(std::span<const uint8_t> prior, std::span<const uint8_t> originalDoc,
                                        const std::string& fileName, Pkcs11Token& token, SignatureLevel level,
                                        const TSAConfig& tsa)
{
    (void)fileName; // JAdES does not carry a per-signer file name in B-B
    (void)tsa;      // B-T+ gated below; tsa unused at B-B
    if (prior.empty())
        return makeFailure(SignFailureKind::InvalidDocument, "JAdES appendSigner: empty prior");

    // Per-signer etsiU upgrades (B-T / B-LT / B-LTA) are not yet wired: the
    // existing sign() etsiU helpers operate on the sole signer of a fresh
    // single-signer JWS. Applying them in this path would attach sigTst /
    // rVals / arcTst at the document level, which conformance validators
    // would attribute to every signer — including the prior ones whose
    // PKCS#11 sessions we no longer hold. Gate with PolicyViolation; the
    // per-signer-index helpers are planned for the next cycle.
    if (level > SignatureLevel::B_B)
        return makeFailure(SignFailureKind::PolicyViolation,
                           "JAdES appendSigner: only B-B is supported for the new signer; per-signer etsiU upgrades "
                           "(B-T / B-LT / B-LTA) are planned for the next cycle");

    try {
        // Parse prior JWS JSON General. Reuse tryParseJwsGeneral so we get
        // the same DoS guards (size cap + depth cap) and structural checks
        // ("signatures" array with "protected"+"signature" string members)
        // that the sign() multi-sign branch applies.
        std::vector<uint8_t> priorBytes(prior.begin(), prior.end());
        auto parsed = tryParseJwsGeneral(priorBytes);
        if (!parsed.has_value())
            return makeFailure(SignFailureKind::InvalidDocument,
                               "JAdES appendSigner: prior is not a well-formed JWS JSON General serialization");
        nlohmann::json priorJws = std::move(*parsed);

        // ENVELOPED prior carries the payload field (RFC 7515 §7.2.1);
        // DETACHED prior omits it (RFC 7797 §4.2).
        const bool isDetached = !priorJws.contains("payload");

        // Determine the bytes the new signer must sign — the SAME payload
        // every prior signer signed.
        std::vector<uint8_t> payload;
        if (isDetached) {
            if (originalDoc.empty())
                return makeFailure(
                    SignFailureKind::InvalidInput,
                    "JAdES DETACHED appendSigner requires originalDocument (RFC 7797 §4.2 omits payload)");
            payload.assign(originalDoc.begin(), originalDoc.end());
        } else {
            if (!priorJws["payload"].is_string())
                return makeFailure(SignFailureKind::InvalidDocument,
                                   "JAdES appendSigner: prior payload field is not a string");
            std::string priorPayloadB64 = priorJws["payload"].get<std::string>();
            payload = base64urlDecode(priorPayloadB64);
            if (payload.empty())
                return makeFailure(SignFailureKind::InvalidDocument,
                                   "JAdES appendSigner: failed to decode prior payload (invalid base64url)");
            // Optional integrity check: if the caller supplied originalDoc
            // for an ENVELOPED prior, assert it matches the decoded payload
            // byte-for-byte. Mismatch is a tampering / wrong-document hint
            // and the API contract says we reject with InvalidDocument.
            if (!originalDoc.empty()) {
                if (payload.size() != originalDoc.size() ||
                    std::memcmp(payload.data(), originalDoc.data(), payload.size()) != 0) {
                    return makeFailure(
                        SignFailureKind::InvalidDocument,
                        "JAdES appendSigner: originalDocument does not match the prior signers' payload");
                }
            }
        }

        // Build the new signer's B-B JWS components over the same payload.
        // buildJwsBB is the same primitive sign() uses for a fresh single-
        // signer JWS so the new entry is byte-compatible with the prior
        // entries (same alg selection, same x5c shape, same crit set).
        JwsComponents newJws = buildJwsBB(payload, isDetached, token);

        // Append the new signature entry to signatures[]. Each entry is the
        // JWS JSON General per-signature object: {"protected", "signature",
        // optional "header"}. The top-level payload field stays as-is —
        // present for ENVELOPED, absent for DETACHED — so the output keeps
        // the prior packaging.
        nlohmann::json newEntry;
        newEntry["protected"] = newJws.protectedHeader;
        newEntry["signature"] = newJws.signature;
        if (!newJws.unprotectedHeader.empty())
            newEntry["header"] = newJws.unprotectedHeader;

        priorJws["signatures"].push_back(std::move(newEntry));

        std::string out = priorJws.dump();
        return makeSuccess(std::vector<uint8_t>(out.begin(), out.end()));

    } catch (const std::exception& e) {
        return makeFailure(SignFailureKind::EngineError, std::string("JAdES appendSigner error: ") + e.what());
    }
}

} // namespace libresign
