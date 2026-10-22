// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "dss/dss_signing_service.h"
#include "dss/dss_path_resolver.h"
#include "http_client.h"
#include "native/native_utils.h"
#include "native/signing_key.h"

#include <json.hpp>
#include <openssl/evp.h>
#include <openssl/x509.h>

#include <chrono>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace libresign {

namespace {

// API-POLICY §9 forward-compat: exhaustive switches with no `default:` and
// no fall-through return. Adding a new SignatureFormat / SignaturePackaging /
// SignatureLevel value triggers a compile error here (gated by
// -Werror=switch-enum on this TU) instead of silently mapping to a wrong
// wire value — a generic `return "PAdES"` fallback would silently
// downgrade a JAdES request to PAdES if a future hypothetical
// SignatureFormat::PAdES_PDFA were added without touching this file.
//
// std::unreachable() (C++23) after the switch tells both the compiler and
// any reader that no path leaves the switch without returning. This is
// equivalent to __builtin_unreachable + a one-line documentation note.
std::string formatToString(SignatureFormat format)
{
    switch (format) {
    case SignatureFormat::Pades:
        return "PAdES";
    case SignatureFormat::Cades:
        return "CAdES";
    case SignatureFormat::Xades:
        return "XAdES";
    case SignatureFormat::AsicE:
        return "ASiC_E";
    case SignatureFormat::Jades:
        return "JAdES";
    }
    std::unreachable();
}

std::string packagingToString(SignaturePackaging packaging)
{
    switch (packaging) {
    case SignaturePackaging::Enveloped:
        return "ENVELOPED";
    case SignaturePackaging::Detached:
        return "DETACHED";
    }
    std::unreachable();
}

std::string levelToString(SignatureLevel level)
{
    switch (level) {
    case SignatureLevel::B_B:
        return "B_B";
    case SignatureLevel::B_T:
        return "B_T";
    case SignatureLevel::B_LT:
        return "B_LT";
    case SignatureLevel::B_LTA:
        return "B_LTA";
    }
    std::unreachable();
}

// DSS is retained in 4.0 as a cross-verification oracle for tests; the
// native backend is the production signing path. The DSS backend is
// intentionally minimal: it does NOT forward TSA credentials (basicAuth /
// bearerToken / mTLS / extraHeaders) or the PDF /ContactInfo
// signature-dictionary field — feature parity with native is not a goal.
// Also: reason / location / contactInfo are gated on visual.enabled here,
// so invisible signatures lose those fields entirely on the DSS backend.
void addTsaConfig(nlohmann::json& body, const SigningRequest& request)
{
    if (request.level != SignatureLevel::B_B && !request.tsa.url.empty()) {
        body["tsa"]["url"] = request.tsa.url;
        body["tsa"]["timeout"] = request.tsa.timeoutSeconds;
    }
}

// See note above addTsaConfig — addVisualConfig is also gated on
// visual.enabled: invisible signatures lose reason/location, and contactInfo
// is never emitted at all. The DSS oracle role does not require parity here.
void addVisualConfig(nlohmann::json& body, const SigningRequest& request)
{
    if (request.visual.enabled) {
        body["visual"]["page"] = request.visual.page;
        body["visual"]["x"] = request.visual.x;
        body["visual"]["y"] = request.visual.y;
        body["visual"]["width"] = request.visual.width;
        body["visual"]["height"] = request.visual.height;
        body["visual"]["reason"] = request.visual.reason;
        body["visual"]["location"] = request.visual.location;
        if (!request.visual.text.empty())
            body["visual"]["text"] = request.visual.text;
    }
}

} // namespace

DSSSigningService::DSSSigningService() : httpClient(std::make_unique<HttpClient>()) {}

DSSSigningService::DSSSigningService(DSSServiceManager& serviceManager)
    : serviceManagerRef(&serviceManager), httpClient(std::make_unique<HttpClient>())
{}

DSSSigningService::~DSSSigningService() = default;

DSSServiceManager& DSSSigningService::manager()
{
    if (serviceManagerRef)
        return *serviceManagerRef;
    if (!ownedManager) {
        auto config = DSSPathResolver::resolve();
        if (config.jarPath.empty())
            throw std::runtime_error("DSS service JAR not found");
        ownedManager = std::make_unique<DSSServiceManager>(std::move(config));
    }
    return *ownedManager;
}

bool DSSSigningService::configure(const TrustConfig& config)
{
    auto result = manager().ensureRunning();
    if (!result)
        return false;

    nlohmann::json body;
    nlohmann::json tlArray = nlohmann::json::array();
    for (const auto& entry : config.trustedLists) {
        tlArray.push_back({
            {"url", entry.url},
            {"lotl", entry.isLotl},
            {"eager", entry.eager},
        });
    }
    body["trustedLists"] = tlArray;
    body["cacheDirectory"] = config.cacheDirectory;
    body["crlEnabled"] = config.crlEnabled;
    body["ocspEnabled"] = config.ocspEnabled;

    auto resp = httpClient->post(result.baseUrl + "/config", body.dump(), 60, manager().unixSocketPath());
    trustConfigured = (resp.statusCode == 200);
    return trustConfigured;
}

bool DSSSigningService::isConfigured() const
{
    return trustConfigured;
}

bool DSSSigningService::isAvailable() const
{
    if (serviceManagerRef)
        return serviceManagerRef->isHealthy();
    if (ownedManager)
        return ownedManager->isHealthy();
    return false;
}

SigningResult DSSSigningService::sign(const SigningRequest& request, SigningKey& key)
{
    try {
        const auto certDer = key.certificate();
        auto cert = native_utils::parseCert(certDer);
        if (!cert)
            return makeFailure(SignFailureKind::CardError, "the key carries no readable certificate");
        if (EVP_PKEY_base_id(X509_get0_pubkey(cert.get())) != EVP_PKEY_RSA)
            return makeFailure(SignFailureKind::EngineError, "the DSS test-oracle backend signs with RSA keys only");

        auto result = manager().ensureRunning();
        if (!result)
            return makeFailure(SignFailureKind::EngineError, result.error);
        const auto socketPath = manager().unixSocketPath();

        // Both steps carry the same metadata, the signing time included: the
        // oracle rebuilds the same signature parameters from it each time.
        nlohmann::json meta;
        meta["format"] = formatToString(request.format);
        meta["packaging"] = packagingToString(request.packaging);
        meta["level"] = levelToString(request.level);
        meta["certificateChain"] = nlohmann::json::array();
        meta["certificateChain"].push_back(native_utils::base64Encode(certDer));
        for (const auto& der : key.certificateChain()) {
            if (der != certDer)
                meta["certificateChain"].push_back(native_utils::base64Encode(der));
        }
        meta["signingTime"] =
            std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
                .count();
        if (request.allowExpiredCertificate)
            meta["allowExpiredCertificate"] = true;
        addTsaConfig(meta, request);
        addVisualConfig(meta, request);

        auto step = [&](const std::string& path) {
            auto resp = httpClient->postMultipart(result.baseUrl + path, request.document, request.fileName,
                                                  meta.dump(), 120, socketPath);
            if (resp.statusCode == 200)
                return std::vector<uint8_t>(resp.body.begin(), resp.body.end());
            std::string msg = "DSS service error";
            if (!resp.body.empty())
                msg += ": " + resp.body;
            else if (!resp.errorMessage.empty())
                msg += " (connection): " + resp.errorMessage;
            else
                msg += " (HTTP " + std::to_string(resp.statusCode) + ", no details)";
            throw std::runtime_error(msg);
        };

        const auto toBeSigned = step("/sign/data-to-sign");
        const auto signature =
            native_utils::signHashWithKey(key, cert.get(), native_utils::sha256(toBeSigned), "SHA-256", toBeSigned);
        meta["signatureValue"] = native_utils::base64Encode(signature);
        return makeSuccess(step("/sign/document"));
    } catch (const SignFailureException& e) {
        return makeFailure(e.kind, e.what());
    } catch (const std::exception& e) {
        return makeFailure(SignFailureKind::EngineError, e.what());
    }
}

SigningResult DSSSigningService::appendSigner(const SigningRequest& /*request*/,
                                              std::span<const uint8_t> /*priorSignature*/,
                                              std::span<const uint8_t> /*originalDocument*/, SigningKey& /*key*/)
{
    return makeFailure(SignFailureKind::EngineError, "appendSigner is not implemented by the DSS test-oracle backend");
}

} // namespace libresign
