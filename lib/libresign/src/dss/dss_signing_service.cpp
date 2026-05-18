// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "dss/dss_signing_service.h"
#include "dss/dss_path_resolver.h"
#include "http_client.h"
#include <smartcard/secure_buffer.h>

#include <json.hpp>
#include <openssl/crypto.h>
#include <stdexcept>
#include <utility>

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
// SigningService::sign() detects callers passing TSA credentials with
// LIBRESCRS_SIGNING_BACKEND=dss and fails LOUD rather than silently
// downgrading.
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

SigningResult DSSSigningService::sign(const SigningRequest& request, const std::string& pkcs11ModulePath,
                                      const LibreSCRS::Secure::Buffer& pin, const std::string& keyAlias,
                                      const std::string& readerName,
                                      std::shared_ptr<LibreSCRS::SmartCard::CardSession> /*sharedSession*/)
{
    auto result = manager().ensureRunning();
    if (!result)
        return makeFailure(SignFailureKind::EngineError, result.error);

    auto socketPath = manager().unixSocketPath();

    // The Java DSS service expects the PIN as a JSON string field. We have to
    // materialize a std::string here to feed nlohmann::json. The caller's
    // Secure::Buffer cleanses its own storage on destruction, but THIS local
    // std::string copy is born outside that contract — keep PinStringScrubber
    // on `pinStr` so it's cleansed on scope exit even on exception. (The PIN
    // still ends up in JVM String memory once the Java side parses the
    // request — inherent limitation of the IPC architecture, documented on
    // the header.)
    std::string pinStr(reinterpret_cast<const char*>(pin.data()), pin.size());
    LibreSCRS::SmartCard::Internal::PinStringScrubber pinScrubber{pinStr};

    nlohmann::json meta;
    meta["format"] = formatToString(request.format);
    meta["packaging"] = packagingToString(request.packaging);
    meta["level"] = levelToString(request.level);
    meta["pkcs11ModulePath"] = pkcs11ModulePath;
    meta["pin"] = pinStr;
    meta["keyAlias"] = keyAlias;
    // The DSS Java service is a cross-verification test oracle, not a
    // production signing path. It accepts a PCSC reader name on the
    // wire and routes the slot lookup the same way the native engine
    // does (see lib/libresign/src/native/pkcs11_token.cpp's
    // findSlotByReaderName). We do NOT replicate the slotIndex=-1
    // legacy here — that path was the source of the multi-card
    // "wrong PIN" bug; the DSS oracle has to behave the same as the
    // native path for the cross-backend test to be meaningful.
    meta["readerName"] = readerName;

    if (request.allowExpiredCertificate)
        meta["allowExpiredCertificate"] = true;

    addTsaConfig(meta, request);
    addVisualConfig(meta, request);

    auto metaJson = meta.dump();
    // Cleanse PIN from JSON object immediately
    if (meta.contains("pin")) {
        auto& pinRef = meta["pin"].get_ref<std::string&>();
        OPENSSL_cleanse(pinRef.data(), pinRef.size());
        meta.erase("pin");
    }

    auto resp = httpClient->postMultipart(result.baseUrl + "/sign/pkcs11", request.document, request.fileName, metaJson,
                                          120, socketPath);
    // Cleanse PIN from the serialized JSON string
    OPENSSL_cleanse(metaJson.data(), metaJson.size());

    if (resp.statusCode != 200) {
        std::string msg = "DSS service error";
        if (!resp.body.empty())
            msg += ": " + resp.body;
        else if (!resp.errorMessage.empty())
            msg += " (connection): " + resp.errorMessage;
        else
            msg += " (HTTP " + std::to_string(resp.statusCode) + ", no details)";
        return makeFailure(SignFailureKind::EngineError, msg);
    }

    // Response is raw binary (application/octet-stream)
    std::vector<uint8_t> doc(resp.body.begin(), resp.body.end());
    return makeSuccess(std::move(doc));
}

SigningResult DSSSigningService::appendSigner(const SigningRequest& /*request*/,
                                              std::span<const uint8_t> /*priorSignature*/,
                                              std::span<const uint8_t> /*originalDocument*/,
                                              const LibreSCRS::Secure::Buffer& /*pin*/,
                                              const std::string& /*pkcs11Module*/, const std::string& /*keyAlias*/,
                                              const std::string& /*readerName*/,
                                              std::shared_ptr<LibreSCRS::SmartCard::CardSession> /*sharedSession*/)
{
    return makeFailure(SignFailureKind::EngineError, "appendSigner not yet implemented in this backend");
}

} // namespace libresign
