// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "libresign/dss/dss_signing_service.h"
#include "libresign/dss/dss_path_resolver.h"
#include "libresign/http_client.h"
#include <smartcard/secure_buffer.h>

#include <json.hpp>
#include <openssl/crypto.h>
#include <stdexcept>

namespace libresign {

namespace {

std::string formatToString(SignatureFormat format)
{
    switch (format) {
    case SignatureFormat::PAdES:
        return "PAdES";
    case SignatureFormat::CAdES:
        return "CAdES";
    case SignatureFormat::XAdES:
        return "XAdES";
    case SignatureFormat::ASiC_E:
        return "ASiC_E";
    case SignatureFormat::JAdES:
        return "JAdES";
    }
    return "PAdES";
}

std::string packagingToString(SignaturePackaging packaging)
{
    switch (packaging) {
    case SignaturePackaging::ENVELOPED:
        return "ENVELOPED";
    case SignaturePackaging::DETACHED:
        return "DETACHED";
    }
    return "ENVELOPED";
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
    return "B_T";
}

void addTsaConfig(nlohmann::json& body, const SigningRequest& request)
{
    if (request.level != SignatureLevel::B_B && !request.tsa.url.empty()) {
        body["tsa"]["url"] = request.tsa.url;
        body["tsa"]["timeout"] = request.tsa.timeoutSeconds;
    }
}

void addVisualConfig(nlohmann::json& body, const SigningRequest& request)
{
    if (request.visual.enabled) {
        body["visual"]["page"] = request.visual.page;
        body["visual"]["x"] = request.visual.x;
        body["visual"]["y"] = request.visual.y;
        body["visual"]["width"] = request.visual.width;
        body["visual"]["height"] = request.visual.height;
        body["visual"]["signerName"] = request.visual.signerName;
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
                                      std::span<const uint8_t> pin, const std::string& keyAlias,
                                      const std::string& tokenLabel)
{
    auto result = manager().ensureRunning();
    if (!result)
        return {false, {}, result.error};

    auto socketPath = manager().unixSocketPath();

    // The Java DSS service expects the PIN as a JSON string field. We have
    // to materialize a std::string here to feed nlohmann::json. Cleanse it
    // unconditionally on scope exit so it doesn't outlive this stack frame
    // even on exception. (The PIN still ends up in JVM String memory once
    // the Java side parses the request — that's an inherent limitation of
    // the IPC architecture documented on the header.)
    std::string pinStr(reinterpret_cast<const char*>(pin.data()), pin.size());
    smartcard::PinStringScrubber pinScrubber{pinStr};

    nlohmann::json meta;
    meta["format"] = formatToString(request.format);
    meta["packaging"] = packagingToString(request.packaging);
    meta["level"] = levelToString(request.level);
    meta["pkcs11ModulePath"] = pkcs11ModulePath;
    meta["pin"] = pinStr;
    meta["keyAlias"] = keyAlias;
    // DSS Java service currently uses slot index only; pass tokenLabel for future use,
    // fall back to slot -1 (auto-detect) when label is provided.
    if (!tokenLabel.empty())
        meta["tokenLabel"] = tokenLabel;
    meta["slotIndex"] = -1;

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
        return {false, {}, msg};
    }

    // Response is raw binary (application/octet-stream)
    std::vector<uint8_t> doc(resp.body.begin(), resp.body.end());
    return {true, std::move(doc), {}};
}

} // namespace libresign
