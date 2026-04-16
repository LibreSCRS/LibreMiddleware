// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "dss_validation_client.h"

#include <json.hpp>

ValidationResult DSSValidationClient::validate(std::span<const uint8_t> signedDocument, const std::string& format,
                                               const std::string& packaging, std::span<const uint8_t> originalDocument)
{
    ValidationResult result;

    // Build JSON metadata
    nlohmann::json meta;
    meta["format"] = format;
    meta["packaging"] = packaging;

    libresign::HttpResponse response;
    try {
        response = httpClient.postMultipartValidation(baseUrl + "/validate", signedDocument, "document", meta.dump(),
                                                      originalDocument, 60, socketPath);
    } catch (const std::exception& e) {
        result.error = std::string("HTTP request failed: ") + e.what();
        return result;
    }

    if (response.statusCode != 200) {
        result.error = "HTTP " + std::to_string(response.statusCode);
        if (!response.body.empty())
            result.error += ": " + response.body;
        else if (!response.errorMessage.empty())
            result.error += ": " + response.errorMessage;
        return result;
    }

    try {
        auto json = nlohmann::json::parse(response.body);
        auto getStr = [](const nlohmann::json& j, const char* k) -> std::string {
            if (!j.contains(k) || j[k].is_null() || !j[k].is_string()) return {};
            return j[k].get<std::string>();
        };
        auto getBool = [](const nlohmann::json& j, const char* k) -> bool {
            if (!j.contains(k) || !j[k].is_boolean()) return false;
            return j[k].get<bool>();
        };
        auto getInt = [](const nlohmann::json& j, const char* k) -> int {
            if (!j.contains(k) || !j[k].is_number_integer()) return 0;
            return j[k].get<int>();
        };
        result.valid = getBool(json, "valid");
        result.signatureCount = getInt(json, "signatureCount");

        if (json.contains("signatures") && json["signatures"].is_array()) {
            for (const auto& sig : json["signatures"]) {
                ValidationSignatureInfo info;
                info.level = getStr(sig, "level");
                info.valid = getBool(sig, "valid");
                info.indication = getStr(sig, "indication");
                info.subIndication = getStr(sig, "subIndication");

                if (sig.contains("errors") && sig["errors"].is_array()) {
                    for (const auto& e : sig["errors"])
                        if (e.is_string()) info.errors.push_back(e.get<std::string>());
                }
                if (sig.contains("warnings") && sig["warnings"].is_array()) {
                    for (const auto& w : sig["warnings"])
                        if (w.is_string()) info.warnings.push_back(w.get<std::string>());
                }

                result.signatures.push_back(std::move(info));
            }
        }
    } catch (const nlohmann::json::exception& e) {
        result.error = std::string("JSON parse error: ") + e.what();
    }

    return result;
}
