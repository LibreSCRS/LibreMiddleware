// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

#include "http_client.h"

#include <cstdint>
#include <span>
#include <string>
#include <vector>

struct ValidationSignatureInfo
{
    std::string level;
    bool valid = false;
    std::string indication;
    std::string subIndication;
    std::vector<std::string> errors;
    std::vector<std::string> warnings;
};

struct ValidationResult
{
    bool valid = false;
    int signatureCount = 0;
    std::string error;
    std::vector<ValidationSignatureInfo> signatures;
};

class DSSValidationClient
{
public:
    DSSValidationClient(const std::string& baseUrl, const std::string& socketPath)
        : baseUrl(baseUrl), socketPath(socketPath)
    {}

    ValidationResult validate(std::span<const uint8_t> signedDocument, const std::string& format,
                              const std::string& packaging, std::span<const uint8_t> originalDocument = {});

private:
    std::string baseUrl;
    std::string socketPath;
    libresign::HttpClient httpClient;
};
