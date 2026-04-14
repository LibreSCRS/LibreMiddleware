// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace libresign {

struct TSAResult
{
    bool success = false;
    std::vector<uint8_t> token; // DER-encoded TimeStampToken (PKCS7)
    std::string errorMessage;
};

class TSAClient
{
public:
    // Request a timestamp for the given SHA-256 hash.
    // Returns DER-encoded RFC 3161 TimeStampToken.
    TSAResult timestamp(const std::vector<uint8_t>& hash, const std::string& tsaUrl, int timeoutSeconds = 10);
};

} // namespace libresign
