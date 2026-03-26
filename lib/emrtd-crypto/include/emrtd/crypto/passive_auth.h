// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace emrtd::crypto {

struct PAResult
{
    enum Status { PASSED, FAILED, NOT_PERFORMED };
    Status sodSignature = NOT_PERFORMED;
    Status cscaChain = NOT_PERFORMED;
    std::map<int, Status> dgHashes;
    std::string hashAlgorithm;
    std::string dscSubject;
    std::string dscExpiry;
    std::string errorDetail;
};

struct SODContent
{
    std::string hashAlgorithm;
    std::map<int, std::vector<uint8_t>> dgHashes;
    std::string ldsVersion;
    std::string unicodeVersion;
};

std::optional<SODContent> parseSOD(const std::vector<uint8_t>& sodRaw);
PAResult::Status verifyDGHash(const std::vector<uint8_t>& dgRaw, const std::vector<uint8_t>& expectedHash,
                              const std::string& hashAlgorithm);
PAResult::Status verifySODSignature(const std::vector<uint8_t>& sodRaw);
PAResult::Status verifyCSCAChain(const std::vector<uint8_t>& sodRaw, const std::string& trustStorePath);
PAResult performPassiveAuth(const std::vector<uint8_t>& sodRaw, const std::map<int, std::vector<uint8_t>>& dgRawData,
                            const std::string& trustStorePath = "");

} // namespace emrtd::crypto
