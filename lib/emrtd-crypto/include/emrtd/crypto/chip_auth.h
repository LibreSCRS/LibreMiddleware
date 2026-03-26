// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once

#include <emrtd/crypto/types.h>
#include <emrtd/crypto/secure_messaging.h>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace smartcard {
class PCSCConnection;
}

namespace emrtd::crypto {

struct ChipAuthInfo
{
    std::vector<uint8_t> oid;
    int version = 0;
    std::optional<int> keyId;
};

struct ChipAuthPublicKey
{
    std::vector<uint8_t> oid;
    std::vector<uint8_t> publicKey; // SubjectPublicKeyInfo DER
    std::optional<int> keyId;
};

struct ChipAuthResult
{
    enum Status { PASSED, FAILED, NOT_PERFORMED, NOT_SUPPORTED };
    Status chipAuthentication = NOT_PERFORMED;
    Status activeAuthentication = NOT_PERFORMED;
    std::string protocol;
    std::string errorDetail;
    std::optional<SessionKeys> newSessionKeys;
    SMAlgorithm newAlgorithm = SMAlgorithm::AES;
};

bool parseDG14(const std::vector<uint8_t>& dg14Raw, std::vector<ChipAuthInfo>& caInfos,
               std::vector<ChipAuthPublicKey>& caKeys);

ChipAuthResult performChipAuth(smartcard::PCSCConnection& conn, const std::vector<uint8_t>& dg14Raw,
                               SecureMessaging& currentSM);
} // namespace emrtd::crypto
