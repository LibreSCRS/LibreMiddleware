// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace emrtd::crypto {

struct BACKeys
{
    std::vector<uint8_t> encKey; // 16 bytes (3DES two-key)
    std::vector<uint8_t> macKey; // 16 bytes (3DES two-key)
};

struct SessionKeys
{
    std::vector<uint8_t> encKey;
    std::vector<uint8_t> macKey;
    std::vector<uint8_t> ssc; // 8 bytes for BAC/3DES, 16+ bytes for PACE/AES
};

enum class SMAlgorithm { DES3, AES };

enum class PACEPasswordType { MRZ = 1, CAN = 2, PIN = 3, PUK = 4 };

struct PACEParams
{
    std::string oid;
    PACEPasswordType passwordType;
    std::vector<uint8_t> password;
    int paramId = 13; // BSI TR-03110 standardized domain parameter ID (default: brainpoolP256r1)
};

} // namespace emrtd::crypto
