// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace emrtd {

struct MRZData
{
    std::string documentNumber;
    std::string dateOfBirth;  // YYMMDD
    std::string dateOfExpiry; // YYMMDD
};

enum class AuthMethod { BAC, PACE_MRZ, PACE_CAN };

struct AuthResult
{
    bool success = false;
    AuthMethod method = AuthMethod::BAC;
    std::string error;
};

// eMRTD Application AID
inline constexpr uint8_t EMRTD_AID[] = {0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01};
inline constexpr size_t EMRTD_AID_LEN = 7;

// EF.CardAccess short file identifier
inline constexpr uint8_t SFID_CARD_ACCESS = 0x1C;

// Data Group File Identifiers
inline uint16_t dgToFID(int dg)
{
    if (dg >= 1 && dg <= 16)
        return static_cast<uint16_t>(0x0100 + dg);
    return 0;
}

inline constexpr uint16_t FID_COM = 0x011E;
inline constexpr uint16_t FID_SOD = 0x011D;

} // namespace emrtd
