// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

#include "types.h"

#include <optional>
#include <string>
#include <vector>

namespace LibreSCRS::SmartCard::Internal {
class PCSCConnection;
}

namespace emrtd::crypto {

// Parse EF.CardAccess (ASN.1 SET OF SecurityInfo) to extract PACE OIDs.
std::vector<std::string> parseCardAccess(const std::vector<uint8_t>& cardAccess);

// Parse EF.CardAccess and return pairs of (OID, paramId) for each PACE SecurityInfo.
// paramId is -1 if the optional parameter INTEGER is absent.
std::vector<std::pair<std::string, int>> parseCardAccessWithParams(const std::vector<uint8_t>& cardAccess);

// Derive the PACE K_π input seed from the password, per BSI TR-03110-3
// §A.3.3 / ICAO 9303 Part 11 §9.7.1.1:
//   - MRZ: full 20-byte SHA-1(MRZ_info).
//   - CAN / PIN / PUK: raw password bytes.
//
// Returns nullopt only if the SHA-1 hash operation fails (unreachable on a
// healthy OpenSSL provider, but the EVP API returns int). The result is
// sensitive intermediate material — callers should manage its lifetime
// behind the same RAII zeroising guard used for K_π / K_MAC.
[[nodiscard]] std::optional<std::vector<uint8_t>> derivePaceKpiSeed(PACEPasswordType passwordType,
                                                                    const std::vector<uint8_t>& password);

// Perform PACE authentication.
std::optional<SessionKeys> performPACE(LibreSCRS::SmartCard::Internal::PCSCConnection& conn, const PACEParams& params);

// Map a PACE OID to the SM algorithm it produces
SMAlgorithm paceOIDToSMAlgorithm(const std::string& oid);

// Well-known PACE OIDs (BSI TR-03110)
namespace pace_oid {
// Generic Mapping (GM)
inline constexpr const char* ECDH_GM_3DES_CBC_CBC = "0.4.0.127.0.7.2.2.4.1.1";
inline constexpr const char* ECDH_GM_AES_CBC_CMAC_128 = "0.4.0.127.0.7.2.2.4.2.2";
inline constexpr const char* ECDH_GM_AES_CBC_CMAC_192 = "0.4.0.127.0.7.2.2.4.2.3";
inline constexpr const char* ECDH_GM_AES_CBC_CMAC_256 = "0.4.0.127.0.7.2.2.4.2.4";
// Integrated Mapping (IM)
inline constexpr const char* ECDH_IM_AES_CBC_CMAC_128 = "0.4.0.127.0.7.2.2.4.3.2";
inline constexpr const char* ECDH_IM_AES_CBC_CMAC_256 = "0.4.0.127.0.7.2.2.4.3.4";
// Chip Authentication Mapping (CAM)
inline constexpr const char* ECDH_CAM_AES_CBC_CMAC_128 = "0.4.0.127.0.7.2.2.4.6.2";
inline constexpr const char* ECDH_CAM_AES_CBC_CMAC_256 = "0.4.0.127.0.7.2.2.4.6.4";
} // namespace pace_oid

} // namespace emrtd::crypto
