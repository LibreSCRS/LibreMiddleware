// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

#include "types.h"

#include <LibreSCRS/SmartCard/TransportError.h>

#include <expected>
#include <optional>
#include <string>
#include <string_view>

namespace LibreSCRS::SmartCard {
class IConnection;
}

namespace emrtd::crypto {

// Derive BAC K_Enc and K_MAC from MRZ fields.
// Document number is padded to 9 chars with '<' if shorter.
// Check digits computed internally per ICAO 9303 Part 11.
BACKeys deriveBACKeys(const std::string& documentNumber, const std::string& dateOfBirth,
                      const std::string& dateOfExpiry);

// Perform BAC mutual authentication with the card.
// Returns session keys on success (3DES, SSC = 8 bytes); an empty optional is
// the card refusing (wrong MRZ), the error is the reader failing to carry an
// exchange.
[[nodiscard]] std::expected<std::optional<SessionKeys>, LibreSCRS::SmartCard::TransportError>
performBAC(LibreSCRS::SmartCard::IConnection& conn, const BACKeys& keys);

namespace detail {
int computeCheckDigit(std::string_view input);
} // namespace detail

} // namespace emrtd::crypto
