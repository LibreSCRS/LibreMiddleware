// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

#include <emrtd/crypto/types.h>

#include <optional>
#include <string>

namespace smartcard {
class PCSCConnection;
}

namespace emrtd::crypto {

// Derive BAC K_Enc and K_MAC from MRZ fields.
// Document number is padded to 9 chars with '<' if shorter.
// Check digits computed internally per ICAO 9303 Part 11.
BACKeys deriveBACKeys(const std::string& documentNumber, const std::string& dateOfBirth,
                      const std::string& dateOfExpiry);

// Perform BAC mutual authentication with the card.
// Returns session keys on success (3DES, SSC = 8 bytes).
std::optional<SessionKeys> performBAC(smartcard::PCSCConnection& conn, const BACKeys& keys);

namespace detail {
int computeCheckDigit(const std::string& input);
} // namespace detail

} // namespace emrtd::crypto
