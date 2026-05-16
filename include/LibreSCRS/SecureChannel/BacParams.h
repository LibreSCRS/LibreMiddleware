// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

/// @file
/// @brief @ref LibreSCRS::SecureChannel::BacInput — public carrier for the
///        three MRZ-Z field components needed to derive BAC session keys
///        (ICAO Doc 9303 Part 11).

#include <LibreSCRS/Export.h>

#include <string>

namespace LibreSCRS::SecureChannel {

/// @brief BAC handshake inputs: the MRZ-Z subset that drives K_Enc / K_Mac
///        derivation. Check digits are computed internally.
///
/// The fields use the ICAO Doc 9303 representation: document number is
/// padded with '<' to 9 characters internally when shorter; the two date
/// fields use the YYMMDD form printed on the MRZ.
///
/// @since 4.1
struct LIBRESCRS_PUBLIC_API BacInput
{
    /// @brief Travel document number from the MRZ line 2.
    std::string documentNumber;

    /// @brief Holder's date of birth (YYMMDD).
    std::string dateOfBirth;

    /// @brief Document's date of expiry (YYMMDD).
    std::string dateOfExpiry;
};

} // namespace LibreSCRS::SecureChannel
