// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

/// @file
/// @brief @ref LibreSCRS::SecureChannel::BacInput — public carrier for the
///        three MRZ-Z field components needed to derive BAC session keys
///        (ICAO Doc 9303 Part 11).

#include <LibreSCRS/Export.h>
#include <LibreSCRS/Secure/String.h>

namespace LibreSCRS::SecureChannel {

/// @brief BAC handshake inputs: the MRZ-Z subset that drives K_Enc / K_Mac
///        derivation. Check digits are computed internally.
///
/// The fields use the ICAO Doc 9303 representation: document number is
/// padded with '<' to 9 characters internally when shorter; the two date
/// fields use the YYMMDD form printed on the MRZ.
///
/// Field types are @ref LibreSCRS::Secure::String — the MRZ subset is
/// scanned off a physical travel document and is a tracking-equivalent
/// secret; storing it in cleansing storage prevents the bytes from
/// surviving in the heap allocator after the struct is dropped.
///
/// @since 4.1
struct LIBRESCRS_PUBLIC_API BacInput
{
    /// @brief Travel document number from the MRZ line 2.
    /// @since 4.1 (field type tightened from `std::string` to
    ///        @ref LibreSCRS::Secure::String — 4.1 is the first release
    ///        that ships @ref BacInput publicly, no consumers were
    ///        broken).
    LibreSCRS::Secure::String documentNumber;

    /// @brief Holder's date of birth (YYMMDD).
    /// @since 4.1 (type tightened — see @ref documentNumber).
    LibreSCRS::Secure::String dateOfBirth;

    /// @brief Document's date of expiry (YYMMDD).
    /// @since 4.1 (type tightened — see @ref documentNumber).
    LibreSCRS::Secure::String dateOfExpiry;
};

} // namespace LibreSCRS::SecureChannel
