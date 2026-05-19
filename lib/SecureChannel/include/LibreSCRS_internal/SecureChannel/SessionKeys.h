// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "LibreSCRS_internal/SecureChannel/SessionKeys.h is internal to LibreMiddleware."
#endif

#pragma once

/// @file
/// @brief Internal session-keys carrier shared by @ref PaceChannel and
///        @ref BacChannel. Wraps encryption key, MAC key, and send-
///        sequence counter (SSC) as cleansing-allocator-backed
///        @ref LibreSCRS::Secure::Buffer instances.

#include <LibreSCRS/Secure/Buffer.h>

#include <cstdint>

namespace LibreSCRS::SecureChannel {

/// @brief Cipher family carried by a @ref SessionKeys block.
///
/// @since 4.1
enum class SmCipher : std::uint8_t {
    /// @brief Two-key 3DES with ISO 9797-1 MAC algorithm 3 (BAC).
    Des3,
    /// @brief AES-CBC + AES-CMAC at the configured key length (PACE).
    Aes,
};

/// @brief Derived secure-channel keys.
///
/// `ssc` is the send-sequence counter. For BAC/3DES it is 8 bytes
/// initialised per ICAO Doc 9303 Part 11 §4.3.4; for PACE/AES it is
/// 16 bytes initialised per BSI TR-03110 §3.4.
///
/// @par Cleansing
/// The three byte fields are @ref LibreSCRS::Secure::Buffer instances:
/// every freed allocation passes through the cleansing allocator before
/// reaching `::operator delete`. Move-only by composition (Buffer is
/// move-only) — copy is deleted at the field level. The destructor and
/// move-assignment chains therefore inherit cleansing for free; no
/// custom operator= or destructor is required.
///
/// @par ABI export
/// Plain aggregate; carries no LIBRESCRS_PUBLIC_API annotation on the
/// type itself per API-POLICY §6.
///
/// @since 4.1
struct SessionKeys
{
    LibreSCRS::Secure::Buffer encKey;
    LibreSCRS::Secure::Buffer macKey;
    LibreSCRS::Secure::Buffer ssc;
    SmCipher cipher = SmCipher::Aes;
};

} // namespace LibreSCRS::SecureChannel
