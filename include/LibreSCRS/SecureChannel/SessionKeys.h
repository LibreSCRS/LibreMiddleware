// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

/// @file
/// @brief Public session-keys carrier shared by @ref PaceChannel and
///        @ref BacChannel. Wraps encryption key, MAC key, and send-
///        sequence counter (SSC) byte vectors.

#include <LibreSCRS/Export.h>

#include <cstdint>
#include <vector>

namespace LibreSCRS::SecureChannel {

/// @brief Cipher family carried by a @ref SessionKeys block.
///
/// @since 4.1
enum class SmCipher
{
    /// @brief Two-key 3DES with ISO 9797-1 MAC algorithm 3 (BAC).
    Des3,
    /// @brief AES-CBC + AES-CMAC at the configured key length (PACE).
    Aes,
};

/// @brief Derived secure-channel keys. Caller owns the vectors;
///        ownership transfers into the channel constructor.
///
/// `ssc` is the send-sequence counter. For BAC/3DES it is 8 bytes
/// initialised per ICAO Doc 9303 Part 11 §4.3.4; for PACE/AES it is
/// 16 bytes initialised per BSI TR-03110 §3.4.
///
/// @since 4.1
struct LIBRESCRS_PUBLIC_API SessionKeys
{
    std::vector<std::uint8_t> encKey;
    std::vector<std::uint8_t> macKey;
    std::vector<std::uint8_t> ssc;
    SmCipher cipher = SmCipher::Aes;
};

} // namespace LibreSCRS::SecureChannel
