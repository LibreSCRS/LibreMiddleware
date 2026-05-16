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

#include <openssl/crypto.h>

namespace LibreSCRS::SecureChannel {

/// @brief Cipher family carried by a @ref SessionKeys block.
///
/// @since 4.1
enum class SmCipher {
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
/// @par Cleansing
/// The destructor zeroes @ref encKey, @ref macKey and @ref ssc via
/// `OPENSSL_cleanse` before the underlying vectors release their
/// allocations. Move-from leaves the source vectors empty (capacity 0,
/// data() either null or points to a 0-byte region) so the post-move
/// cleanse is a no-op — that's intentional and correct; the live key
/// material follows ownership into the move destination, which carries
/// the same cleansing contract.
///
/// @since 4.1
struct LIBRESCRS_PUBLIC_API SessionKeys
{
    std::vector<std::uint8_t> encKey;
    std::vector<std::uint8_t> macKey;
    std::vector<std::uint8_t> ssc;
    SmCipher cipher = SmCipher::Aes;

    SessionKeys() = default;
    SessionKeys(const SessionKeys&) = default;
    SessionKeys(SessionKeys&&) noexcept = default;
    SessionKeys& operator=(const SessionKeys&) = default;
    SessionKeys& operator=(SessionKeys&&) noexcept = default;

    /// @brief Cleanse every key field before the vectors release their
    ///        allocations.
    /// @since 4.1
    ~SessionKeys()
    {
        if (!encKey.empty()) {
            OPENSSL_cleanse(encKey.data(), encKey.size());
        }
        if (!macKey.empty()) {
            OPENSSL_cleanse(macKey.data(), macKey.size());
        }
        if (!ssc.empty()) {
            OPENSSL_cleanse(ssc.data(), ssc.size());
        }
    }
};

} // namespace LibreSCRS::SecureChannel
