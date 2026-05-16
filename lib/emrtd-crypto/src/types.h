// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <openssl/crypto.h>

namespace emrtd::crypto {

struct BACKeys
{
    std::vector<uint8_t> encKey; // 16 bytes (3DES two-key)
    std::vector<uint8_t> macKey; // 16 bytes (3DES two-key)
};

/// @brief Internal session-keys carrier consumed by @ref SecureMessaging.
///
/// Mirrors the public @ref LibreSCRS::SecureChannel::SessionKeys cleansing
/// contract: the destructor zeroes every key field via OPENSSL_cleanse before
/// the underlying std::vector allocator releases the storage. This closes the
/// uncleansed-leak window that opens when an enclosing construction (typically
/// @c std::make_unique<SecureMessaging> in @c SmChannelBody) throws after the
/// SessionKeys local has been built but before ownership transfers — without
/// this destructor, the local @c std::vector dtors would release the secret
/// bytes through the default allocator without cleansing.
///
/// Move-from leaves the source vectors empty (data() either null or pointing
/// to a 0-byte block), so the post-move cleanse is a no-op; live key material
/// follows ownership into the destination which carries the same contract.
struct SessionKeys
{
    std::vector<uint8_t> encKey;
    std::vector<uint8_t> macKey;
    std::vector<uint8_t> ssc; // 8 bytes for BAC/3DES, 16+ bytes for PACE/AES

    SessionKeys() = default;
    SessionKeys(const SessionKeys&) = default;
    SessionKeys(SessionKeys&&) noexcept = default;

    // Custom assignment that cleanses the destination before letting
    // std::vector's allocator release the storage. The defaulted
    // operator= would release the destination's existing key buffers
    // through the std::vector allocator WITHOUT calling OPENSSL_cleanse
    // on them first, opening exactly the leak window the destructor
    // closes. Required because std::optional<SessionKeys> demands T
    // be move-assignable for its own move-assign to be defined (see
    // ChipAuthResult move-assign in chip_auth.cpp).
    SessionKeys& operator=(const SessionKeys& other)
    {
        if (this != &other) {
            cleanse();
            encKey = other.encKey;
            macKey = other.macKey;
            ssc = other.ssc;
        }
        return *this;
    }
    SessionKeys& operator=(SessionKeys&& other) noexcept
    {
        if (this != &other) {
            cleanse();
            encKey = std::move(other.encKey);
            macKey = std::move(other.macKey);
            ssc = std::move(other.ssc);
        }
        return *this;
    }

    ~SessionKeys()
    {
        cleanse();
    }

private:
    void cleanse() noexcept
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
