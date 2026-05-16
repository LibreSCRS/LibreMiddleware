// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

/// @file
/// @brief @ref LibreSCRS::SecureChannel::PACEParams — public carrier for
///        the PACE handshake inputs consumed by @ref PaceChannel::establish.
///        Mirrors the internal `emrtd::crypto::PACEParams` aggregate one-
///        for-one so the public surface does not depend on emrtd-crypto's
///        internal header.

#include <LibreSCRS/Auth/PaceSecretKind.h>
#include <LibreSCRS/Export.h>
#include <LibreSCRS/Secure/String.h>

#include <cstdint>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace LibreSCRS::SecureChannel {

/// @brief Inputs for a single PACE handshake attempt.
///
/// Callers populate @ref oid + @ref paramId from parsing EF.CardAccess on
/// the card; @ref passwordType + @ref password come from the credentials
/// cache populated by the host or the credential provider.
///
/// @since 4.1
struct LIBRESCRS_PUBLIC_API PACEParams
{
    /// @brief PACE protocol OID, e.g. "0.4.0.127.0.7.2.2.4.2.4".
    std::string oid;

    /// @brief Variant of the shared secret carried in @ref password.
    LibreSCRS::Auth::PaceSecretKind passwordType = LibreSCRS::Auth::PaceSecretKind::Can;

    /// @brief Shared-secret bytes. Caller-owned; cleansed by the channel
    ///        on handshake completion.
    LibreSCRS::Secure::String password;

    /// @brief BSI TR-03110 standardised domain parameter ID
    ///        (default: brainpoolP256r1 == 13).
    int paramId = 13;
};

/// @brief Parse EF.CardAccess (ASN.1 SET OF SecurityInfo) and return the
///        PACE entries it advertises as (OID, paramId) pairs.
///
/// @p cardAccess is the raw byte content read from EF.CardAccess (FID 011C
/// under MF). Returns an empty vector when the file does not contain any
/// PACE SecurityInfo (i.e. the card does not advertise PACE).
///
/// This is a pure function over the input bytes; no card I/O.
///
/// @since 4.1
[[nodiscard]] LIBRESCRS_PUBLIC_API std::vector<std::pair<std::string, int>>
parsePaceOidsFromCardAccess(std::span<const std::uint8_t> cardAccess);

} // namespace LibreSCRS::SecureChannel
