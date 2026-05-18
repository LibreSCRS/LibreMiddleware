// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

/// @file
/// @brief @ref LibreSCRS::Auth::PaceSecretKind — variant tag describing
///        which kind of shared secret a card uses for PACE (or BAC). The
///        same enum classifies the per-process credentials cache slot on
///        @ref LibreSCRS::SmartCard::CardSession.

#include <cstddef>
#include <cstdint>

namespace LibreSCRS::Auth {

/// @brief Kind of pre-shared secret used to derive a secure channel.
///
/// The @ref Mrz variant is shared between PACE (eMRTD passports using
/// MRZ-as-PACE-password) and BAC (which always uses MRZ); plugin code
/// dispatches on the channel protocol, not on the secret kind.
///
/// @since 4.1
enum class PaceSecretKind : std::uint8_t {
    /// @brief Card Access Number — short numeric secret printed on the card
    ///        (BSI TR-03110 §2.3, "non-blocking PACE password"). Used by
    ///        contactless RS eID, GEO CB, NAM CL and other government cards.
    Can = 0,
    /// @brief Machine Readable Zone subset (document number + date of birth +
    ///        date of expiry) per ICAO Doc 9303 Part 11. Used both as the
    ///        PACE password on PACE-only eMRTDs and as the BAC key seed on
    ///        passports lacking PACE SecurityInfos.
    Mrz = 1,
    /// @brief User PIN promoted to PACE-password role (BSI TR-03110 §2.3
    ///        "PACE-PIN"). Blocks on consecutive failures; the host must
    ///        track retries-left semantics on top of the channel.
    Pin = 2,
    /// @brief PIN-Unblocking Key promoted to PACE-password role. Same
    ///        retry/blocking semantics as @ref Pin; reserved for the PIN
    ///        unblock workflow.
    Puk = 3,
};

/// @brief Cardinality of @ref PaceSecretKind. Sized to fit a small
///        fixed-size cache array indexed by the enumerator value.
inline constexpr std::size_t kPaceSecretKindCount = 4;

} // namespace LibreSCRS::Auth
