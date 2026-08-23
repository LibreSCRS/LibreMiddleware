// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

/// @file
/// @brief @ref LibreSCRS::SmartCard::SmProtocolRequest variant — used by
///        @ref CardSession::activateChannelWithSm to indicate which SM
///        protocol the plugin wants the session to establish.

#include <LibreSCRS/Auth/PaceSecretKind.h>

#include <variant>

namespace LibreSCRS::SmartCard {

/// @brief Request BAC SM (ICAO Doc 9303 Part 11). Always keyed on MRZ.
///
/// @par Thread-safety
/// thread-compatible (see API-POLICY §8).
///
/// @since 4.1
struct BacRequest
{
    /// @brief Defaulted byte-identity equality.
    [[nodiscard]] bool operator==(const BacRequest&) const noexcept = default;
};

/// @brief Request PACE SM (BSI TR-03110) using @ref secretKind as the
///        shared-secret variant.
///
/// @par Thread-safety
/// thread-compatible (see API-POLICY §8).
///
/// @since 4.1
struct PaceRequest
{
    LibreSCRS::Auth::PaceSecretKind secretKind = LibreSCRS::Auth::PaceSecretKind::Can;

    /// @brief Defaulted byte-identity equality.
    [[nodiscard]] bool operator==(const PaceRequest&) const noexcept = default;
};

/// @brief Request routing through a live Chip-Authentication SM tunnel
///        (BSI TR-03110 §4.4 / ICAO Doc 9303 Part 11).
///
/// Reuse-only: the session cannot establish this protocol from scratch —
/// the CA handshake needs a freshly read DG14 and therefore lives inside
/// the eMRTD read flow, which installs the resulting channel and records
/// this request. @ref CardSession::activateChannelWithSm honours it only
/// through the live-channel reuse paths (same-applet fast path and
/// wrapped-SELECT applet switch) and refuses otherwise.
///
/// @par Thread-safety
/// thread-compatible (see API-POLICY §8).
///
/// @since 4.4
struct ChipAuthRequest
{
    /// @brief Defaulted byte-identity equality.
    [[nodiscard]] bool operator==(const ChipAuthRequest&) const noexcept = default;
};

/// @brief Variant tag chosen by the plugin to specify which protocol the
///        session should establish.
///
/// Future protocol families (EAC/TA) will extend this variant when their
/// consumer plugins arrive. Alternatives are append-only — the variant
/// index is part of the in-process contract between plugins and
/// @ref CardSession.
///
/// @since 4.1
using SmProtocolRequest = std::variant<BacRequest, PaceRequest, ChipAuthRequest>;

} // namespace LibreSCRS::SmartCard
