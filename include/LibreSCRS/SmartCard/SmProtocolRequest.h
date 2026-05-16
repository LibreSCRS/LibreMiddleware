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
/// @since 4.1
struct BacRequest
{
};

/// @brief Request PACE SM (BSI TR-03110) using @ref secretKind as the
///        shared-secret variant.
///
/// @since 4.1
struct PaceRequest
{
    LibreSCRS::Auth::PaceSecretKind secretKind = LibreSCRS::Auth::PaceSecretKind::Can;
};

/// @brief Variant tag chosen by the plugin to specify which protocol the
///        session should establish.
///
/// Future protocol families (EAC/TA/CA) will extend this variant when
/// their consumer plugins arrive.
///
/// @since 4.1
using SmProtocolRequest = std::variant<BacRequest, PaceRequest>;

} // namespace LibreSCRS::SmartCard
