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
    Can = 0,
    Mrz = 1,
    Pin = 2,
    Puk = 3,
};

/// @brief Cardinality of @ref PaceSecretKind. Sized to fit a small
///        fixed-size cache array indexed by the enumerator value.
inline constexpr std::size_t kPaceSecretKindCount = 4;

} // namespace LibreSCRS::Auth
