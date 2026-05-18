// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

/// @file
/// @brief Single source of user-PIN classification across every PKCS#15
///        surface (the host-side card-plugin display flow and the PKCS#11
///        module's slot logic).

namespace pkcs15 {
struct PinInfo;
} // namespace pkcs15

namespace LibreSCRS::Pkcs15::Internal {

/// @brief True when @p pin describes a normal user PIN (the credential
///        entered at sign / decrypt / verify time), false when it
///        describes an auxiliary credential (CAN, MRZ, PACE secret, PUK,
///        SO PIN, Security-Officer or admin PIN).
///
/// Centralised classification: any future card family that introduces a
/// new label convention extends exactly one site. Consumed by both the
/// eager-bind path (one slot per user PIN) and the placeholder slot
/// self-transform path, as well as the host-side display plugin.
///
/// @since 4.1
[[nodiscard]] bool isUserPin(const ::pkcs15::PinInfo& pin) noexcept;

} // namespace LibreSCRS::Pkcs15::Internal
