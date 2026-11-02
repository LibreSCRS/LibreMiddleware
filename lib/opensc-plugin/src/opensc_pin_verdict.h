// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

/// @file
/// @brief How the OpenSC card plugin reads the answer of
///        @c sc_pkcs15_verify_pin: a verdict on the PIN apart from every
///        failure the PIN did not cause.

#include <libopensc/errors.h>

namespace LibreSCRS::OpenSc {

/// @brief What a VERIFY answer says about the PIN itself.
enum class PinVerdict {
    Accepted,    ///< The card took the PIN.
    Incorrect,   ///< The card refused it (63Cx).
    Blocked,     ///< The card reports it blocked (6983).
    NotAVerdict, ///< Anything the PIN did not cause: a reset, a transport
                 ///< failure, a length OpenSC refused before any APDU.
};

/// @brief The verdict in a @c sc_pkcs15_verify_pin result.
///
/// The retry counter is deliberately not consulted: OpenSC leaves
/// @c tries_left at 0 for every driver that does not go through
/// @c iso7816_pin_cmd, so 0 does not mean "blocked". Only the card's
/// blocked answer (6983) is. A refused one-shot PIN must never be presented
/// a second time, and only Incorrect and Blocked are such a refusal.
[[nodiscard]] constexpr PinVerdict pinVerdictFromVerifyRc(int rc) noexcept
{
    if (rc == SC_SUCCESS)
        return PinVerdict::Accepted;
    if (rc == SC_ERROR_AUTH_METHOD_BLOCKED)
        return PinVerdict::Blocked;
    if (rc == SC_ERROR_PIN_CODE_INCORRECT)
        return PinVerdict::Incorrect;
    return PinVerdict::NotAVerdict;
}

} // namespace LibreSCRS::OpenSc
