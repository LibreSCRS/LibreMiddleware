// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

/// @file
/// @brief How the OpenSC PKCS#11 slot reads the answer of
///        @c sc_pkcs15_verify_pin: a verdict on the PIN apart from every
///        failure the PIN did not cause.

#include <internal/Crv.h>

#include <libopensc/errors.h>

namespace LibreSCRS::OpenSc::Pkcs11 {

/// @brief The slot's return code for a @c sc_pkcs15_verify_pin result --
///        OpenSC's own PKCS#11 mapping of the same answer.
///
/// The retry counter is deliberately not consulted: OpenSC leaves
/// @c tries_left at 0 for every driver that does not go through
/// @c iso7816_pin_cmd, so 0 does not mean "blocked". Only the card's
/// blocked answer (6983) is.
[[nodiscard]] constexpr unsigned long crvFromVerifyRc(int rc) noexcept
{
    namespace Crv = LibreSCRS::Pkcs11::Internal::Crv;
    if (rc == SC_SUCCESS)
        return Crv::Ok;
    if (rc == SC_ERROR_AUTH_METHOD_BLOCKED)
        return Crv::PinLocked;
    if (rc == SC_ERROR_PIN_CODE_INCORRECT)
        return Crv::PinIncorrect;
    if (rc == SC_ERROR_INVALID_PIN_LENGTH)
        return Crv::PinLenRange;
    return Crv::DeviceError;
}

/// @brief The error of a one-shot-PIN signature whose VERIFY failed:
///        @c PinIncorrect / @c PinLocked when the card refused the PIN, and
///        @c DeviceError for anything that is not the card's verdict on it.
[[nodiscard]] constexpr unsigned long refusalFromVerifyRc(int rc) noexcept
{
    namespace Crv = LibreSCRS::Pkcs11::Internal::Crv;
    const unsigned long crv = crvFromVerifyRc(rc);
    if (crv == Crv::PinIncorrect || crv == Crv::PinLocked)
        return crv;
    return Crv::DeviceError;
}

} // namespace LibreSCRS::OpenSc::Pkcs11
