// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

/// @file
/// @brief The per-operation PIN rule for an OpenSC-bound key, shared by the
///        OpenSC card plugin and the OpenSC PKCS#11 slot so the two cannot
///        disagree about a key.

#include <libopensc/opensc.h>
#include <libopensc/pkcs15.h>

namespace LibreSCRS::OpenSc {

/// @brief True when the card wants the PIN again for every operation with
///        @p object -- OpenSC's own reading of PKCS#15 userConsent, which its
///        PKCS#11 framework publishes as CKA_ALWAYS_AUTHENTICATE. The PIV
///        emulator sets it on the Digital Signature key (9C).
[[nodiscard]] inline bool requiresPerOperationAuth(const sc_pkcs15_object_t& object) noexcept
{
    return object.user_consent >= 1;
}

} // namespace LibreSCRS::OpenSc
