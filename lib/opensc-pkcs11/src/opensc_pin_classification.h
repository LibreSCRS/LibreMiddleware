// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif
#pragma once

#include <libopensc/pkcs15.h>

/// @file
/// @brief Single source of user-PIN classification over OpenSC's own
///        sc_pkcs15_auth_info_t, shared by the PKCS#11 module's slot logic
///        and the OpenSC display/change/counter plugin.

namespace LibreSCRS::OpenSc {

/// @brief Filter for AODF PIN objects: drop the PUK / unblocking entries and
///        the SO PIN (we surface only user-auth slots; OpenSC's auth_info
///        conveys the role via the SC_PKCS15_PIN_FLAG_UNBLOCKING_PIN /
///        SC_PKCS15_PIN_FLAG_SO_PIN bits).
[[nodiscard]] inline bool isUserPin(const sc_pkcs15_auth_info_t* auth) noexcept
{
    if (!auth)
        return false;
    if (auth->auth_type != SC_PKCS15_PIN_AUTH_TYPE_PIN)
        return false;
    if (auth->attrs.pin.flags & SC_PKCS15_PIN_FLAG_UNBLOCKING_PIN)
        return false;
    if (auth->attrs.pin.flags & SC_PKCS15_PIN_FLAG_SO_PIN)
        return false;
    return true;
}

/// @brief The first AODF entry that is a real user PIN.
///
/// AUTH_PIN objects arrive in AODF insertion order, and nothing says the user
/// PIN is first: on a card that lists its unblocking PIN first, addressing
/// index 0 spends the PUK's retry counter on a user's PIN attempt, and a PUK
/// driven to zero takes the card's last recovery path with it.
///
/// Returns nullptr when the AODF names no user PIN. Callers must treat that
/// as "no credential to address" -- never as a reason to fall back to index 0.
[[nodiscard]] inline sc_pkcs15_object_t* firstUserPinObject(sc_pkcs15_object_t* const* pinObjs, int pinCount) noexcept
{
    if (!pinObjs || pinCount <= 0)
        return nullptr;
    for (int i = 0; i < pinCount; ++i) {
        sc_pkcs15_object_t* obj = pinObjs[i];
        if (!obj || !obj->data)
            continue;
        if (isUserPin(static_cast<const sc_pkcs15_auth_info_t*>(obj->data)))
            return obj;
    }
    return nullptr;
}

} // namespace LibreSCRS::OpenSc
