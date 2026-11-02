// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif
#pragma once

#include "pin_lifecycle_derivation.h"

#include <libopensc/pkcs15.h>

#include <cstdint>
#include <string>
#include <vector>

/// @file
/// @brief The evidence of an OpenSC auth object, and the user-PIN choice the
///        derivation engine makes over it -- the same rule the PKCS#15 card
///        plugin applies to its own AODF.

namespace LibreSCRS::OpenSc {

/// @brief The derivation evidence of one AODF PIN object as OpenSC parsed it.
///        The generic OpenSC path has no signature-DF map and no PACE
///        evidence, so @c inQscdDf and @c paceEvidence stay false.
[[nodiscard]] inline LibreSCRS::Plugin::Internal::PinEvidence authEvidence(const sc_pkcs15_object_t& obj,
                                                                           const sc_pkcs15_auth_info_t& info)
{
    LibreSCRS::Plugin::Internal::PinEvidence ev;
    // An empty AODF label must never be advertised verbatim: the changePIN
    // selector contract reserves the EMPTY selector for the default-PIN
    // fallback, so "" would alias this record onto a DIFFERENT credential.
    // The documented "pin_<reference>" form is the non-aliasing substitute.
    const auto reference = static_cast<std::uint8_t>(info.attrs.pin.reference & 0xff);
    ev.label = obj.label[0] ? std::string{obj.label} : "pin_" + std::to_string(reference);
    ev.reference = reference;
    ev.ownId.assign(info.auth_id.value, info.auth_id.value + info.auth_id.len);
    ev.protectingAuthId.assign(obj.auth_id.value, obj.auth_id.value + obj.auth_id.len);
    const unsigned int flags = info.attrs.pin.flags;
    ev.localScope = (flags & SC_PKCS15_PIN_FLAG_LOCAL) != 0;
    ev.soPinFlag = (flags & SC_PKCS15_PIN_FLAG_SO_PIN) != 0;
    ev.unblockingPinFlag = (flags & SC_PKCS15_PIN_FLAG_UNBLOCKING_PIN) != 0;
    ev.unblockDisabledFlag = (flags & SC_PKCS15_PIN_FLAG_UNBLOCK_DISABLED) != 0;
    ev.changeDisabledFlag = (flags & SC_PKCS15_PIN_FLAG_CHANGE_DISABLED) != 0;
    ev.initialized = (flags & SC_PKCS15_PIN_FLAG_INITIALIZED) != 0;
    // tries_left semantics: -1 = unknown; >= 0 = real count, 0 blocked.
    ev.blocked = (info.tries_left == 0);
    ev.needsChangeSignal = (info.logged_in & SC_PIN_STATE_NEEDS_CHANGE) != 0;
    return ev;
}

/// @brief The card's user PIN among the AODF's AUTH_PIN objects.
///
/// AUTH_PIN objects arrive in AODF insertion order, and nothing says the user
/// PIN is first: on a card that lists its unblocking PIN first, addressing
/// index 0 spends the PUK's retry counter on a user's PIN attempt, and a PUK
/// driven to zero takes the card's last recovery path with it. The choice is
/// LibreSCRS::Plugin::Internal::selectUserPin over every PIN object's
/// evidence, chains resolved -- an initialized local user PIN first, then an
/// initialized one.
///
/// Returns nullptr when the AODF names no user PIN. Callers must treat that
/// as "no credential to address" -- never as a reason to fall back to index 0.
[[nodiscard]] inline sc_pkcs15_object_t* firstUserPinObject(sc_pkcs15_object_t* const* pinObjs, int pinCount)
{
    if (!pinObjs || pinCount <= 0)
        return nullptr;
    std::vector<LibreSCRS::Plugin::Internal::PinEvidence> evidence;
    std::vector<sc_pkcs15_object_t*> objects; // aligned with evidence
    for (int i = 0; i < pinCount; ++i) {
        sc_pkcs15_object_t* obj = pinObjs[i];
        const auto* info = obj ? static_cast<const sc_pkcs15_auth_info_t*>(obj->data) : nullptr;
        if (info == nullptr || info->auth_type != SC_PKCS15_PIN_AUTH_TYPE_PIN)
            continue;
        evidence.push_back(authEvidence(*obj, *info));
        objects.push_back(obj);
    }
    LibreSCRS::Plugin::Internal::resolveAuthIdChains(evidence);
    const auto chosen = LibreSCRS::Plugin::Internal::selectUserPin(evidence);
    return chosen ? objects[*chosen] : nullptr;
}

} // namespace LibreSCRS::OpenSc
