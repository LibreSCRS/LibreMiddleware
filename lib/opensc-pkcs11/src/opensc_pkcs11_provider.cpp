// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

/// @file
/// @brief @ref LibreSCRS::OpenSc::Pkcs11::OpenScPKCS11Provider — broadest
///        PKCS#11 fallback. Constructs an @ref OpenScCard and returns it
///        on a successful @c sc_pkcs15_bind.

#include <internal/OpenScPKCS11Provider.h>

#include "opensc_card.h"

#include <internal/Crv.h>

#include <LibreSCRS_internal/SmartCard/SessionPresence.h>
#include <LibreSCRS_internal/SmartCard/SmartCardServices.h>

namespace LibreSCRS::OpenSc::Pkcs11 {

std::shared_ptr<LibreSCRS::Pkcs11::Internal::PKCS11Card> OpenScPKCS11Provider::probe(const std::string& readerName)
{
    // Defer when another in-process CardSession holds a live SM channel on
    // this reader: binding a card over a parallel PC/SC handle while a PACE/BAC
    // SM tunnel is live on the card-side context invalidates the tunnel
    // (BSI TR-03110 §3 — SM is session-scoped). Sessions without a live
    // secure channel (contact PKCS#15, PIV, generic ICC) are safe to bind
    // against in parallel — mere presence of a CardSession is NOT
    // sufficient grounds to skip.
    //
    // This is deliberately conservative about the handle as well as the bind.
    // What is known to break a tunnel is the bind: it sends APDUs outside the
    // secure channel, and a malformed or plain command under an established
    // channel ends the session card-side. A handle on its own need not — the reader enumeration
    // this very call performs opens and closes one on every reader holding a
    // card, including readers refused here, and does no more than a
    // reader-level control call before a SCARD_LEAVE_CARD disconnect. That
    // narrower statement is not yet measured on hardware, so the guard refuses
    // the whole probe rather than only the APDUs.
    LibreSCRS::SmartCard::Internal::ensureSessionPresenceInitialised();
    if (LibreSCRS::SmartCard::Internal::sessionPresence().hasLiveSm(readerName))
        return nullptr;

    auto card = std::make_shared<OpenScCard>();
    if (auto rc = card->bind(readerName); rc != LibreSCRS::Pkcs11::Internal::Crv::Ok)
        return nullptr;
    return card;
}

} // namespace LibreSCRS::OpenSc::Pkcs11
