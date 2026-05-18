// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

/// @file
/// @brief @ref LibreSCRS::OpenSc::Pkcs11::OpenScPKCS11Provider — broadest
///        PKCS#11 fallback. Constructs an @ref OpenScCard and returns it
///        on a successful @c sc_pkcs15_bind.

#include <internal/OpenScPKCS11Provider.h>

#include "opensc_card.h"

#include <internal/Crv.h>
#include <internal/SessionRegistry.h>

#include <LibreSCRS/SmartCard/CardSession.h>

namespace LibreSCRS::OpenSc::Pkcs11 {

std::shared_ptr<LibreSCRS::Pkcs11::Internal::PKCS11Card> OpenScPKCS11Provider::probe(const std::string& readerName)
{
    // Defer to a sibling provider only when the parked session is
    // actively running secure messaging: opening a parallel PC/SC handle
    // while a PACE/BAC SM tunnel is live on the card-side context
    // invalidates the tunnel. Sessions without a live secure channel
    // (contact PKCS#15, PIV, generic ICC) are safe to bind against in
    // parallel — mere presence of an injected session is NOT sufficient
    // grounds to skip.
    if (sessionRegistry) {
        if (auto session = sessionRegistry->peek(readerName)) {
            if (session->hasLiveSecureChannel())
                return nullptr;
        }
    }

    auto card = std::make_shared<OpenScCard>();
    if (auto rc = card->bind(readerName); rc != LibreSCRS::Pkcs11::Internal::Crv::Ok)
        return nullptr;
    return card;
}

} // namespace LibreSCRS::OpenSc::Pkcs11
