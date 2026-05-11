// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

/// @file
/// @brief Default-implemented members of @ref LibreSCRS::Pkcs11::Internal::PKCS11Card.

#include "internal/PKCS11Card.h"

#include "internal/Crv.h"

#include <mutex>

namespace LibreSCRS::Pkcs11::Internal {

PKCS11Card::PKCS11Card() = default;

PKCS11Card::~PKCS11Card() = default;

std::span<const std::shared_ptr<PKCS11Slot>> PKCS11Card::enumerateSlots() const noexcept
{
    return std::span<const std::shared_ptr<PKCS11Slot>>{slots.data(), slots.size()};
}

unsigned long PKCS11Card::handleReset()
{
    // Public wrapper around the private reconnectInline() hook so the
    // library layer can drive recovery without breaching the
    // friendship boundary or leaking transport details. Acquires
    // cardMutex for the duration of the reattach; callers must NOT
    // hold any slotMutex (project-wide lock order: slotMutex →
    // cardMutex).
    unsigned long rv;
    {
        std::scoped_lock lock(cardMutex);
        rv = reconnectInline();
    }
    // On successful reattach, propagate the invalidation to slots
    // OUTSIDE cardMutex — each slot's onCardReset() acquires its own
    // slotMutex, which would invert the project lock order if taken
    // here. PKCS#11 consumers must re-login after a RESET; without
    // this step they would see CKR_DEVICE_ERROR or stale loggedIn
    // state instead of the spec-mandated CKR_USER_NOT_LOGGED_IN.
    // The slots vector is populated once during bind() and never
    // mutated thereafter (documented invariant on enumerateSlots),
    // so reading it lock-free is safe.
    if (rv == Crv::Ok) {
        for (auto& slot : slots) {
            if (slot)
                slot->onCardReset();
        }
    }
    return rv;
}

} // namespace LibreSCRS::Pkcs11::Internal
