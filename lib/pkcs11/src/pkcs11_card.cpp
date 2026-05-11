// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

/// @file
/// @brief Default-implemented members of @ref LibreSCRS::Pkcs11::Internal::PKCS11Card.

#include "internal/PKCS11Card.h"

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
    // cardMutex). Slot-side bookkeeping (login state, object cache)
    // is the library's responsibility once we return.
    std::scoped_lock lock(cardMutex);
    return reconnectInline();
}

} // namespace LibreSCRS::Pkcs11::Internal
