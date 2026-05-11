// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

/// @file
/// @brief Default-implemented members of @ref LibreSCRS::Pkcs11::Internal::PKCS11Slot.
///
/// Phase A introduces only the type contract — concrete login / logout /
/// enumerateObjects / signData / mechanisms paths are left pure-virtual on
/// the base and will be implemented per-card-family in subsequent phases.

#include "internal/PKCS11Card.h"
#include "internal/PKCS11Slot.h"

#include <utility>

namespace LibreSCRS::Pkcs11::Internal {

PKCS11Slot::PKCS11Slot(std::weak_ptr<PKCS11Card> parentCard, std::vector<std::uint8_t> pinId, std::string pinLabel)
    : parentCard(std::move(parentCard)), pinId(std::move(pinId)), pinLabel(std::move(pinLabel))
{}

PKCS11Slot::~PKCS11Slot() = default;

PKCS11TokenInfo PKCS11Slot::tokenInfo() const
{
    std::scoped_lock lock(slotMutex);
    return cachedTokenInfo;
}

bool PKCS11Slot::isLoggedIn() const noexcept
{
    // Default implementation: the inherited @ref loggedIn flag is the
    // sole source of truth. Subclasses with per-key or multi-mode
    // authentication state override this. Acquiring slotMutex here is
    // mandatory to publish writes from login() / logout() to readers
    // outside the lock; std::scoped_lock cannot throw on an
    // uncontended std::mutex, so noexcept is preserved on every glibc
    // / libc++ implementation we ship against.
    std::scoped_lock lock(slotMutex);
    return loggedIn;
}

// Friend-mediated parent accessors (Phase B). PKCS11Slot is the friend
// of PKCS11Card; concrete slot subclasses (Pkcs15Slot, CardEdgeSlot, ...)
// are NOT friends and route protected-state access through these
// statics so the friendship boundary stays a single point.

std::mutex& PKCS11Slot::parentTransportMutex(PKCS11Card& parent) noexcept
{
    return parent.cardMutex;
}

bool PKCS11Slot::parentNeedsPace(const PKCS11Card& parent) noexcept
{
    return parent.needsPace;
}

bool PKCS11Slot::parentCanIsEmpty(const PKCS11Card& parent) noexcept
{
    return parent.cachedCan.empty();
}

void PKCS11Slot::parentCacheCan(PKCS11Card& parent, Secure::String can) noexcept
{
    parent.cachedCan = std::move(can);
}

void PKCS11Slot::parentClearCan(PKCS11Card& parent) noexcept
{
    parent.cachedCan.clear();
}

unsigned long PKCS11Slot::parentEstablishPACE(PKCS11Card& parent)
{
    return parent.establishPACE();
}

} // namespace LibreSCRS::Pkcs11::Internal
