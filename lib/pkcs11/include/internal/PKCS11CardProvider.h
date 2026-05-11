// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

/// @file
/// @brief Provider strategy that probes a reader and constructs the
///        appropriate concrete @ref LibreSCRS::Pkcs11::Internal::PKCS11Card.

#include "PKCS11Card.h"

#include <memory>
#include <string>

namespace LibreSCRS::Pkcs11::Internal {

/// @brief Strategy interface for detecting and constructing
///        @ref PKCS11Card instances from a reader name.
///
/// One concrete provider per supported card family (CardEdge, PKCS#15,
/// PIV, …). The PKCS#11 library iterates registered providers in
/// priority order; the first whose @ref probe returns a non-null
/// pointer wins.
///
/// @par Thread-safety
/// Implementations must be safe to invoke from any thread; @ref probe
/// itself may serialise on internal state but must not require the
/// caller to hold any external lock.
///
/// @since 4.1
class PKCS11CardProvider
{
public:
    PKCS11CardProvider() = default;
    PKCS11CardProvider(const PKCS11CardProvider&) = delete;
    PKCS11CardProvider& operator=(const PKCS11CardProvider&) = delete;
    PKCS11CardProvider(PKCS11CardProvider&&) = delete;
    PKCS11CardProvider& operator=(PKCS11CardProvider&&) = delete;

    /// @brief Virtual destructor for safe deletion through this base.
    /// @since 4.1
    virtual ~PKCS11CardProvider() = default;

    /// @brief Probe @p readerName and, if recognised, return a fully
    ///        bound @ref PKCS11Card.
    /// @param readerName PC/SC reader name.
    /// @return Owning shared pointer to the constructed card on
    ///         success; @c nullptr if the card in this reader does not
    ///         match this provider's family or cannot be bound.
    /// @par Thread-safety
    /// Internally synchronised. Concurrent calls with distinct reader
    /// names are independent; concurrent calls with the same reader
    /// name return independent card instances (probing may open and
    /// close the PC/SC handle multiple times — implementations are
    /// expected to coordinate at the PC/SC layer).
    /// @since 4.1
    [[nodiscard]] virtual std::shared_ptr<PKCS11Card> probe(const std::string& readerName) = 0;
};

} // namespace LibreSCRS::Pkcs11::Internal
