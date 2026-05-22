// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

/// @file
/// @brief @ref LibreSCRS::OpenSc::Pkcs11::OpenScPKCS11Provider — broadest
///        PKCS#11 fallback backed by the vendored OpenSC static archive.

#include <internal/PKCS11CardProvider.h>

#include <memory>

namespace LibreSCRS::OpenSc::Pkcs11 {

/// @brief @ref LibreSCRS::Pkcs11::Internal::PKCS11CardProvider backed by
///        the vendored OpenSC fork. Broadest fallback in the multi-PIN
///        refactor.
///
/// Probes by attempting @c sc_pkcs15_bind on the live PC/SC connection;
/// accepts any card OpenSC's emulator chain or built-in driver recognises
/// (OpenPGP, generic PKCS#15, the bundled srbeid driver, …).
///
/// @par Registration priority
/// Registered FIRST (priority 1) by the PKCS#11 library during
/// @c C_Initialize when @c LIBRESCRS_VENDOR_OPENSC is enabled. The custom
/// @c Pkcs15PKCS11Provider runs after.
///
/// @par PACE handling
/// PACE is owned internally by OpenSC's drivers (when applicable). This
/// provider does NOT expose the project's CAN-in-PIN mechanism — that path
/// is reserved for the custom PKCS#15 provider that wraps the in-tree
/// PACE/eMRTD secure-messaging surface.
///
/// @par Thread-safety
/// @ref probe is internally synchronised; concurrent calls with distinct
/// reader names yield independent card instances.
///
/// @since 4.1
class OpenScPKCS11Provider final : public LibreSCRS::Pkcs11::Internal::PKCS11CardProvider
{
public:
    /// @brief Default-construct. The probe path consults the process-local
    ///        @ref LibreSCRS::SmartCard::Internal::SessionPresence for the
    ///        cross-reader SM guard, so this provider holds no per-instance
    ///        state beyond its parent's vtable.
    /// @since 4.1
    OpenScPKCS11Provider() noexcept = default;

    ~OpenScPKCS11Provider() override = default;

    /// @copydoc LibreSCRS::Pkcs11::Internal::PKCS11CardProvider::probe
    /// @since 4.1
    [[nodiscard]] std::shared_ptr<LibreSCRS::Pkcs11::Internal::PKCS11Card>
    probe(const std::string& readerName) override;
};

} // namespace LibreSCRS::OpenSc::Pkcs11
