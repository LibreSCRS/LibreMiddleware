// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware."
#endif

#pragma once

/// @file
/// @brief Per-module process-global state for librescrs-pkcs11.so.
///        Allocated by C_Initialize, destroyed by C_Finalize. The
///        single bridge between the PKCS#11 lifecycle and the C-linkage
///        inject hooks; explicit lifecycle, NOT a Meyers singleton.

#include <memory>
#include <shared_mutex>

namespace LibreSCRS::Pkcs15::Pkcs11 {

class AttachRegistry;

struct ModuleContext
{
    std::shared_ptr<AttachRegistry> attachRegistry;
    // Future fields: card-event subscribers, diagnostics, etc.
};

/// @brief Shared mutex guarding the module-scope ModuleContext lifetime.
///
/// @c C_Initialize / @c C_Finalize take this exclusively; all other PKCS#11
/// C_* entry points and the extern "C" inject hooks
/// (@c librescrs_pkcs11_attach_session / @c librescrs_pkcs11_detach_session)
/// take it shared before dereferencing the pointer returned by
/// @ref moduleContext. Defined in @c pkcs11.cpp.
extern std::shared_mutex libraryMutex;

/// @brief Accessor for the module-scope ModuleContext owned by
///        @c pkcs11.cpp. Returns @c nullptr before @c C_Initialize or
///        after @c C_Finalize. The single resolution path consumed by
///        the C-linkage inject hooks in @c pkcs15_pkcs11_attach.cpp.
///
/// @note The returned pointer is only valid while a @c std::shared_lock
///       on @ref libraryMutex is held. Callers outside @c C_Initialize /
///       @c C_Finalize MUST hold the shared lock for the entire span in
///       which they dereference the result; otherwise @c C_Finalize on a
///       concurrent thread may free the @c ModuleContext underneath.
[[nodiscard]] ModuleContext* moduleContext() noexcept;

} // namespace LibreSCRS::Pkcs15::Pkcs11
