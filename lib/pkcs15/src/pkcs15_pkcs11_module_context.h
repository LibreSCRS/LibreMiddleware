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

namespace LibreSCRS::Pkcs15::Pkcs11 {

class AttachRegistry;

struct ModuleContext
{
    std::shared_ptr<AttachRegistry> attachRegistry;
    // Future fields: card-event subscribers, diagnostics, etc.
};

/// @brief Accessor for the module-scope ModuleContext owned by
///        @c pkcs11.cpp. Returns @c nullptr before @c C_Initialize or
///        after @c C_Finalize. The single resolution path consumed by
///        the C-linkage inject hooks in @c pkcs15_pkcs11_attach.cpp.
[[nodiscard]] ModuleContext* moduleContext() noexcept;

} // namespace LibreSCRS::Pkcs15::Pkcs11
