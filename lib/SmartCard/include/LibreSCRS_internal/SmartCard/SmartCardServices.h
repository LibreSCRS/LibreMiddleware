// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "LibreSCRS_internal/SmartCard/SmartCardServices.h is internal to LibreMiddleware."
#endif

#pragma once

#include <LibreSCRS/Export.h>

namespace LibreSCRS::SmartCard::Internal {

class SessionPresence;

/// @brief Returns the process-local SessionPresence. Behaviour is undefined
///        if @ref ensureSessionPresenceInitialised has not been called first.
///        Callers in CardSession invoke @c ensure... before reaching here.
///
/// Annotated @ref LIBRESCRS_PUBLIC_API so cross-`.so` callers (plugins,
/// libresign, the in-tree PKCS#11 module) resolve against the one SHARED-LM
/// instance instead of each linking a private static-LM copy that would
/// give every `.so` its own registry (silent ODR — defeats the whole design).
[[nodiscard]] LIBRESCRS_PUBLIC_API SessionPresence& sessionPresence() noexcept;

/// @brief One-shot initialiser. Idempotent across multiple call sites.
///        Allocates the heap-owned process instance via a function-local
///        std::call_once + std::unique_ptr; reachability is gated by an
///        explicit lifecycle, NOT by Meyers magic-static semantics.
///        Mirrors the @c g_module precedent in @c lib/pkcs11/src/pkcs11.cpp.
LIBRESCRS_PUBLIC_API void ensureSessionPresenceInitialised() noexcept;

/// @brief Test-only: clear every entry in the process-local instance.
///        Production code does not call this; test fixtures use it to
///        guarantee a clean slate between cases without paying for a
///        full reinitialisation of the @c std::once_flag.
LIBRESCRS_PUBLIC_API void shutdownSessionPresenceForTest() noexcept;

} // namespace LibreSCRS::SmartCard::Internal
