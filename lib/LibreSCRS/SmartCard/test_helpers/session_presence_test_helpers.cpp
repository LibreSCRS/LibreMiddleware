// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

/// @file
/// @brief Test-only seam for the process-local @ref
///        LibreSCRS::SmartCard::Internal::SessionPresence registry.
///
/// This translation unit is compiled into the build-tree-only
/// @ref LibreSCRS_SmartCard_TestHelpers archive — it is never installed and
/// never linked into the production @c libLibreSCRS_SmartCard shared library.
/// Production builds therefore never carry @ref
/// LibreSCRS::SmartCard::Internal::shutdownSessionPresenceForTest in their
/// dynamic export set, so the dlsym-reachable footgun is gone while the test
/// fixtures that need a clean registry between cases link the archive directly.
///
/// The body reaches the registry through the exported accessors
/// (@ref ensureSessionPresenceInitialised / @ref sessionPresence) rather than
/// the file-local anonymous-namespace statics that hold it, since those live
/// in a different translation unit (@c SmartCardServices.cpp).

#include <LibreSCRS_internal/SmartCard/SessionPresence.h>
#include <LibreSCRS_internal/SmartCard/SmartCardServices.h>

namespace LibreSCRS::SmartCard::Internal {

void shutdownSessionPresenceForTest() noexcept
{
    // Idempotent ensure guarantees a non-null instance; clearing a freshly
    // initialised (empty) registry is a no-op, matching the original
    // null-guarded behaviour.
    ensureSessionPresenceInitialised();
    sessionPresence().clearAll();
}

} // namespace LibreSCRS::SmartCard::Internal
