// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <LibreSCRS_internal/SmartCard/SessionPresence.h>
#include <LibreSCRS_internal/SmartCard/SmartCardServices.h>

#include <memory>
#include <mutex>

namespace LibreSCRS::SmartCard::Internal {

namespace {

// Explicit-lifecycle process-local instance. Distinct from a Meyers
// singleton: no magic-static block-scope initialiser, no instance()
// accessor; the unique_ptr is populated through ensureSessionPresenceInitialised
// under a std::call_once and never replaced. Mirrors the @c g_module pattern
// in @c lib/pkcs11/src/pkcs11.cpp where module-scope state is wired through
// an explicit ensure/clear pair driven by @c C_Initialize and @c C_Finalize.
std::once_flag g_initFlag;
std::unique_ptr<SessionPresence> g_presence;

} // namespace

void ensureSessionPresenceInitialised() noexcept
{
    try {
        std::call_once(g_initFlag, []() { g_presence = std::make_unique<SessionPresence>(); });
    } catch (...) {
        // bad_alloc on init: leave g_presence null. The next sessionPresence()
        // call returns through a null reference (programmer error in caller
        // wiring would surface as a crash); CardSession sites defensively
        // skip registration when the accessor returns through a null pointer
        // — see CardSession::activateChannelWithSm.
    }
}

SessionPresence& sessionPresence() noexcept
{
    return *g_presence;
}

void shutdownSessionPresenceForTest() noexcept
{
    if (g_presence)
        g_presence->clearAll();
}

} // namespace LibreSCRS::SmartCard::Internal
