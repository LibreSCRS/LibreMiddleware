// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "pkcs15_pkcs11_card.h"

#include <LibreSCRS/SmartCard/CardSession.h>
#include <LibreSCRS/SmartCard/detail/CardSessionInjection.h>

#include <internal/Crv.h>

#include <gtest/gtest.h>

#include <memory>
#include <string>

namespace LibreSCRS::Pkcs15::Pkcs11 {

// Pkcs15CardInjectBindTests exercises the new bindFromInjectedSession
// surface using detached CardSession fixtures (no PC/SC IO). The detached
// session's PCSCConnection has no live card handle, so any holder
// activation surfaces as a transport-level failure mapped to DeviceError —
// sufficient to assert that the new code path adopts the injected session
// (rather than crashing or trying to open a second handle) and propagates
// the holder's failure mode through the existing mapHolderErrorToCrv
// translator.

TEST(Pkcs15CardInjectBindTest, NullSessionReturnsArgumentsBad)
{
    auto card = std::make_shared<Pkcs15Card>(nullptr);
    auto rc = card->bindFromInjectedSession("Reader 0", nullptr);
    EXPECT_EQ(rc, LibreSCRS::Pkcs11::Internal::Crv::ArgumentsBad);
}

TEST(Pkcs15CardInjectBindTest, DetachedSessionAdoptsAndPropagatesHolderFailure)
{
    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("Reader 0");
    ASSERT_NE(session, nullptr);

    auto card = std::make_shared<Pkcs15Card>(nullptr);
    auto rc = card->bindFromInjectedSession("Reader 0", session);

    // Detached PCSCConnection rejects beginTransaction (no live card
    // handle) — activateChannelFor returns ReaderError, which the holder-
    // error mapper translates to DeviceError. The important invariant is
    // that the card adopted the session and reported a deterministic
    // numeric Crv rather than crashing or opening a new PC/SC handle.
    EXPECT_EQ(rc, LibreSCRS::Pkcs11::Internal::Crv::DeviceError);

    // Adoption: the card holds a shared reference to the same session.
    // Two refs in this test scope (local + card) plus any extra LM-
    // internal refs — assert ≥2 to keep the test robust against future
    // intermediate caches.
    EXPECT_GE(session.use_count(), 2L);
}

} // namespace LibreSCRS::Pkcs15::Pkcs11
