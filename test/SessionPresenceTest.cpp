// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <LibreSCRS/SmartCard/CardSession.h>
#include <LibreSCRS/SmartCard/detail/CardSessionInjection.h>
#include <LibreSCRS_internal/SmartCard/SessionPresence.h>
#include <LibreSCRS_internal/SmartCard/SmartCardServices.h>

#include <gtest/gtest.h>

#include <optional>
#include <utility>

namespace {

using LibreSCRS::SmartCard::CardSession;
using LibreSCRS::SmartCard::Internal::ensureSessionPresenceInitialised;
using LibreSCRS::SmartCard::Internal::SessionPresence;
using LibreSCRS::SmartCard::Internal::sessionPresence;
using LibreSCRS::SmartCard::Internal::shutdownSessionPresenceForTest;

class SessionPresenceTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        ensureSessionPresenceInitialised();
        shutdownSessionPresenceForTest();
    }
};

TEST_F(SessionPresenceTest, EmptyAfterClear)
{
    EXPECT_FALSE(sessionPresence().hasLiveSm("any-reader"));
    EXPECT_EQ(sessionPresence().peek("any-reader"), nullptr);
}

TEST_F(SessionPresenceTest, InsertedSessionIsVisible)
{
    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("test-reader");
    ASSERT_NE(session, nullptr);

    auto reg = sessionPresence().insert("test-reader", session);
    auto found = sessionPresence().peek("test-reader");
    EXPECT_EQ(found, session);
}

TEST_F(SessionPresenceTest, RegistrationDestructionUnregisters)
{
    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("destruct-reader");
    {
        auto reg = sessionPresence().insert("destruct-reader", session);
        EXPECT_NE(sessionPresence().peek("destruct-reader"), nullptr);
    }
    EXPECT_EQ(sessionPresence().peek("destruct-reader"), nullptr);
}

TEST_F(SessionPresenceTest, WeakPtrDoesNotExtendLifetime)
{
    SessionPresence::Registration reg;
    {
        auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("weak-reader");
        reg = sessionPresence().insert("weak-reader", session);
        EXPECT_NE(sessionPresence().peek("weak-reader"), nullptr);
    }
    // Session is destroyed; weak_ptr is expired. peek must return null.
    EXPECT_EQ(sessionPresence().peek("weak-reader"), nullptr);
}

TEST_F(SessionPresenceTest, HasLiveSmReflectsCardSessionState)
{
    // Detached session has no live SM channel; hasLiveSm should be false.
    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("sm-reader");
    auto reg = sessionPresence().insert("sm-reader", session);

    EXPECT_FALSE(sessionPresence().hasLiveSm("sm-reader"));
}

// Two sessions naming one reader is not prevented anywhere, and the registry
// holds one entry per name. What must not happen is one session's registration
// deleting the other's entry: the only consumer of this registry reads it to
// decide whether it may bind the card, so a false "nothing live here" is a bound
// card and, on a card behind a secure channel, a dead tunnel.
TEST_F(SessionPresenceTest, ARegistrationRemovesOnlyItsOwnEntry)
{
    auto first = LibreSCRS::SmartCard::detail::makeDetachedCardSession("shared-reader");
    auto second = LibreSCRS::SmartCard::detail::makeDetachedCardSession("shared-reader");
    ASSERT_NE(first, nullptr);
    ASSERT_NE(second, nullptr);
    ASSERT_NE(first, second);

    auto firstReg = sessionPresence().insert("shared-reader", first);
    auto secondReg = sessionPresence().insert("shared-reader", second);
    ASSERT_EQ(sessionPresence().peek("shared-reader"), second);

    // The first session's registration goes away. Its entry is no longer the one
    // in the map, so it must take nothing with it.
    {
        auto doomed = std::move(firstReg);
    }
    EXPECT_EQ(sessionPresence().peek("shared-reader"), second)
        << "the older registration deleted the newer session's entry";

    // Same through move-assignment, which also removes what it is replacing.
    auto other = LibreSCRS::SmartCard::detail::makeDetachedCardSession("other-reader");
    auto otherReg = sessionPresence().insert("other-reader", other);
    otherReg = SessionPresence::Registration{};
    EXPECT_EQ(sessionPresence().peek("shared-reader"), second);
    EXPECT_EQ(sessionPresence().peek("other-reader"), nullptr);

    // And the owning registration still removes its own entry.
    {
        auto doomed = std::move(secondReg);
    }
    EXPECT_EQ(sessionPresence().peek("shared-reader"), nullptr);
}

// Re-registering the SAME session must leave it registered. The optional that
// stores the registration destroys the old one while constructing the new, and
// the old one's entry is the new one's, so the order of those two steps decides
// whether the reader ends up registered or silently empty.
TEST_F(SessionPresenceTest, ReRegisteringOneSessionLeavesItRegistered)
{
    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("re-reader");
    std::optional<SessionPresence::Registration> held;

    held.emplace(sessionPresence().insert("re-reader", session));
    ASSERT_EQ(sessionPresence().peek("re-reader"), session);

    // The shape every caller in CardSession uses: drop the old registration
    // first, then take the new one.
    held.reset();
    held.emplace(sessionPresence().insert("re-reader", session));
    EXPECT_EQ(sessionPresence().peek("re-reader"), session) << "re-registration left the reader unregistered";

    held.reset();
    EXPECT_EQ(sessionPresence().peek("re-reader"), nullptr);
}

// The trap the shape above avoids, stated so it is not rediscovered. emplace
// destroys the registration it is replacing AFTER the argument has already
// written the new entry, and the old registration owns exactly that entry -- so
// it erases what was just registered. Every caller in CardSession therefore
// resets first.
TEST_F(SessionPresenceTest, EmplacingOverALiveRegistrationLeavesTheReaderUnregistered)
{
    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("trap-reader");
    std::optional<SessionPresence::Registration> held;

    held.emplace(sessionPresence().insert("trap-reader", session));
    ASSERT_EQ(sessionPresence().peek("trap-reader"), session);

    held.emplace(sessionPresence().insert("trap-reader", session));
    EXPECT_EQ(sessionPresence().peek("trap-reader"), nullptr)
        << "if this now holds the entry, emplace-over-live is safe and the reset calls "
           "in CardSession can go";
}

} // namespace
