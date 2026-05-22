// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <LibreSCRS/SmartCard/CardSession.h>
#include <LibreSCRS/SmartCard/detail/CardSessionInjection.h>
#include <LibreSCRS_internal/SmartCard/SessionPresence.h>
#include <LibreSCRS_internal/SmartCard/SmartCardServices.h>

#include <gtest/gtest.h>

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

} // namespace
