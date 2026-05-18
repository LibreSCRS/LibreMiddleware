// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <internal/SessionRegistry.h>

#include <LibreSCRS/SmartCard/CardSession.h>
#include <LibreSCRS/SmartCard/detail/CardSessionInjection.h>

#include <gtest/gtest.h>

#include <thread>

namespace LibreSCRS::Pkcs11::Internal {

namespace {

std::shared_ptr<LibreSCRS::SmartCard::CardSession> makeFakeSession(const std::string& reader)
{
    return LibreSCRS::SmartCard::detail::makeDetachedCardSession(reader);
}

} // namespace

TEST(SessionRegistryTest, PutThenPeekReturnsSamePointerAndKeepsEntry)
{
    SessionRegistry r;
    auto s = makeFakeSession("Reader 0");
    r.put("Reader 0", s);
    auto peeked = r.peek("Reader 0");
    EXPECT_EQ(peeked.get(), s.get());
    // peek is non-consuming — second peek must return the same pointer.
    EXPECT_EQ(r.peek("Reader 0").get(), s.get());
    EXPECT_TRUE(r.contains("Reader 0"));
}

TEST(SessionRegistryTest, PeekOnEmptyReturnsNullptr)
{
    SessionRegistry r;
    EXPECT_EQ(r.peek("Reader 0"), nullptr);
    EXPECT_FALSE(r.contains("Reader 0"));
}

TEST(SessionRegistryTest, ReplaceOldEntryDroppedNewWins)
{
    SessionRegistry r;
    auto s1 = makeFakeSession("Reader 0");
    auto s2 = makeFakeSession("Reader 0");
    r.put("Reader 0", s1);
    r.put("Reader 0", s2);
    auto peeked = r.peek("Reader 0");
    EXPECT_EQ(peeked.get(), s2.get());
}

TEST(SessionRegistryTest, RemoveDropsEntry)
{
    SessionRegistry r;
    auto s = makeFakeSession("Reader 0");
    r.put("Reader 0", s);
    EXPECT_TRUE(r.contains("Reader 0"));
    r.remove("Reader 0");
    EXPECT_FALSE(r.contains("Reader 0"));
    EXPECT_EQ(r.peek("Reader 0"), nullptr);
}

TEST(SessionRegistryTest, ClearAllRemovesEverything)
{
    SessionRegistry r;
    r.put("R0", makeFakeSession("R0"));
    r.put("R1", makeFakeSession("R1"));
    r.clearAll();
    EXPECT_EQ(r.peek("R0"), nullptr);
    EXPECT_EQ(r.peek("R1"), nullptr);
}

TEST(SessionRegistryTest, RemoveNonexistentNoOp)
{
    SessionRegistry r;
    r.remove("missing"); // must not throw
    SUCCEED();
}

TEST(SessionRegistryTest, PeekedRefSurvivesConcurrentRemove)
{
    SessionRegistry r;
    auto s = makeFakeSession("R0");
    r.put("R0", s);
    auto peeked = r.peek("R0");
    ASSERT_NE(peeked, nullptr);
    // Concurrent remove must not invalidate the peeked ref: peek
    // returns an independent shared_ptr copy.
    r.remove("R0");
    EXPECT_NE(peeked, nullptr);
    EXPECT_FALSE(r.contains("R0"));
}

TEST(SessionRegistryTest, ConcurrentPutFromTwoThreadsNoDataRace)
{
    SessionRegistry r;
    constexpr int kIters = 1000;
    std::thread t1([&] {
        for (int i = 0; i < kIters; ++i)
            r.put("R0", makeFakeSession("R0"));
    });
    std::thread t2([&] {
        for (int i = 0; i < kIters; ++i)
            r.put("R1", makeFakeSession("R1"));
    });
    t1.join();
    t2.join();
    EXPECT_NE(r.peek("R0"), nullptr);
    EXPECT_NE(r.peek("R1"), nullptr);
}

} // namespace LibreSCRS::Pkcs11::Internal
