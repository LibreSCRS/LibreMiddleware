// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "attach_registry.h"

#include <LibreSCRS/SmartCard/CardSession.h>
#include <LibreSCRS/SmartCard/detail/CardSessionInjection.h>

#include <gtest/gtest.h>

#include <thread>

namespace LibreSCRS::Pkcs15::Pkcs11 {

namespace {

std::shared_ptr<LibreSCRS::SmartCard::CardSession> makeFakeSession(const std::string& reader)
{
    return LibreSCRS::SmartCard::detail::makeDetachedCardSession(reader);
}

} // namespace

TEST(AttachRegistryTest, PutThenAdoptReturnsSamePointerAndRemovesEntry)
{
    AttachRegistry r;
    auto s = makeFakeSession("Reader 0");
    r.put("Reader 0", s);
    auto adopted = r.tryAdopt("Reader 0");
    EXPECT_EQ(adopted.get(), s.get());
    EXPECT_EQ(r.tryAdopt("Reader 0"), nullptr); // entry consumed
}

TEST(AttachRegistryTest, AdoptOnEmptyReturnsNullptr)
{
    AttachRegistry r;
    EXPECT_EQ(r.tryAdopt("Reader 0"), nullptr);
}

TEST(AttachRegistryTest, ReplaceOldEntryDroppedNewWins)
{
    AttachRegistry r;
    auto s1 = makeFakeSession("Reader 0");
    auto s2 = makeFakeSession("Reader 0");
    r.put("Reader 0", s1);
    r.put("Reader 0", s2);
    auto adopted = r.tryAdopt("Reader 0");
    EXPECT_EQ(adopted.get(), s2.get());
}

TEST(AttachRegistryTest, ClearAllRemovesEverything)
{
    AttachRegistry r;
    r.put("R0", makeFakeSession("R0"));
    r.put("R1", makeFakeSession("R1"));
    r.clearAll();
    EXPECT_EQ(r.tryAdopt("R0"), nullptr);
    EXPECT_EQ(r.tryAdopt("R1"), nullptr);
}

TEST(AttachRegistryTest, RemoveNonexistentNoOp)
{
    AttachRegistry r;
    r.remove("missing"); // must not throw
    SUCCEED();
}

TEST(AttachRegistryTest, ConcurrentPutFromTwoThreadsNoDataRace)
{
    AttachRegistry r;
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
    EXPECT_NE(r.tryAdopt("R0"), nullptr);
    EXPECT_NE(r.tryAdopt("R1"), nullptr);
}

} // namespace LibreSCRS::Pkcs15::Pkcs11
