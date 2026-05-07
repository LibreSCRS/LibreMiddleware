// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <LibreSCRS/SmartCard/CardSession.h>
#include <LibreSCRS/SmartCard/detail/CardSessionInjection.h>

#include <gtest/gtest.h>

#include <utility>

using LibreSCRS::SmartCard::CardSession;

TEST(CardSessionTest, OpenReturnsErrorOnBadReader)
{
    // 4.0: noexcept factory replaces the throwing constructor. A bad reader
    // name yields a populated @ref OpenError rather than an exception.
    // std::expected<CardSession, OpenError> — has_value() / error() per C++23.
    auto result = CardSession::open("No Such Reader 9999");
    ASSERT_FALSE(result.has_value());
    const auto& err = result.error();
    EXPECT_TRUE(err.diagnosticDetail.has_value());
    EXPECT_FALSE(err.userMessage.key.empty()); // 4.0: userMessage mandatory
}

TEST(CardSessionTest, DefaultMoveSemantics)
{
    // CardSession is move-only; assert via type traits
    static_assert(!std::is_copy_constructible_v<CardSession>);
    static_assert(!std::is_copy_assignable_v<CardSession>);
    static_assert(std::is_move_constructible_v<CardSession>);
    static_assert(std::is_move_assignable_v<CardSession>);
    SUCCEED();
}

// A moved-from CardSession holds no Impl and must not be used.
// This aligns with sibling pimpl-backed classes (SigningService,
// SigningRequest). Verify the move-destination retains full state; the
// moved-from source is out-of-contract for any accessor (UB) and not tested.

TEST(CardSessionMove, MoveDestinationPreservesReaderName)
{
    auto src = LibreSCRS::SmartCard::detail::makeDetachedCardSession("TestReader");
    CardSession moved{std::move(*src)};
    EXPECT_EQ(moved.readerName(), "TestReader");
    EXPECT_TRUE(moved.isConnected());
}
