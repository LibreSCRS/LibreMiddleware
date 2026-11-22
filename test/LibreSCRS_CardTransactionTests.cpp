// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

/// @file
/// @brief Static-property tests for CardTransaction's move + release()
///        extension. Behavioural tests against a real PC/SC stack live in
///        the hardware-tagged integration suite; this suite only verifies
///        the type-system contract (move-only, release() noexcept,
///        isTransactionHeld() flag visible).

#include <pcsc_connection.h>

#include <gtest/gtest.h>

#include <expected>
#include <type_traits>

using LibreSCRS::SmartCard::TransportError;
using LibreSCRS::SmartCard::Internal::CardTransaction;
using LibreSCRS::SmartCard::Internal::PCSCConnection;

TEST(CardTransactionTests, IsMoveOnly)
{
    static_assert(!std::is_copy_constructible_v<CardTransaction>);
    static_assert(!std::is_copy_assignable_v<CardTransaction>);
    static_assert(std::is_move_constructible_v<CardTransaction>);
    static_assert(std::is_move_assignable_v<CardTransaction>);
    SUCCEED();
}

TEST(CardTransactionTests, ReleaseIsNoexcept)
{
    static_assert(noexcept(std::declval<CardTransaction&>().release()));
    static_assert(noexcept(std::declval<const CardTransaction&>().owns()));
    SUCCEED();
}

TEST(CardTransactionTests, PCSCConnectionExposesIsTransactionHeld)
{
    // Static probe: the accessor exists with the expected signature.
    static_assert(std::is_same_v<decltype(std::declval<const PCSCConnection&>().isTransactionHeld()), bool>);
    SUCCEED();
}

// A reader that refuses the transaction is the error begin() returns, not an
// exception out of a constructor.
TEST(CardTransactionTests, BeginFailureIsAValue)
{
    PCSCConnection conn(PCSCConnection::DetachedTag{}, "test-reader");
    conn.setDetachedTransactionFailure(SCARD_E_SHARING_VIOLATION);

    auto t = CardTransaction::begin(conn);

    ASSERT_FALSE(t);
    EXPECT_EQ(t.error().kind, TransportError::Kind::SessionRefused);
    EXPECT_FALSE(conn.isTransactionHeld());
}

TEST(CardTransactionTests, BeginSuccessHoldsAndDestructionEnds)
{
    PCSCConnection conn(PCSCConnection::DetachedTag{}, "test-reader");
    {
        auto t = CardTransaction::begin(conn);
        ASSERT_TRUE(t);
        EXPECT_TRUE(t->owns());
        EXPECT_TRUE(conn.isTransactionHeld());
    }
    EXPECT_FALSE(conn.isTransactionHeld());
}
