// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <LibreSCRS/CancelToken.h>

#include <gtest/gtest.h>

#include <atomic>
#include <thread>

using LibreSCRS::CancelSource;
using LibreSCRS::CancelToken;

TEST(CancelTokenTest, DefaultTokenIsNeverCancellable)
{
    CancelToken token;
    EXPECT_FALSE(token.isCancellable());
    EXPECT_FALSE(token.isCancelled());
}

TEST(CancelTokenTest, SourceCreatesCancellableToken)
{
    CancelSource source;
    CancelToken token = source.token();
    EXPECT_TRUE(token.isCancellable());
    EXPECT_FALSE(token.isCancelled());
}

TEST(CancelTokenTest, RequestCancelPropagatesToToken)
{
    CancelSource source;
    CancelToken token = source.token();

    EXPECT_TRUE(source.requestCancel());
    EXPECT_TRUE(source.isCancelled());
    EXPECT_TRUE(token.isCancelled());
}

TEST(CancelTokenTest, RequestCancelIsIdempotent)
{
    CancelSource source;
    EXPECT_TRUE(source.requestCancel());
    EXPECT_FALSE(source.requestCancel());
    EXPECT_FALSE(source.requestCancel());
}

TEST(CancelTokenTest, RegisterCallbackFiresOnCancel)
{
    CancelSource source;
    CancelToken token = source.token();

    std::atomic<int> fired{0};
    auto reg = token.registerCallback([&fired] { fired.fetch_add(1); });

    EXPECT_EQ(fired.load(), 0);
    source.requestCancel();
    EXPECT_EQ(fired.load(), 1);
}

TEST(CancelTokenTest, RegistrationDtorUnregistersBeforeCancel)
{
    CancelSource source;
    CancelToken token = source.token();

    std::atomic<int> fired{0};
    {
        auto reg = token.registerCallback([&fired] { fired.fetch_add(1); });
    } // reg destroyed before cancel

    source.requestCancel();
    EXPECT_EQ(fired.load(), 0);
}

TEST(CancelTokenTest, MultipleTokensShareState)
{
    CancelSource source;
    CancelToken t1 = source.token();
    CancelToken t2 = source.token();
    CancelToken t3 = t1; // copy

    source.requestCancel();
    EXPECT_TRUE(t1.isCancelled());
    EXPECT_TRUE(t2.isCancelled());
    EXPECT_TRUE(t3.isCancelled());
}

TEST(CancelTokenTest, NeverCancellableRegisterReturnsEmptyRegistration)
{
    CancelToken token; // default = never-cancellable
    std::atomic<int> fired{0};

    auto reg = token.registerCallback([&fired] { fired.fetch_add(1); });
    // No source to cancel; we just verify nothing crashes and reg dies cleanly.
    (void)reg;
    EXPECT_EQ(fired.load(), 0);
}

#include "../lib/LibreSCRS/detail/cancel_bridge.h" // internal-only header

TEST(CancelTokenBridgeTest, NeverCancellableTokenYieldsNeverStoppableStopToken)
{
    LibreSCRS::CancelToken token;
    std::stop_token st = LibreSCRS::detail::stopTokenFrom(token);
    EXPECT_FALSE(st.stop_possible());
}

TEST(CancelTokenBridgeTest, CancellableTokenYieldsValidStopToken)
{
    LibreSCRS::CancelSource source;
    LibreSCRS::CancelToken token = source.token();
    std::stop_token st = LibreSCRS::detail::stopTokenFrom(token);

    EXPECT_TRUE(st.stop_possible());
    EXPECT_FALSE(st.stop_requested());

    source.requestCancel();
    EXPECT_TRUE(st.stop_requested());
}
