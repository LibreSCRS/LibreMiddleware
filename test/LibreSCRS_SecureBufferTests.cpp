// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <LibreSCRS/Secure/Buffer.h>

#include <gtest/gtest.h>

#include <cstring>
#include <string_view>

using LibreSCRS::Secure::Buffer;

TEST(SecureBufferTest, DefaultConstructIsEmpty)
{
    Buffer b;
    EXPECT_EQ(b.size(), 0u);
    EXPECT_EQ(b.data(), nullptr);
}

TEST(SecureBufferTest, SizedConstructFillsWithZero)
{
    Buffer b(16);
    ASSERT_EQ(b.size(), 16u);
    ASSERT_NE(b.data(), nullptr);
    for (size_t i = 0; i < 16; ++i)
        EXPECT_EQ(b.data()[i], 0);
}

TEST(SecureBufferTest, SizedConstructFillsWithValue)
{
    Buffer b(8, 0xAB);
    ASSERT_EQ(b.size(), 8u);
    for (size_t i = 0; i < 8; ++i)
        EXPECT_EQ(b.data()[i], 0xAB);
}

TEST(SecureBufferTest, StringViewConstructCopiesBytes)
{
    std::string_view sv = "abc123";
    Buffer b(sv);
    ASSERT_EQ(b.size(), 6u);
    EXPECT_EQ(std::memcmp(b.data(), sv.data(), 6), 0);
}

TEST(SecureBufferTest, MoveConstructTransfersOwnership)
{
    Buffer src(4, 0xFF);
    const uint8_t* srcData = src.data();
    Buffer dst(std::move(src));
    EXPECT_EQ(dst.size(), 4u);
    EXPECT_EQ(dst.data(), srcData);
    EXPECT_EQ(src.size(), 0u);
    EXPECT_EQ(src.data(), nullptr);
}

TEST(SecureBufferTest, MoveAssignTransfersOwnership)
{
    Buffer src(4, 0xEE);
    Buffer dst(1);
    dst = std::move(src);
    EXPECT_EQ(dst.size(), 4u);
    EXPECT_EQ(dst.data()[0], 0xEE);
    EXPECT_EQ(src.size(), 0u);
}

TEST(SecureBufferTest, EqualityIdenticalContents)
{
    Buffer a(4, 0xAB);
    Buffer b(4, 0xAB);
    EXPECT_TRUE(a == b);
}

TEST(SecureBufferTest, EqualityDifferentSize)
{
    Buffer a(4, 0xAB);
    Buffer b(5, 0xAB);
    EXPECT_FALSE(a == b);
}

TEST(SecureBufferTest, EqualityDifferentBytes)
{
    Buffer a(4, 0xAB);
    Buffer b(4, 0xCD);
    EXPECT_FALSE(a == b);
}

TEST(SecureBufferTest, EqualityBothEmpty)
{
    Buffer a;
    Buffer b;
    EXPECT_TRUE(a == b);
}
