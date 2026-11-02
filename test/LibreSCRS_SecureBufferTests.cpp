// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <LibreSCRS/Secure/Buffer.h>

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <span>
#include <string_view>

using LibreSCRS::Secure::Buffer;

TEST(SecureBufferTest, DefaultConstructIsEmpty)
{
    Buffer b;
    EXPECT_EQ(b.size(), 0u);
    EXPECT_EQ(b.data(), nullptr);
}

TEST(SecureBufferTest, SpanConstructCopiesBytes)
{
    const std::array<std::uint8_t, 4> bytes{0xDE, 0xAD, 0xBE, 0xEF};
    Buffer b{std::span<const std::uint8_t>{bytes}};
    ASSERT_EQ(b.size(), 4u);
    EXPECT_NE(b.data(), bytes.data());
    EXPECT_EQ(std::memcmp(b.data(), bytes.data(), 4), 0);
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
    Buffer src(std::string_view{"\xFF\xFF\xFF\xFF"});
    const uint8_t* srcData = src.data();
    Buffer dst(std::move(src));
    EXPECT_EQ(dst.size(), 4u);
    EXPECT_EQ(dst.data(), srcData);
    EXPECT_EQ(src.size(), 0u);
    EXPECT_EQ(src.data(), nullptr);
}

TEST(SecureBufferTest, MoveAssignTransfersOwnership)
{
    Buffer src(std::string_view{"\xEE\xEE\xEE\xEE"});
    Buffer dst(std::string_view{"x"});
    dst = std::move(src);
    EXPECT_EQ(dst.size(), 4u);
    EXPECT_EQ(dst.data()[0], 0xEE);
    EXPECT_EQ(src.size(), 0u);
}
