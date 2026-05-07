// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <LibreSCRS/Plugin/PluginTypes.h>
#include <gtest/gtest.h>

#include <cstdint>
#include <optional>
#include <vector>

using LibreSCRS::Plugin::Atr;

TEST(AtrMatching, ExactBytesMatchExactCandidate)
{
    Atr a{{0x3B, 0x9F, 0x96, 0x80}, std::nullopt};
    EXPECT_TRUE(a.matches(std::vector<std::uint8_t>{0x3B, 0x9F, 0x96, 0x80}));
}

TEST(AtrMatching, ExactBytesRejectDifferingCandidate)
{
    Atr a{{0x3B, 0x9F, 0x96, 0x80}, std::nullopt};
    EXPECT_FALSE(a.matches(std::vector<std::uint8_t>{0x3B, 0x9F, 0x96, 0x81}));
}

TEST(AtrMatching, ExactBytesRejectDifferentLength)
{
    Atr a{{0x3B, 0x9F, 0x96, 0x80}, std::nullopt};
    EXPECT_FALSE(a.matches(std::vector<std::uint8_t>{0x3B, 0x9F, 0x96}));
}

TEST(AtrMatching, MaskedBytesMatchAcrossDontCareBytes)
{
    Atr a{{0x3B, 0x9F, 0x96, 0x80, 0x01, 0xFF, 0xFF},
          std::vector<std::uint8_t>{0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00}};
    EXPECT_TRUE(a.matches(std::vector<std::uint8_t>{0x3B, 0x9F, 0x96, 0x80, 0xCA, 0xFE, 0x00}));
}

TEST(AtrMatching, MaskedBytesRejectMismatchedFixedByte)
{
    Atr a{{0x3B, 0x9F, 0x96, 0x80, 0x01, 0xFF, 0xFF},
          std::vector<std::uint8_t>{0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00}};
    EXPECT_FALSE(a.matches(std::vector<std::uint8_t>{0x3B, 0x9F, 0x96, 0x81, 0xCA, 0xFE, 0x00}));
}

TEST(AtrMatching, MaskedBytesLengthMismatchAlwaysRejected)
{
    Atr a{{0x3B, 0x9F, 0x96, 0x80}, std::vector<std::uint8_t>{0xFF, 0xFF, 0xFF, 0xFF}};
    EXPECT_FALSE(a.matches(std::vector<std::uint8_t>{0x3B, 0x9F, 0x96, 0x80, 0x00}));
}

// 4.0 hardening: pin the documented empty-pattern semantics. An empty
// pattern matches empty candidates (trivially) and rejects every
// non-empty candidate (length mismatch path).
TEST(AtrMatching, EmptyPatternMatchesEmptyCandidate)
{
    Atr a{{}, std::nullopt};
    EXPECT_TRUE(a.matches(std::vector<std::uint8_t>{}));
}

TEST(AtrMatching, EmptyPatternRejectsNonEmptyCandidate)
{
    Atr a{{}, std::nullopt};
    EXPECT_FALSE(a.matches(std::vector<std::uint8_t>{0x3B}));
}
