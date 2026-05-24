// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <gtest/gtest.h>
#include "card_protocol.h"

using namespace eidcard::protocol;

TEST(EidProtocolATR, GemaltoMatchesExpectedPrefix)
{
    // 3B FF 94 00 00 ... — known Gemalto 2014 ATR shape
    std::vector<uint8_t> atr = {0x3B, 0xFF, 0x94, 0x00, 0x00, 0xFF};
    EXPECT_TRUE(isGemaltoATR(atr));
    EXPECT_FALSE(isApolloATR(atr));
}

TEST(EidProtocolATR, ApolloMatchesExpectedPrefix)
{
    // 3B B9 18 00 ... — known Apollo 2008 ATR shape
    std::vector<uint8_t> atr = {0x3B, 0xB9, 0x18, 0x00, 0x81, 0x31};
    EXPECT_TRUE(isApolloATR(atr));
    EXPECT_FALSE(isGemaltoATR(atr));
}

TEST(EidProtocolATR, UnknownAtrMatchesNeither)
{
    std::vector<uint8_t> atr = {0x3B, 0x00, 0x00, 0x00};
    EXPECT_FALSE(isApolloATR(atr));
    EXPECT_FALSE(isGemaltoATR(atr));
}

TEST(EidProtocolATR, ShortAtrRejectedDefensively)
{
    std::vector<uint8_t> atr = {0x3B, 0xFF};
    EXPECT_FALSE(isApolloATR(atr));
    EXPECT_FALSE(isGemaltoATR(atr));

    std::vector<uint8_t> empty;
    EXPECT_FALSE(isApolloATR(empty));
    EXPECT_FALSE(isGemaltoATR(empty));
}

TEST(EidProtocolATR, GemaltoRequiresExactByteTwo)
{
    // Same prefix but byte[2]=0x95 should not match Gemalto
    std::vector<uint8_t> atr = {0x3B, 0xFF, 0x95, 0x00, 0x00};
    EXPECT_FALSE(isGemaltoATR(atr));
}

TEST(EidProtocolAids, SerianAidsAre11Bytes)
{
    EXPECT_EQ(AID_SERID.size(), 11u);
    EXPECT_EQ(AID_SERIF.size(), 11u);
    EXPECT_EQ(AID_SERRP.size(), 11u);
    // All three share the F3 81 00 00 02 prefix
    EXPECT_EQ(AID_SERID[0], 0xF3);
    EXPECT_EQ(AID_SERIF[0], 0xF3);
    EXPECT_EQ(AID_SERRP[0], 0xF3);
    // ASCII "SER" suffix differentiator
    EXPECT_EQ(AID_SERID[5], 'S');
    EXPECT_EQ(AID_SERID[6], 'E');
    EXPECT_EQ(AID_SERID[7], 'R');
}

TEST(EidProtocolConstants, ChunkSizeIsMaxShortLe)
{
    // READ BINARY chunk size should be 0xFF (255 bytes) — ISO 7816-4 short form maximum.
    EXPECT_EQ(READ_CHUNK_SIZE, 0xFF);
}
