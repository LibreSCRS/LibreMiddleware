// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include "docp_parser.h"
#include "fixtures/appletsuitegen1_docp_20260721.h"
#include <gtest/gtest.h>

using LibreSCRS::pkcs15::parseDocpCounters;
using namespace LibreSCRS::test::fixtures;

TEST(DocpParser, PukCarriesTriesUsesAndResets)
{
    const auto c = parseDocpCounters(kAppletSuiteGen1PukDocp);
    EXPECT_EQ(c.retriesMax, 5);
    EXPECT_EQ(c.retriesLeft, 5);
    EXPECT_EQ(c.usesMax, 20);
    EXPECT_EQ(c.usesLeft, 16);
    EXPECT_EQ(c.unblocksLeft, 5);
}

TEST(DocpParser, UserPinCarriesOnlyTries)
{
    const auto c = parseDocpCounters(kAppletSuiteGen1UserPinDocp);
    EXPECT_EQ(c.retriesMax, 3);
    EXPECT_EQ(c.retriesLeft, 3);
    EXPECT_FALSE(c.usesMax.has_value());
    EXPECT_FALSE(c.usesLeft.has_value());
    EXPECT_FALSE(c.unblocksLeft.has_value());
}

TEST(DocpParser, EmptyOrTruncatedYieldsNothing)
{
    EXPECT_FALSE(parseDocpCounters({}).retriesMax.has_value());
    // A 62 template header with no content.
    const std::array<std::uint8_t, 4> stub = {0x70, 0x02, 0x62, 0x00};
    const auto c = parseDocpCounters(stub);
    EXPECT_FALSE(c.retriesMax.has_value());
    EXPECT_FALSE(c.usesMax.has_value());
}

TEST(DocpParser, IgnoresCounterByteValuesInsideAccessRules)
{
    // The 86/87 access-rule values contain 0x05/0xFF bytes; the walker
    // must not read them as counter tags. PUK fixture exercises this
    // (86 value has 0x05); assert the parse still equals the true tags.
    const auto c = parseDocpCounters(kAppletSuiteGen1PukDocp);
    EXPECT_EQ(c.usesMax, 20); // not a stray 0x05 from an 86 value
}
