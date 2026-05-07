// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <LibreSCRS/LocalizedText.h>

#include <gtest/gtest.h>

#include <chrono>
#include <cstdint>
#include <string>
#include <vector>

using LibreSCRS::Count;
using LibreSCRS::LocalizedText;
using LibreSCRS::Placeholder;

TEST(LocalizedTextInterpolate, ReplacesNamedTokens)
{
    auto t = LocalizedText{
        .key = "test.greeting",
        .defaultText = "Hello {name}, you have {count} messages.",
        .placeholders =
            {
                {.name = "name", .value = std::string{"Alice"}},
                {.name = "count", .value = Count{3}},
            },
    };
    EXPECT_EQ(t.interpolate(t.defaultText), "Hello Alice, you have 3 messages.");
}

TEST(LocalizedTextInterpolate, EscapesDoubleBrace)
{
    auto t = LocalizedText{
        .key = "test.literal",
        .defaultText = "{{literal}} {x}",
        .placeholders = {{.name = "x", .value = std::string{"y"}}},
    };
    EXPECT_EQ(t.interpolate(t.defaultText), "{literal} y");
}

TEST(LocalizedTextInterpolate, LeavesUnmatchedTokenIntact)
{
    auto t = LocalizedText{
        .key = "test.partial",
        .defaultText = "{x} {missing}",
        .placeholders = {{.name = "x", .value = std::string{"hi"}}},
    };
    EXPECT_EQ(t.interpolate(t.defaultText), "hi {missing}");
}

TEST(LocalizedTextInterpolate, AppliesToConsumerFormat)
{
    auto t = LocalizedText{
        .key = "rs-eid.error.communication",
        .defaultText = "Failed to communicate with reader '{readerName}'.",
        .placeholders = {{.name = "readerName", .value = std::string{"Omnikey 5422"}}},
    };
    EXPECT_EQ(t.interpolate("Грешка у комуникацији са читачем '{readerName}'."),
              "Грешка у комуникацији са читачем 'Omnikey 5422'.");
}

TEST(PlaceholderFormatted, RendersString)
{
    Placeholder p{.name = "x", .value = std::string{"hello"}};
    EXPECT_EQ(p.formatted(), "hello");
}

TEST(PlaceholderFormatted, RendersInt)
{
    Placeholder p{.name = "n", .value = std::int64_t{-42}};
    EXPECT_EQ(p.formatted(), "-42");
}

TEST(PlaceholderFormatted, RendersCount)
{
    Placeholder p{.name = "n", .value = Count{3}};
    EXPECT_EQ(p.formatted(), "3");
    EXPECT_EQ(p.type(), Placeholder::Type::Count);
}

TEST(PlaceholderFormatted, RendersUInt)
{
    Placeholder p{.name = "n", .value = std::uint64_t{18446744073709551615ULL}};
    EXPECT_EQ(p.formatted(), "18446744073709551615");
}

TEST(PlaceholderFormatted, RendersHex)
{
    Placeholder p{.name = "atr", .value = std::vector<std::uint8_t>{0x3B, 0x7D, 0x95, 0x04}};
    EXPECT_EQ(p.formatted(), "3B7D9504");
}

TEST(PlaceholderFormatted, RendersBool)
{
    Placeholder pT{.name = "x", .value = true};
    Placeholder pF{.name = "x", .value = false};
    EXPECT_EQ(pT.formatted(), "true");
    EXPECT_EQ(pF.formatted(), "false");
}

TEST(PlaceholderFormatted, RendersDate)
{
    // Fixed time-point: 2026-05-04T00:00:00Z (Unix 1777852800).
    // Pinning a known UTC instant exercises the thread-safe gmtime_r/_s
    // path without depending on the host's wall clock.
    using namespace std::chrono;
    auto tp = system_clock::time_point{seconds{1777852800}};
    Placeholder p{.name = "ts", .value = tp};
    EXPECT_EQ(p.formatted(), "2026-05-04T00:00:00Z");
    EXPECT_EQ(p.type(), Placeholder::Type::Date);
}

TEST(LocalizedTextDomain, ExtractsBeforeFirstDot)
{
    auto t = LocalizedText{.key = "rs-eid.error.communication", .defaultText = "x"};
    EXPECT_EQ(t.domain(), "rs-eid");
}

TEST(LocalizedTextDomain, EmptyForKeyWithoutDot)
{
    auto t = LocalizedText{.key = "noKey", .defaultText = "x"};
    EXPECT_EQ(t.domain(), "noKey");
}
