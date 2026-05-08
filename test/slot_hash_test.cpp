// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <gtest/gtest.h>
#include <pkcs11/internal/slot_hash.h>

#include <array>
#include <cstring>
#include <string>
#include <string_view>

using librescrs::pkcs11::internal::fnv1a32;
using librescrs::pkcs11::internal::formatSlotDescription;
using librescrs::pkcs11::internal::parseSlotHash;
using librescrs::pkcs11::internal::toHex8;

TEST(SlotHash, Fnv1aCanonicalVectors)
{
    EXPECT_EQ(fnv1a32(""), 0x811c9dc5u);
    EXPECT_EQ(fnv1a32("a"), 0xe40c292cu);
    EXPECT_EQ(fnv1a32("foobar"), 0xbf9cf968u);
}

TEST(SlotHash, Fnv1aDistinguishesSimilarReaderNames)
{
    const std::string a = "HID Global OMNIKEY 5422 Smartcard Reader [OMNIKEY 5422 Smartcard Reader] (IM0O2C00NF10456904) 02 00";
    const std::string b = "HID Global OMNIKEY 5422 Smartcard Reader [OMNIKEY 5422 Smartcard Reader] (IM0O2C00NF10456904) 02 01";
    EXPECT_NE(fnv1a32(a), fnv1a32(b));
}

TEST(SlotHash, ToHex8AlwaysEightChars)
{
    auto h = toHex8(0x00000000u);
    EXPECT_EQ(std::string_view(h.data(), 8), "00000000");
    h = toHex8(0xdeadbeefu);
    EXPECT_EQ(std::string_view(h.data(), 8), "deadbeef");
    h = toHex8(0xffffffffu);
    EXPECT_EQ(std::string_view(h.data(), 8), "ffffffff");
}

TEST(SlotHash, FormatRoundTripsThroughParse)
{
    char buf[64];
    std::memset(buf, ' ', sizeof(buf));
    const std::string reader = "Gemalto USB Shell Token V2";
    formatSlotDescription(reader, buf);

    const std::string_view view(buf, 64);
    EXPECT_EQ(view[0], '[');
    EXPECT_EQ(view[9], ']');
    EXPECT_EQ(view[10], ' ');

    EXPECT_EQ(parseSlotHash(view), fnv1a32(reader));

    EXPECT_EQ(view.substr(11, reader.size()), reader);
}

TEST(SlotHash, FormatPreservesBlankPadding)
{
    char buf[64];
    std::memset(buf, ' ', sizeof(buf));
    formatSlotDescription("short", buf);
    for (std::size_t i = 11 + 5; i < 64; ++i)
        EXPECT_EQ(buf[i], ' ') << "non-space byte at index " << i;
}

TEST(SlotHash, FormatTruncatesLongReaderNameButKeepsHash)
{
    char buf[64];
    std::memset(buf, ' ', sizeof(buf));
    const std::string longName(200, 'X');
    formatSlotDescription(longName, buf);

    EXPECT_EQ(parseSlotHash(std::string_view(buf, 64)), fnv1a32(longName));
}

TEST(SlotHash, ParseRejectsNonBracketShape)
{
    EXPECT_EQ(parseSlotHash(""), 0u);
    EXPECT_EQ(parseSlotHash("LibreSCRS RS-eID Token             "), 0u);
    EXPECT_EQ(parseSlotHash("(deadbeef) Gemalto"), 0u);
}

TEST(SlotHash, ParseRejectsNonHexInsideBracket)
{
    EXPECT_EQ(parseSlotHash("[xxxxxxxx] reader"), 0u);
    EXPECT_EQ(parseSlotHash("[DEADBEEF] reader"), 0u); // uppercase not accepted
}

TEST(SlotHash, ParseRejectsTooShort)
{
    EXPECT_EQ(parseSlotHash("[abc]"), 0u);
}
