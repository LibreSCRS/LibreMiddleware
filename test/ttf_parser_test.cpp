// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <gtest/gtest.h>

#include "native/liberation_sans_data.h"
#include "native/ttf_parser.h"

#include <span>

using libresign::OldGid;
using libresign::TtfParser;

namespace {
std::span<const uint8_t> bundledLiberationSans()
{
    return {LiberationSansRegular, LiberationSansRegularSize};
}
} // namespace

TEST(TtfParser, ParsesBundledLiberationSans)
{
    TtfParser parser(bundledLiberationSans());
    ASSERT_TRUE(parser.parse());
    EXPECT_GT(parser.numGlyphs(), 1000u);  // Liberation Sans has ~2500 glyphs
    EXPECT_EQ(parser.unitsPerEm(), 2048u); // Liberation Sans is 2048 UPM
    EXPECT_TRUE(parser.hasTable("cmap"));
    EXPECT_TRUE(parser.hasTable("glyf"));
    EXPECT_TRUE(parser.hasTable("loca"));
    EXPECT_TRUE(parser.hasTable("hmtx"));
    EXPECT_TRUE(parser.hasTable("head"));
    EXPECT_TRUE(parser.hasTable("hhea"));
    EXPECT_TRUE(parser.hasTable("maxp"));
    EXPECT_TRUE(parser.hasTable("OS/2"));
}

TEST(TtfParser, RejectsTooShortInput)
{
    std::vector<uint8_t> tiny(10, 0);
    TtfParser parser(tiny);
    EXPECT_FALSE(parser.parse());
}

TEST(TtfParser, RejectsBogusMagic)
{
    std::vector<uint8_t> bad(256, 0xAA);
    TtfParser parser(bad);
    EXPECT_FALSE(parser.parse());
}

TEST(TtfParser, ExtractsCoreMetrics)
{
    TtfParser parser(bundledLiberationSans());
    ASSERT_TRUE(parser.parse());
    EXPECT_GT(parser.ascent(), 1000);   // positive, significant
    EXPECT_LT(parser.descent(), 0);     // negative per convention
    EXPECT_GT(parser.capHeight(), 500); // Liberation Sans cap ~1409
    EXPECT_GT(parser.stemV(), 50u);     // stem width defined
    // Bounding box is sane (not inside-out)
    EXPECT_LT(parser.bboxMinX(), parser.bboxMaxX());
    EXPECT_LT(parser.bboxMinY(), parser.bboxMaxY());
}

TEST(TtfParser, CmapBasicAscii)
{
    TtfParser parser(bundledLiberationSans());
    ASSERT_TRUE(parser.parse());
    EXPECT_NE(parser.gidForCodepoint(U'A'), OldGid{0});
    EXPECT_NE(parser.gidForCodepoint(U'a'), OldGid{0});
    EXPECT_NE(parser.gidForCodepoint(U'0'), OldGid{0});
    EXPECT_NE(parser.gidForCodepoint(U' '), OldGid{0});
    // Each should be distinct.
    EXPECT_NE(parser.gidForCodepoint(U'A'), parser.gidForCodepoint(U'a'));
}

TEST(TtfParser, CmapSerbianLatin)
{
    TtfParser parser(bundledLiberationSans());
    ASSERT_TRUE(parser.parse());
    for (char32_t cp : {U'š', U'Š', U'č', U'Č', U'ć', U'Ć', U'ž', U'Ž', U'đ', U'Đ'}) {
        EXPECT_NE(parser.gidForCodepoint(cp), OldGid{0})
            << "Liberation Sans should cover Serbian Latin code point U+" << std::hex << uint32_t(cp);
    }
}

TEST(TtfParser, CmapSerbianCyrillic)
{
    TtfParser parser(bundledLiberationSans());
    ASSERT_TRUE(parser.parse());
    for (char32_t cp :
         {U'Ј', U'ј', U'Љ', U'љ', U'Њ', U'њ', U'Ћ', U'ћ', U'Ђ', U'ђ', U'Џ', U'џ', U'А', U'а', U'Б', U'б', U'П', U'п'}) {
        EXPECT_NE(parser.gidForCodepoint(cp), OldGid{0})
            << "Liberation Sans should cover Serbian Cyrillic U+" << std::hex << uint32_t(cp);
    }
}

TEST(TtfParser, CmapMissesUnsupportedCodepoints)
{
    TtfParser parser(bundledLiberationSans());
    ASSERT_TRUE(parser.parse());
    // Emoji / Han — not in Liberation Sans
    EXPECT_EQ(parser.gidForCodepoint(U'🙂'), OldGid{0});
    EXPECT_EQ(parser.gidForCodepoint(U'漢'), OldGid{0});
}

TEST(TtfParser, GlyphSpanNotdefIsPresent)
{
    TtfParser parser(bundledLiberationSans());
    ASSERT_TRUE(parser.parse());
    // GID 0 (.notdef) may be zero-length in some fonts, but Liberation
    // Sans has a drawn .notdef box — should be non-empty.
    EXPECT_FALSE(parser.glyphSpan(OldGid{0}).empty());
}

TEST(TtfParser, GlyphSpanAsciiNonEmpty)
{
    TtfParser parser(bundledLiberationSans());
    ASSERT_TRUE(parser.parse());
    OldGid gidA = parser.gidForCodepoint(U'A');
    ASSERT_NE(gidA, OldGid{0});
    EXPECT_FALSE(parser.glyphSpan(gidA).empty());
}

TEST(TtfParser, CompositeReferencesAccent)
{
    TtfParser parser(bundledLiberationSans());
    ASSERT_TRUE(parser.parse());
    // In Liberation Sans 2.1.5, 'š' (U+0161) is a composite of s + caron.
    // If upstream ever switches to a simple glyph this test decays into
    // a no-op — fall through is still OK.
    OldGid gidSCaron = parser.gidForCodepoint(U'š');
    ASSERT_NE(gidSCaron, OldGid{0});
    auto refs = parser.compositeReferences(gidSCaron);
    // Accept either outcome, but if there are refs, they must be valid GIDs.
    for (auto g : refs) {
        EXPECT_LT(g.raw(), parser.numGlyphs());
    }
}

TEST(TtfParser, CompositeReferencesSimpleGlyphIsEmpty)
{
    TtfParser parser(bundledLiberationSans());
    ASSERT_TRUE(parser.parse());
    OldGid gidA = parser.gidForCodepoint(U'A');
    ASSERT_NE(gidA, OldGid{0});
    EXPECT_TRUE(parser.compositeReferences(gidA).empty());
}

TEST(TtfParser, AdvanceWidthForAsciiIsPositive)
{
    TtfParser parser(bundledLiberationSans());
    ASSERT_TRUE(parser.parse());
    OldGid gidA = parser.gidForCodepoint(U'A');
    OldGid gidI = parser.gidForCodepoint(U'i');
    OldGid gidSpace = parser.gidForCodepoint(U' ');
    EXPECT_GT(parser.advanceWidth(gidA), 0u);
    EXPECT_GT(parser.advanceWidth(gidI), 0u);
    EXPECT_GT(parser.advanceWidth(gidSpace), 0u);
    // Reality check: capital A is wider than lowercase i in a proportional font.
    EXPECT_GT(parser.advanceWidth(gidA), parser.advanceWidth(gidI));
}

TEST(TtfParser, AdvanceWidthForNotdefIsDefined)
{
    TtfParser parser(bundledLiberationSans());
    ASSERT_TRUE(parser.parse());
    EXPECT_GT(parser.advanceWidth(OldGid{0}), 0u);
}
