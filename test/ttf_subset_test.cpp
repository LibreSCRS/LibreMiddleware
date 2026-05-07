// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <gtest/gtest.h>

#include "native/liberation_sans_data.h"
#include "native/ttf_parser.h"
#include "native/ttf_subset.h"

#include <cstdint>
#include <iomanip>
#include <set>
#include <span>
#include <unordered_set>

using libresign::computeUsedGids;
using libresign::NewGid;
using libresign::OldGid;
using libresign::subsetTtf;
using libresign::TtfParser;
using libresign::TtfSubset;

namespace {
std::span<const uint8_t> bundledLiberationSans()
{
    return {LiberationSansRegular, LiberationSansRegularSize};
}
} // namespace

TEST(TtfSubsetClosure, EmptyInputYieldsOnlyNotdef)
{
    TtfParser parser(bundledLiberationSans());
    ASSERT_TRUE(parser.parse());
    auto gids = computeUsedGids(parser, {});
    EXPECT_EQ(gids.size(), 1u);
    EXPECT_EQ(*gids.begin(), OldGid{0}); // .notdef
}

TEST(TtfSubsetClosure, AsciiSet)
{
    TtfParser parser(bundledLiberationSans());
    ASSERT_TRUE(parser.parse());
    auto gids = computeUsedGids(parser, {U'H', U'i'});
    EXPECT_TRUE(gids.count(OldGid{0})); // always .notdef
    EXPECT_TRUE(gids.count(parser.gidForCodepoint(U'H')));
    EXPECT_TRUE(gids.count(parser.gidForCodepoint(U'i')));
    EXPECT_GE(gids.size(), 3u);
}

TEST(TtfSubsetClosure, CompositeDependenciesIncluded)
{
    TtfParser parser(bundledLiberationSans());
    ASSERT_TRUE(parser.parse());
    OldGid sCaronGid = parser.gidForCodepoint(U'š');
    ASSERT_NE(sCaronGid, OldGid{0});
    auto gids = computeUsedGids(parser, {U'š'});
    EXPECT_TRUE(gids.count(sCaronGid));
    // Any composite components must also be present.
    for (auto ref : parser.compositeReferences(sCaronGid)) {
        EXPECT_TRUE(gids.count(ref)) << "Composite reference GID " << ref.raw() << " missing from closure of 'š'";
    }
}

TEST(TtfSubsetClosure, UnmappedCodepointsAreIgnored)
{
    TtfParser parser(bundledLiberationSans());
    ASSERT_TRUE(parser.parse());
    auto gids = computeUsedGids(parser, {U'🙂', U'A'});
    EXPECT_TRUE(gids.count(parser.gidForCodepoint(U'A')));
    EXPECT_EQ(gids.size(), 2u); // .notdef + A; emoji silently skipped
}

TEST(TtfSubset, EmptyProducesValidTtf)
{
    auto subset = subsetTtf(bundledLiberationSans(), {});
    ASSERT_GT(subset.bytes.size(), 100u);
    // Output parses as a valid TTF.
    TtfParser roundTrip(subset.bytes);
    ASSERT_TRUE(roundTrip.parse());
    EXPECT_EQ(roundTrip.numGlyphs(), 1u); // only .notdef
    EXPECT_TRUE(subset.gidForCodepoint.empty());
    EXPECT_EQ(subset.widthForGid.size(), 1u);
}

TEST(TtfSubset, AsciiRoundTrips)
{
    auto subset = subsetTtf(bundledLiberationSans(), {U'H', U'i'});
    TtfParser roundTrip(subset.bytes);
    ASSERT_TRUE(roundTrip.parse());
    EXPECT_GE(roundTrip.numGlyphs(), 3u); // .notdef + H + i (+ any composite refs)
    // The subset's codepoint→new-GID map round-trips through the new cmap.
    NewGid hNewGid = subset.gidForCodepoint.at(U'H');
    NewGid iNewGid = subset.gidForCodepoint.at(U'i');
    // roundTrip parses the subset as if it were the source, so its
    // gidForCodepoint returns OldGid in *that* parser's space — which is
    // numerically the new-GID space we encoded. Compare raw values.
    EXPECT_EQ(roundTrip.gidForCodepoint(U'H').raw(), hNewGid.raw());
    EXPECT_EQ(roundTrip.gidForCodepoint(U'i').raw(), iNewGid.raw());
    // Widths propagate: new width for 'H' matches source 'H' width.
    TtfParser source(bundledLiberationSans());
    ASSERT_TRUE(source.parse());
    EXPECT_EQ(subset.widthForGid[hNewGid.raw()], source.advanceWidth(source.gidForCodepoint(U'H')));
}

TEST(TtfSubset, SerbianLatinAndCyrillic)
{
    std::unordered_set<char32_t> cps = {
        U'H', U'i', U'r', U'š', U'l', U' ', U'Ć', U'i', U'r', U'k',
        U'o', U'v', U'i', U'ć', U'Д', U'а', U'т', U'у', U'м', U':',
    };
    auto subset = subsetTtf(bundledLiberationSans(), cps);
    TtfParser roundTrip(subset.bytes);
    ASSERT_TRUE(roundTrip.parse());
    for (auto cp : cps) {
        EXPECT_NE(roundTrip.gidForCodepoint(cp), OldGid{0}) << "Codepoint U+" << std::hex << uint32_t(cp) << " missing";
    }
}

TEST(TtfSubset, OutputSizeIsBounded)
{
    auto subset = subsetTtf(bundledLiberationSans(), {U'A', U'B', U'C'});
    // Full Liberation Sans is ~320 KB; a 3-glyph subset should be well under 20 KB.
    EXPECT_LT(subset.bytes.size(), 20u * 1024u);
    EXPECT_GT(subset.bytes.size(), 500u); // sanity lower bound
}

TEST(TtfSubset, MetricsCopiedFromSource)
{
    auto subset = subsetTtf(bundledLiberationSans(), {U'H'});
    TtfParser source(bundledLiberationSans());
    ASSERT_TRUE(source.parse());
    EXPECT_EQ(subset.unitsPerEm, source.unitsPerEm());
    EXPECT_EQ(subset.ascent, source.ascent());
    EXPECT_EQ(subset.descent, source.descent());
    EXPECT_EQ(subset.capHeight, source.capHeight());
    EXPECT_EQ(subset.stemV, source.stemV());
}

TEST(TtfSubset, Idempotent)
{
    // Subset then subset again with the same codepoints — both outputs parse
    // and report the same codepoint→GID mapping.
    std::unordered_set<char32_t> cps = {U'A', U'š', U'Ћ'};
    auto first = subsetTtf(bundledLiberationSans(), cps);
    auto second = subsetTtf(first.bytes, cps);
    for (auto cp : cps) {
        EXPECT_EQ(first.gidForCodepoint.at(cp), second.gidForCodepoint.at(cp));
    }
}

TEST(TtfSubset, CompositeGlyphReferencesAreRewritten)
{
    // 'š' is typically stored in Liberation Sans as a composite of
    // s + caron-comb. After subsetting, the 'š' glyph in the output's
    // glyf table must reference the NEW GIDs of its components, not
    // the original GIDs.
    auto subset = subsetTtf(bundledLiberationSans(), {U's', U'š'});
    TtfParser parser(subset.bytes);
    ASSERT_TRUE(parser.parse());

    // Re-parsing the subset, gidForCodepoint returns OldGid in *this*
    // parser's space — which is numerically the new-GID space.
    OldGid newSCaronGid = parser.gidForCodepoint(U'š');
    ASSERT_NE(newSCaronGid, OldGid{0});

    auto refs = parser.compositeReferences(newSCaronGid);
    if (refs.empty()) {
        // Some font versions ship 'š' as a simple glyph (no composite).
        // In that case there's nothing to verify — the test trivially passes.
        GTEST_SKIP() << "Liberation Sans 's-caron' is not a composite in this version";
    }

    // Every composite component reference must point to a glyph that
    // exists within the subset (i.e. < numGlyphs of the subset).
    for (auto ref : refs) {
        EXPECT_LT(ref.raw(), parser.numGlyphs())
            << "Composite reference " << ref.raw() << " is outside subset's glyph range "
            << "(numGlyphs=" << parser.numGlyphs() << "). Refs were not rewritten old→new.";
        // Each component must have a non-empty glyph entry in the subset.
        EXPECT_FALSE(parser.glyphSpan(ref).empty())
            << "Composite reference " << ref.raw() << " points to an empty glyph slot.";
    }

    // Negative case: original-font GID values are typically much larger
    // than the subset's tiny glyph count. If the subsetter forgot to
    // rewrite, refs would point to OOB glyph slots in the subset and
    // the EXPECT_LT above would fire.
}

TEST(TtfSubset, FileLevelChecksumIsValid)
{
    // SFNT spec: the 32-bit big-endian sum of every word in the file
    // (with checkSumAdjustment treated as written, not as zero) must
    // equal 0xB1B0AFBA. This is the OpenType integrity check.
    auto subset = subsetTtf(bundledLiberationSans(), {U'H', U'š', U'Ћ'});
    ASSERT_GT(subset.bytes.size(), 100u);
    // Pad to a 4-byte boundary mentally — but the SFNT writer already
    // 4-aligns each table, so subset.bytes.size() should be a multiple
    // of 4 anyway.
    ASSERT_EQ(subset.bytes.size() % 4, 0u);

    uint32_t sum = 0;
    for (size_t i = 0; i < subset.bytes.size(); i += 4) {
        uint32_t w = (uint32_t(subset.bytes[i + 0]) << 24) | (uint32_t(subset.bytes[i + 1]) << 16) |
                     (uint32_t(subset.bytes[i + 2]) << 8) | (uint32_t(subset.bytes[i + 3]));
        sum += w;
    }
    EXPECT_EQ(sum, 0xB1B0AFBAu) << "SFNT file-level checksum invariant violated; subsetter writer is buggy";
}
