// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <gtest/gtest.h>

#include "native/liberation_sans_data.h"
#include "native/pdf_font.h"
#include "native/ttf_subset.h"

#include <set>
#include <sstream>
#include <string>
#include <unordered_set>

using libresign::emitPdfFontObjects;
using libresign::PdfFontObjects;
using libresign::subsetTtf;

namespace {
std::span<const uint8_t> bundledLiberationSans()
{
    return {LiberationSansRegular, LiberationSansRegularSize};
}

bool contains(std::string_view hay, std::string_view needle)
{
    return hay.find(needle) != std::string_view::npos;
}
} // namespace

TEST(PdfFont, EmitsAllSixObjects)
{
    auto subset = subsetTtf(bundledLiberationSans(), {U'H', U'i'});
    PdfFontObjects out;
    emitPdfFontObjects(subset, /*firstObjNum=*/100, out);
    // Six-object structure: each ObjNum field is set, distinct, and
    // non-zero (the dead `totalObjects` field was retired — the named
    // ObjNum fields are the structure of record).
    EXPECT_NE(out.type0ObjNum, 0u);
    EXPECT_NE(out.cidFontObjNum, 0u);
    EXPECT_NE(out.fontDescriptorObjNum, 0u);
    EXPECT_NE(out.toUnicodeObjNum, 0u);
    EXPECT_NE(out.fontFile2ObjNum, 0u);
    EXPECT_NE(out.cidSetObjNum, 0u);
    std::set<uint32_t> objs{out.type0ObjNum,     out.cidFontObjNum,   out.fontDescriptorObjNum,
                            out.toUnicodeObjNum, out.fontFile2ObjNum, out.cidSetObjNum};
    EXPECT_EQ(objs.size(), 6u);
    EXPECT_FALSE(out.type0Dict.empty());
    EXPECT_FALSE(out.cidFontDict.empty());
    EXPECT_FALSE(out.fontDescriptorDict.empty());
    EXPECT_FALSE(out.toUnicodeStream.empty());
    EXPECT_FALSE(out.fontFile2Stream.empty());
    EXPECT_FALSE(out.cidSetStream.empty());
}

TEST(PdfFont, Type0DictReferencesDescendantAndToUnicode)
{
    auto subset = subsetTtf(bundledLiberationSans(), {U'A'});
    PdfFontObjects out;
    emitPdfFontObjects(subset, 100, out);
    EXPECT_TRUE(contains(out.type0Dict, "/Type /Font"));
    EXPECT_TRUE(contains(out.type0Dict, "/Subtype /Type0"));
    EXPECT_TRUE(contains(out.type0Dict, "/Encoding /Identity-H"));
    EXPECT_TRUE(contains(out.type0Dict, "/DescendantFonts"));
    EXPECT_TRUE(contains(out.type0Dict, "/ToUnicode"));
}

TEST(PdfFont, CidFontReferencesFontDescriptor)
{
    auto subset = subsetTtf(bundledLiberationSans(), {U'A'});
    PdfFontObjects out;
    emitPdfFontObjects(subset, 100, out);
    EXPECT_TRUE(contains(out.cidFontDict, "/Subtype /CIDFontType2"));
    EXPECT_TRUE(contains(out.cidFontDict, "/CIDSystemInfo"));
    EXPECT_TRUE(contains(out.cidFontDict, "/CIDToGIDMap /Identity"));
    EXPECT_TRUE(contains(out.cidFontDict, "/FontDescriptor"));
    EXPECT_TRUE(contains(out.cidFontDict, "/W"));
}

TEST(PdfFont, FontDescriptorReferencesFontFile2)
{
    auto subset = subsetTtf(bundledLiberationSans(), {U'A'});
    PdfFontObjects out;
    emitPdfFontObjects(subset, 100, out);
    EXPECT_TRUE(contains(out.fontDescriptorDict, "/Type /FontDescriptor"));
    EXPECT_TRUE(contains(out.fontDescriptorDict, "/FontFile2"));
    EXPECT_TRUE(contains(out.fontDescriptorDict, "/FontBBox"));
    EXPECT_TRUE(contains(out.fontDescriptorDict, "/Ascent"));
    EXPECT_TRUE(contains(out.fontDescriptorDict, "/Descent"));
    EXPECT_TRUE(contains(out.fontDescriptorDict, "/Flags"));
    EXPECT_TRUE(contains(out.fontDescriptorDict, "/ItalicAngle 0"));
}

TEST(PdfFont, ToUnicodeMapsNewGidsToCodepoints)
{
    auto subset = subsetTtf(bundledLiberationSans(), {U'H', U'i'});
    PdfFontObjects out;
    emitPdfFontObjects(subset, 100, out);
    EXPECT_TRUE(contains(out.toUnicodeStream, "beginbfchar"));
    EXPECT_TRUE(contains(out.toUnicodeStream, "endbfchar"));
    EXPECT_TRUE(contains(out.toUnicodeStream, "/CIDInit /ProcSet findresource"));
    // Content should map H's new GID to U+0048 somewhere.
    char buf[32];
    std::snprintf(buf, sizeof buf, "<%04X> <0048>", subset.gidForCodepoint.at(U'H').raw());
    EXPECT_TRUE(contains(out.toUnicodeStream, buf));
}

TEST(PdfFont, FontFile2StreamIsTheSubsetBytes)
{
    auto subset = subsetTtf(bundledLiberationSans(), {U'A'});
    PdfFontObjects out;
    emitPdfFontObjects(subset, 100, out);
    EXPECT_EQ(out.fontFile2Stream, subset.bytes);
}

TEST(PdfFont, CidSetBitmapHasCorrectSize)
{
    // 5 distinct codepoints → subset has GIDs 0..N-1 where N = 5 chars + .notdef = 6
    // (subsetTtf always includes .notdef at GID 0).
    auto subset = subsetTtf(bundledLiberationSans(), {U'A', U'B', U'C', U'D', U'E'});
    PdfFontObjects out;
    emitPdfFontObjects(subset, 100, out);

    const size_t N = subset.widthForGid.size();
    const size_t expected = (N + 7) / 8;
    EXPECT_EQ(out.cidSetStream.size(), expected);
    EXPECT_GT(N, 0u); // sanity — subset must include .notdef
}

TEST(PdfFont, CidSetBitmapBitsAreMsbFirstAndDense)
{
    auto subset = subsetTtf(bundledLiberationSans(), {U'H', U'i'});
    PdfFontObjects out;
    emitPdfFontObjects(subset, 100, out);

    const size_t N = subset.widthForGid.size();
    // Verify: first N bits set MSB-first, remaining bits in last byte are 0.
    for (size_t cid = 0; cid < N; ++cid) {
        const uint8_t byte = out.cidSetStream[cid / 8];
        const uint8_t mask = static_cast<uint8_t>(0x80 >> (cid % 8));
        EXPECT_EQ(byte & mask, mask) << "CID " << cid << " not set";
    }
    // Trailing bits in last byte (if N % 8 != 0) must be 0.
    if (N % 8 != 0) {
        const uint8_t lastByte = out.cidSetStream.back();
        const uint8_t trailingMask = static_cast<uint8_t>(0xFF >> (N % 8));
        EXPECT_EQ(lastByte & trailingMask, 0) << "trailing bits set; expected 0";
    }
}

TEST(PdfFont, FontDescriptorReferencesCidSet)
{
    auto subset = subsetTtf(bundledLiberationSans(), {U'A'});
    PdfFontObjects out;
    emitPdfFontObjects(subset, 100, out);
    EXPECT_TRUE(contains(out.fontDescriptorDict, "/CIDSet"));
    EXPECT_NE(out.cidSetObjNum, 0u);
}

// ---- measureTextWidth tests (A2 from rc2 visual-signature spec) ----

TEST(PdfFont, MeasureEmpty)
{
    auto subset = subsetTtf(bundledLiberationSans(), {U'H', U'e', U'l', U'o'});
    EXPECT_FLOAT_EQ(libresign::measureTextWidth(subset, "", 12.0f), 0.0f);
}

TEST(PdfFont, MeasureAscii)
{
    // "Hello" at 12pt in Liberation Sans should produce a non-zero width
    // bounded by an obvious sanity ceiling (5 wide-glyphs at 12pt < 60).
    std::unordered_set<char32_t> cps{U'H', U'e', U'l', U'o'};
    auto subset = subsetTtf(bundledLiberationSans(), cps);
    float w = libresign::measureTextWidth(subset, "Hello", 12.0f);
    EXPECT_GT(w, 0.0f);
    EXPECT_LT(w, 60.0f);
    // Sanity: width matches a hand-rolled font-unit accumulation.
    std::uint32_t fu = 0;
    for (char32_t cp : std::u32string{U"Hello"}) {
        auto it = subset.gidForCodepoint.find(cp);
        ASSERT_NE(it, subset.gidForCodepoint.end());
        fu += subset.widthForGid[it->second.raw()];
    }
    float expected = 12.0f * static_cast<float>(fu) / static_cast<float>(subset.unitsPerEm);
    EXPECT_FLOAT_EQ(w, expected);
}

TEST(PdfFont, MeasureCyrillic)
{
    // Cyrillic ХИРШЛ — must produce a non-zero, finite width.
    std::unordered_set<char32_t> cps{U'Х', U'И', U'Р', U'Ш', U'Л'};
    auto subset = subsetTtf(bundledLiberationSans(), cps);
    // UTF-8 encoding of "ХИРШЛ".
    std::string utf8 = "\xD0\xA5\xD0\x98\xD0\xA0\xD0\xA8\xD0\x9B";
    float w = libresign::measureTextWidth(subset, utf8, 12.0f);
    EXPECT_GT(w, 0.0f);
    EXPECT_LT(w, 80.0f);
}

TEST(PdfFont, MeasureNotdefForMissingCodepoint)
{
    // Subset only knows about 'A'. Measuring text containing 'B' should
    // sum the .notdef glyph width, not zero, and not crash.
    auto subset = subsetTtf(bundledLiberationSans(), {U'A'});
    float wKnown = libresign::measureTextWidth(subset, "A", 12.0f);
    float wUnknown = libresign::measureTextWidth(subset, "B", 12.0f);
    // Both must be non-negative; the unknown path must hit .notdef rather
    // than asserting/crashing/returning negative.
    EXPECT_GT(wKnown, 0.0f);
    EXPECT_GE(wUnknown, 0.0f);
}

TEST(PdfFont, MeasureUtf8BoundaryRobust)
{
    // Truncated multi-byte sequence must not crash; measurement returns
    // some non-negative number using .notdef for the malformed prefix.
    auto subset = subsetTtf(bundledLiberationSans(), {U'A'});
    std::string truncated = "\xD0"; // first byte of a two-byte sequence
    float w = libresign::measureTextWidth(subset, truncated, 12.0f);
    EXPECT_GE(w, 0.0f);
}

TEST(PdfFont, MeasureScalesLinearly)
{
    auto subset = subsetTtf(bundledLiberationSans(), {U'H', U'e', U'l', U'o'});
    float w6 = libresign::measureTextWidth(subset, "Hello", 6.0f);
    float w12 = libresign::measureTextWidth(subset, "Hello", 12.0f);
    EXPECT_NEAR(w12, 2.0f * w6, 1e-3f);
}
