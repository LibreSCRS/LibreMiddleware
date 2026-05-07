// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <gtest/gtest.h>

#include "native/liberation_sans_data.h"
#include "native/pdf_font.h"
#include "native/ttf_subset.h"

#include <set>
#include <sstream>

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
