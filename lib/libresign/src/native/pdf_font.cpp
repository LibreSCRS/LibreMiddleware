// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "pdf_font.h"

#include <algorithm>
#include <format>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>

namespace libresign {

namespace {

// PDF font name embedded in the Type0 / CIDFontType2 / FontDescriptor
// dicts. Independent of the underlying TTF source — this is the "name
// the PDF references this font by", chosen to match the bundled font.
// If the bundled font is ever swapped (e.g. to Noto Sans), update here.
constexpr std::string_view kBaseFontName = "LiberationSans";

std::string hex4(uint16_t v)
{
    return std::format("{:04X}", v);
}

// PDF /W array entry: [startCID [w1 w2 ... wN]]. Emits one contiguous run
// covering new GIDs 0..N-1.
std::string widthArray(const std::vector<uint16_t>& widths)
{
    std::string inner;
    inner.reserve(widths.size() * 5);
    bool first = true;
    for (auto width : widths) {
        if (!first)
            inner.push_back(' ');
        inner += std::format("{}", width);
        first = false;
    }
    return std::format("[ 0 [{}] ]", inner);
}

std::string toUnicodeCmap(const TtfSubset& s)
{
    // Collect (new_gid_raw → codepoint) mappings in GID order. The raw uint16
    // is the byte-level CID encoded in the bfchar table, so emit raw() at the
    // format-string boundary.
    std::vector<std::pair<uint16_t, char32_t>> pairs;
    pairs.reserve(s.gidForCodepoint.size());
    for (auto [cp, gid] : s.gidForCodepoint)
        pairs.push_back({gid.raw(), cp});
    std::sort(pairs.begin(), pairs.end());

    std::ostringstream cmap;
    cmap << "/CIDInit /ProcSet findresource begin\n"
         << "12 dict begin\n"
         << "begincmap\n"
         << "/CIDSystemInfo << /Registry (Adobe) /Ordering (UCS) /Supplement 0 >> def\n"
         << "/CMapName /Adobe-Identity-UCS def\n"
         << "/CMapType 2 def\n"
         << "1 begincodespacerange\n"
         << "<0000> <FFFF>\n"
         << "endcodespacerange\n";

    // Chunk bfchar into groups of <= 100 (PDF spec limit).
    size_t i = 0;
    while (i < pairs.size()) {
        size_t chunk = std::min<size_t>(100, pairs.size() - i);
        cmap << chunk << " beginbfchar\n";
        for (size_t j = 0; j < chunk; ++j) {
            auto [gidRaw, cp] = pairs[i + j];
            if (cp <= 0xFFFF) {
                cmap << "<" << hex4(gidRaw) << "> <" << hex4(static_cast<uint16_t>(cp)) << ">\n";
            } else {
                // Supplementary: UTF-16 surrogate pair.
                uint32_t v = cp - 0x10000;
                uint16_t high = 0xD800 + (v >> 10);
                uint16_t low = 0xDC00 + (v & 0x3FF);
                cmap << "<" << hex4(gidRaw) << "> <" << hex4(high) << hex4(low) << ">\n";
            }
        }
        cmap << "endbfchar\n";
        i += chunk;
    }

    cmap << "endcmap\nCMapName currentdict /CMap defineresource pop\nend\nend\n";
    return cmap.str();
}

} // namespace

void emitPdfFontObjects(const TtfSubset& subset, uint32_t firstObjNum, PdfFontObjects& out)
{
    out.type0ObjNum = firstObjNum + 0;
    out.cidFontObjNum = firstObjNum + 1;
    out.fontDescriptorObjNum = firstObjNum + 2;
    out.toUnicodeObjNum = firstObjNum + 3;
    out.fontFile2ObjNum = firstObjNum + 4;
    out.cidSetObjNum = firstObjNum + 5;

    // /CIDSet bitmap (PDF/A-2/3, ISO 19005-2 §6.2.11.4.2). MSB-first per
    // ISO 32000-1 §9.7.4. Subset is dense (CIDs 0..N-1 all present), but
    // the loop is sparse-tolerant for refactor robustness.
    {
        const size_t N = subset.widthForGid.size();
        out.cidSetStream.assign((N + 7) / 8, 0);
        for (size_t cid = 0; cid < N; ++cid)
            out.cidSetStream[cid / 8] |= static_cast<uint8_t>(0x80 >> (cid % 8));
    }

    // Convert font-unit metrics to the PDF 1000-unit ems.
    auto toEm = [&](int v) -> int { return subset.unitsPerEm == 0 ? 0 : v * 1000 / subset.unitsPerEm; };

    std::vector<uint16_t> widthsEm;
    widthsEm.reserve(subset.widthForGid.size());
    for (auto w : subset.widthForGid) {
        // Clamp to uint16_t range. For Liberation Sans (UPM=2048) widths fit
        // comfortably (max ~2048 → ~1000 PDF units). For an unusual UPM<1000
        // future font, large source widths could theoretically exceed 65535
        // PDF units; clamp defensively.
        int em = toEm(w);
        if (em < 0)
            em = 0;
        if (em > 65535)
            em = 65535;
        widthsEm.push_back(static_cast<uint16_t>(em));
    }

    // Type0 font dict.
    out.type0Dict = std::format("<< /Type /Font\n"
                                "   /Subtype /Type0\n"
                                "   /BaseFont /{}\n"
                                "   /Encoding /Identity-H\n"
                                "   /DescendantFonts [ {} 0 R ]\n"
                                "   /ToUnicode {} 0 R\n"
                                ">>",
                                kBaseFontName, out.cidFontObjNum, out.toUnicodeObjNum);

    // CIDFontType2 dict.
    out.cidFontDict = std::format("<< /Type /Font\n"
                                  "   /Subtype /CIDFontType2\n"
                                  "   /BaseFont /{}\n"
                                  "   /CIDSystemInfo << /Registry (Adobe) /Ordering (Identity) /Supplement 0 >>\n"
                                  "   /FontDescriptor {} 0 R\n"
                                  "   /CIDToGIDMap /Identity\n"
                                  "   /W {}\n"
                                  ">>",
                                  kBaseFontName, out.fontDescriptorObjNum, widthArray(widthsEm));

    // FontDescriptor.
    // Flags: bit 3 (4) = Symbolic per PDF 32000-1 §9.8.2. Embedded TTF
    // FontFile2 programs without a WinAnsi-compatible /Encoding
    // conventionally set the Symbolic bit; parent Type0's
    // /Encoding /Identity-H then selects glyphs via our ToUnicode CMap.
    // This matches the convention used by PDFBox, iText, and other
    // established TTF embedders.
    out.fontDescriptorDict =
        std::format("<< /Type /FontDescriptor\n"
                    "   /FontName /{}\n"
                    "   /Flags 4\n"
                    "   /FontBBox [ {} {} {} {} ]\n"
                    "   /ItalicAngle 0\n"
                    "   /Ascent {}\n"
                    "   /Descent {}\n"
                    "   /CapHeight {}\n"
                    "   /StemV {}\n"
                    "   /FontFile2 {} 0 R\n"
                    "   /CIDSet {} 0 R\n"
                    ">>",
                    kBaseFontName, toEm(subset.bboxMinX), toEm(subset.bboxMinY), toEm(subset.bboxMaxX),
                    toEm(subset.bboxMaxY), toEm(subset.ascent), toEm(subset.descent), toEm(subset.capHeight),
                    subset.stemV, out.fontFile2ObjNum, out.cidSetObjNum);

    out.toUnicodeStream = toUnicodeCmap(subset);
    out.fontFile2Stream = subset.bytes;
}

} // namespace libresign
