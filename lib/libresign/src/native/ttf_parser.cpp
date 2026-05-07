// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "ttf_parser.h"

#include "sfnt_io.h"

#include <cstring>
#include <string>

namespace libresign {

using sfnt::readI16;
using sfnt::readU16;
using sfnt::readU32;
using sfnt::tagAt;

namespace {

// SFNT scaler types per OpenType spec.
constexpr uint32_t kSfntTtfV1 = 0x00010000u;   // TrueType v1 outlines
constexpr uint32_t kSfntTtfTrue = 0x74727565u; // 'true' (legacy macOS TrueType)

// F8: cmap iteration caps. Format 12 groups can in principle cover any
// 32-bit codepoint range (endCharCode = 0xFFFFFFFF would loop ~4 billion
// times). Format 4 is BMP-only but a malicious font could still produce a
// pathological number of segments. Both caps are well above any legitimate
// font (the entire Unicode codepoint space is 0x110000 ≈ 1.1M).
constexpr uint32_t kMaxCodepointsPerGroup = 0x110000;
constexpr size_t kMaxTotalCmapEntries = 0x110000;

} // namespace

TtfParser::TtfParser(std::span<const uint8_t> data) : rawData(data) {}

bool TtfParser::parse()
{
    if (rawData.size() < 12)
        return false;

    // Offset subtable (SFNT header)
    uint32_t scalerType = readU32(rawData, 0);
    // Accept TrueType outlines only: 0x00010000 or 'true'. Reject
    // 'OTTO' (OpenType with CFF outlines) — not supported by our
    // TTF subsetter, which only handles glyf/loca.
    if (scalerType != kSfntTtfV1 && scalerType != kSfntTtfTrue)
        return false;

    uint16_t numTables = readU16(rawData, 4);
    if (rawData.size() < 12u + 16u * numTables)
        return false;

    // Table directory — 16 bytes per entry: tag(4) checksum(4) offset(4) length(4)
    for (uint16_t i = 0; i < numTables; ++i) {
        size_t e = 12 + i * 16;
        std::string tag = tagAt(rawData, e);
        uint32_t off = readU32(rawData, e + 8);
        uint32_t len = readU32(rawData, e + 12);
        // F7: `off + len` is uint32 arithmetic and can wrap on malicious
        // input. Reformulate the bounds check into the overflow-safe
        // `len > rawData.size() - off` form once we've established
        // `off <= rawData.size()`.
        if (off > rawData.size() || len > rawData.size() - off)
            return false;
        tableDir[tag] = {off, len};
    }

    // Required tables
    for (const auto* req : {"head", "hhea", "maxp", "OS/2", "cmap", "glyf", "loca", "hmtx"}) {
        if (!hasTable(req))
            return false;
    }

    // head: unitsPerEm (18), indexToLocFormat (50), bbox (36-42)
    {
        auto head = tableSpan("head");
        if (head.size() < 54)
            return false;
        emUnits = readU16(head, 18);
        headBboxMinX = readI16(head, 36);
        headBboxMinY = readI16(head, 38);
        headBboxMaxX = readI16(head, 40);
        headBboxMaxY = readI16(head, 42);
        longLocaFormat = (readU16(head, 50) == 1);
    }

    // maxp: numGlyphs (4)
    {
        auto maxp = tableSpan("maxp");
        if (maxp.size() < 6)
            return false;
        glyphCount = readU16(maxp, 4);
    }

    // hhea: ascent (4), descent (6), numberOfHMetrics (34)
    {
        auto hhea = tableSpan("hhea");
        if (hhea.size() < 36)
            return false;
        hheaAscent = readI16(hhea, 4);
        hheaDescent = readI16(hhea, 6);
    }

    // OS/2: sCapHeight at offset 88 (version >= 2). Fallback to ascent if absent.
    {
        auto os2 = tableSpan("OS/2");
        uint16_t ver = os2.size() >= 2 ? readU16(os2, 0) : 0;
        if (ver >= 2 && os2.size() >= 90) {
            os2CapHeight = readI16(os2, 88);
        } else {
            os2CapHeight = hheaAscent;
        }
    }

    // stemV: no canonical source in TTF. Standard heuristic: derive from usWeightClass.
    {
        auto os2 = tableSpan("OS/2");
        uint16_t weight = os2.size() >= 6 ? readU16(os2, 4) : 400;
        // fontTools-style quadratic mapping: StemV ≈ 50 + (weight/65)^2, clamped to [50, 220].
        // Gives ~88 for Regular (400), ~166 for Bold (700) — matches typical PDF writers.
        double w = static_cast<double>(weight) / 65.0;
        int sv = 50 + static_cast<int>(w * w);
        if (sv < 50)
            sv = 50;
        if (sv > 220)
            sv = 220;
        derivedStemV = static_cast<uint16_t>(sv);
    }

    if (!parseCmap())
        return false;
    if (!parseLoca())
        return false;
    if (!parseHmtx())
        return false;
    return true;
}

bool TtfParser::hasTable(std::string_view tag) const
{
    return tableDir.find(std::string(tag)) != tableDir.end();
}

std::span<const uint8_t> TtfParser::tableSpan(std::string_view tag) const
{
    auto it = tableDir.find(std::string(tag));
    if (it == tableDir.end())
        return {};
    return rawData.subspan(it->second.first, it->second.second);
}

OldGid TtfParser::gidForCodepoint(char32_t cp) const
{
    auto it = cmapTable.find(cp);
    return it == cmapTable.end() ? OldGid{0} : it->second;
}

std::span<const uint8_t> TtfParser::glyphSpan(OldGid gid) const
{
    // locaOffsets is indexed by old-GID raw value.
    if (gid.raw() + 1u >= locaOffsets.size())
        return {};
    auto glyf = tableSpan("glyf");
    uint32_t start = locaOffsets[gid.raw()];
    uint32_t end = locaOffsets[gid.raw() + 1];
    if (end <= start || end > glyf.size())
        return {};
    return glyf.subspan(start, end - start);
}

std::vector<OldGid> TtfParser::compositeReferences(OldGid gid) const
{
    std::vector<OldGid> refs;
    auto g = glyphSpan(gid);
    if (g.size() < 10)
        return refs;
    int16_t numContours = readI16(g, 0);
    if (numContours >= 0)
        return refs; // simple glyph

    // Composite glyph loop: at offset 10, repeat:
    //   flags (u16), glyphIndex (u16), args (depend on flags)
    // until kMoreComponents (0x0020) flag is clear.
    using namespace ttf_constants;

    size_t off = 10;
    while (off + 4 <= g.size()) {
        uint16_t flags = readU16(g, off);
        uint16_t glyphIndex = readU16(g, off + 2);
        refs.push_back(OldGid{glyphIndex});
        off += 4;
        off += (flags & kArg1And2AreWords) ? 4 : 2;
        if (flags & kWeHaveAScale)
            off += 2;
        else if (flags & kWeHaveAnXAndYScale)
            off += 4;
        else if (flags & kWeHaveATwoByTwo)
            off += 8;
        if (!(flags & kMoreComponents))
            break;
    }
    return refs;
}

uint16_t TtfParser::advanceWidth(OldGid gid) const
{
    // hmtxAdvanceWidths is indexed by old-GID raw value.
    return gid.raw() < hmtxAdvanceWidths.size() ? hmtxAdvanceWidths[gid.raw()] : 0;
}

bool TtfParser::parseCmap()
{
    auto cmap = tableSpan("cmap");
    if (cmap.size() < 4)
        return false;
    uint16_t numTables = readU16(cmap, 2);
    if (cmap.size() < 4u + 8u * numTables)
        return false;

    // Prefer (3,10) Unicode full repertoire, then (3,1) BMP, then (0,*).
    uint32_t chosenOffset = 0;
    int chosenRank = -1;
    for (uint16_t i = 0; i < numTables; ++i) {
        size_t e = 4 + i * 8;
        uint16_t platform = readU16(cmap, e);
        uint16_t encoding = readU16(cmap, e + 2);
        uint32_t offset = readU32(cmap, e + 4);
        int rank = -1;
        if (platform == 3 && encoding == 10)
            rank = 3; // Windows UCS-4
        else if (platform == 3 && encoding == 1)
            rank = 2; // Windows BMP
        else if (platform == 0)
            rank = 1; // Unicode
        if (rank > chosenRank) {
            chosenRank = rank;
            chosenOffset = offset;
        }
    }
    if (chosenRank < 0)
        return false;
    if (chosenOffset + 4 > cmap.size())
        return false;

    auto sub = cmap.subspan(chosenOffset);
    uint16_t format = readU16(sub, 0);

    if (format == 4) {
        // Format 4: segmented BMP mapping.
        if (sub.size() < 14)
            return false;
        uint16_t segCountX2 = readU16(sub, 6);
        uint16_t segCount = segCountX2 / 2;
        size_t endCodesOff = 14;
        size_t startCodesOff = endCodesOff + segCountX2 + 2; // +2 for reservedPad
        size_t idDeltaOff = startCodesOff + segCountX2;
        size_t idRangeOffOff = idDeltaOff + segCountX2;
        // segCountX2 is uint16, so 4 * segCountX2 + 14 fits in size_t without
        // overflow on any platform with sizeof(size_t) >= 4.
        if (sub.size() < idRangeOffOff + segCountX2)
            return false;

        for (uint16_t seg = 0; seg < segCount; ++seg) {
            uint16_t endCode = readU16(sub, endCodesOff + 2 * seg);
            uint16_t startCode = readU16(sub, startCodesOff + 2 * seg);
            int16_t idDelta = readI16(sub, idDeltaOff + 2 * seg);
            uint16_t idRangeOff = readU16(sub, idRangeOffOff + 2 * seg);
            for (uint32_t cp = startCode; cp <= endCode; ++cp) {
                uint16_t gid;
                if (idRangeOff == 0) {
                    gid = static_cast<uint16_t>((cp + idDelta) & 0xFFFF);
                } else {
                    size_t glyphIdOff = idRangeOffOff + 2 * seg + idRangeOff + 2 * (cp - startCode);
                    if (glyphIdOff + 2 > sub.size())
                        continue;
                    uint16_t raw = readU16(sub, glyphIdOff);
                    gid = raw == 0 ? 0 : static_cast<uint16_t>((raw + idDelta) & 0xFFFF);
                }
                if (gid != 0) {
                    cmapTable[cp] = OldGid{gid};
                    // F8: global cmap-entry cap (symmetric with Format 12).
                    if (cmapTable.size() > kMaxTotalCmapEntries)
                        return false;
                }
            }
        }
        return true;
    }

    if (format == 12) {
        // Format 12: segmented coverage, 32-bit codepoints.
        if (sub.size() < 16)
            return false;
        uint32_t numGroups = readU32(sub, 12);
        // Use division form to avoid 32-bit unsigned overflow on 12*numGroups
        // — a maliciously crafted font with numGroups ≈ 0x16000001 would wrap
        // and bypass the additive check, allowing a multi-billion-iteration
        // loop below.
        if (numGroups > (sub.size() - 16u) / 12u)
            return false;
        for (uint32_t g = 0; g < numGroups; ++g) {
            size_t e = 16 + 12 * g;
            uint32_t startCharCode = readU32(sub, e);
            uint32_t endCharCode = readU32(sub, e + 4);
            uint32_t startGlyphId = readU32(sub, e + 8);

            // F8: reject implausible groups (e.g. endCharCode = 0xFFFFFFFF).
            // The whole Unicode space is 0x110000 codepoints — anything
            // covering more is malformed regardless of intent.
            if (endCharCode < startCharCode || endCharCode - startCharCode > kMaxCodepointsPerGroup)
                return false;

            for (uint32_t cp = startCharCode; cp <= endCharCode; ++cp) {
                uint16_t gid = static_cast<uint16_t>(startGlyphId + (cp - startCharCode));
                if (gid != 0) {
                    cmapTable[cp] = OldGid{gid};
                    if (cmapTable.size() > kMaxTotalCmapEntries)
                        return false;
                }
            }
        }
        return true;
    }

    return false; // unsupported format
}

bool TtfParser::parseLoca()
{
    auto loca = tableSpan("loca");
    locaOffsets.assign(glyphCount + 1, 0);
    if (longLocaFormat) {
        if (loca.size() < 4u * (glyphCount + 1))
            return false;
        for (uint32_t i = 0; i <= glyphCount; ++i) {
            locaOffsets[i] = readU32(loca, 4u * i);
        }
    } else {
        if (loca.size() < 2u * (glyphCount + 1))
            return false;
        for (uint32_t i = 0; i <= glyphCount; ++i) {
            locaOffsets[i] = uint32_t(readU16(loca, 2u * i)) * 2u;
        }
    }
    return true;
}

bool TtfParser::parseHmtx()
{
    auto hhea = tableSpan("hhea");
    auto hmtx = tableSpan("hmtx");
    if (hhea.size() < 36)
        return false;
    uint16_t numHMetrics = readU16(hhea, 34);
    if (numHMetrics == 0 || numHMetrics > glyphCount)
        return false;
    if (hmtx.size() < 4u * numHMetrics + 2u * (glyphCount - numHMetrics))
        return false;

    hmtxAdvanceWidths.assign(glyphCount, 0);
    for (uint16_t i = 0; i < numHMetrics; ++i) {
        hmtxAdvanceWidths[i] = readU16(hmtx, 4u * i);
    }
    // Remaining glyphs inherit the last advance width (TTF convention).
    uint16_t lastAw = hmtxAdvanceWidths[numHMetrics - 1];
    for (uint16_t i = numHMetrics; i < glyphCount; ++i) {
        hmtxAdvanceWidths[i] = lastAw;
    }
    return true;
}

} // namespace libresign
