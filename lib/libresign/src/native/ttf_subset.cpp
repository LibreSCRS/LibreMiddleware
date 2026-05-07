// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "ttf_subset.h"

#include "sfnt_io.h"

#include <algorithm>
#include <cstring>
#include <deque>
#include <ranges>
#include <stdexcept>
#include <string>
#include <utility>

namespace libresign {

using sfnt::readI16;
using sfnt::readU16;
using sfnt::readU32;

std::set<OldGid> computeUsedGids(const TtfParser& parser, const std::unordered_set<char32_t>& codepoints)
{
    constexpr size_t kMaxClosureSize = 10000; // safety cap; see comment below
    std::set<OldGid> used;
    used.insert(OldGid{0}); // .notdef always
    std::deque<OldGid> queue;

    for (auto cp : codepoints) {
        OldGid gid = parser.gidForCodepoint(cp);
        if (gid == OldGid{0})
            continue; // unmapped — render as .notdef
        if (used.insert(gid).second)
            queue.push_back(gid);
    }

    while (!queue.empty()) {
        OldGid g = queue.front();
        queue.pop_front();
        for (OldGid ref : parser.compositeReferences(g)) {
            if (used.insert(ref).second) {
                if (used.size() > kMaxClosureSize) {
                    // Defensive: bail out before a pathological composite
                    // chain in an adversarial font produces a >10k-glyph
                    // subset. Liberation Sans has ~2500 glyphs total; any
                    // request that pulls in 10000+ is either malformed or
                    // an attack. The bundled font cannot trigger this.
                    throw std::runtime_error("computeUsedGids: glyph closure exceeded safety cap");
                }
                queue.push_back(ref);
            }
        }
    }
    return used;
}

namespace {

struct Table
{
    std::vector<uint8_t> data;
    std::string tag;
};

// ---------- Big-endian write helpers ----------

void w16(std::vector<uint8_t>& b, uint16_t v)
{
    b.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
    b.push_back(static_cast<uint8_t>(v & 0xFF));
}

void w32(std::vector<uint8_t>& b, uint32_t v)
{
    b.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
    b.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
    b.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
    b.push_back(static_cast<uint8_t>(v & 0xFF));
}

// Overwrite a 32-bit big-endian word at an existing offset.
void put32At(std::vector<uint8_t>& b, size_t off, uint32_t v)
{
    b[off] = static_cast<uint8_t>((v >> 24) & 0xFF);
    b[off + 1] = static_cast<uint8_t>((v >> 16) & 0xFF);
    b[off + 2] = static_cast<uint8_t>((v >> 8) & 0xFF);
    b[off + 3] = static_cast<uint8_t>(v & 0xFF);
}

// Overwrite a 16-bit big-endian word at an existing offset.
void put16At(std::vector<uint8_t>& b, size_t off, uint16_t v)
{
    b[off] = static_cast<uint8_t>((v >> 8) & 0xFF);
    b[off + 1] = static_cast<uint8_t>(v & 0xFF);
}

// Big-endian readers come from sfnt_io.h (sfnt::readU16, sfnt::readU32,
// sfnt::readI16) via the using-declarations at the top of the
// `namespace libresign` block. Composite-glyph flag constants come from
// `libresign::ttf_constants` (declared in ttf_parser.h).

// ---------- glyf + loca rebuilder ----------

// @p oldGidByNewGid maps new-GID raw index → OldGid. @p oldToNew maps OldGid → NewGid.
std::pair<std::vector<uint8_t>, std::vector<uint32_t>> buildGlyfLoca(const TtfParser& src,
                                                                     const std::vector<OldGid>& oldGidByNewGid,
                                                                     const std::unordered_map<OldGid, NewGid>& oldToNew)
{
    std::vector<uint8_t> glyf;
    std::vector<uint32_t> locaOffs;
    locaOffs.reserve(oldGidByNewGid.size() + 1);

    for (size_t newGidIdx = 0; newGidIdx < oldGidByNewGid.size(); ++newGidIdx) {
        locaOffs.push_back(static_cast<uint32_t>(glyf.size()));
        OldGid oldGid = oldGidByNewGid[newGidIdx];
        auto glyph = src.glyphSpan(oldGid);
        if (glyph.empty()) {
            // Empty glyph — nothing to write. loca offset recorded; glyf unchanged.
            continue;
        }

        size_t start = glyf.size();
        glyf.insert(glyf.end(), glyph.begin(), glyph.end());

        // If composite, rewrite component GIDs from old → new.
        if (glyph.size() >= 10) {
            int16_t numContours = readI16(glyph, 0);
            if (numContours < 0) {
                using namespace ttf_constants;
                size_t off = 10; // into the source glyph bytes
                while (off + 4 <= glyph.size()) {
                    uint16_t flags = readU16(glyph, off);
                    OldGid oldComponent{readU16(glyph, off + 2)};
                    auto it = oldToNew.find(oldComponent);
                    NewGid newComponent = (it != oldToNew.end()) ? it->second : NewGid{0};
                    // Rewrite at the same offset inside the freshly appended bytes —
                    // raw() at the byte-emission boundary.
                    put16At(glyf, start + off + 2, newComponent.raw());
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
            }
        }

        // Pad each glyph record to a 2-byte boundary (OpenType recommendation —
        // makes loca offsets representable in the short format, harmless in long).
        if (glyf.size() & 1u)
            glyf.push_back(0);
    }
    locaOffs.push_back(static_cast<uint32_t>(glyf.size()));
    return {std::move(glyf), std::move(locaOffs)};
}

// ---------- hmtx rebuilder ----------

// @p oldGidByNewGid maps new-GID raw index → OldGid. Iteration order is the
// new-GID order; each entry's old-GID raw value indexes the source hmtx table.
std::vector<uint8_t> buildHmtx(const TtfParser& src, const std::vector<OldGid>& oldGidByNewGid)
{
    // Read source hhea to recover numberOfHMetrics (needed to decide whether
    // each old GID had its own lsb or was in the tail of 2-byte lsb-only rows).
    auto hhea = src.tableSpan("hhea");
    auto hmtx = src.tableSpan("hmtx");
    uint16_t numHMetrics = 0;
    if (hhea.size() >= 36)
        numHMetrics = readU16(hhea, 34);

    std::vector<uint8_t> out;
    out.reserve(oldGidByNewGid.size() * 4);

    for (OldGid oldGid : oldGidByNewGid) {
        uint16_t aw = src.advanceWidth(oldGid);
        int16_t lsb = 0;
        if (oldGid.raw() < numHMetrics) {
            // advance(2) + lsb(2) pair at offset 4 * oldGid
            size_t pairOff = 4u * static_cast<size_t>(oldGid.raw());
            if (pairOff + 4 <= hmtx.size()) {
                lsb = readI16(hmtx, pairOff + 2);
            }
        } else {
            // tail: advances are shared; lsb is stored as int16 after the
            // 4*numHMetrics pair block.
            size_t base = 4u * static_cast<size_t>(numHMetrics);
            size_t idx = static_cast<size_t>(oldGid.raw()) - numHMetrics;
            size_t lsbOff = base + 2 * idx;
            if (lsbOff + 2 <= hmtx.size()) {
                lsb = readI16(hmtx, lsbOff);
            }
        }
        w16(out, aw);
        w16(out, static_cast<uint16_t>(lsb));
    }
    return out;
}

// ---------- cmap rebuilder (Format 4 + Format 12) ----------

// Build a Format 4 (BMP segment mapping to delta values) subtable.
std::vector<uint8_t> buildCmapFormat4(const std::vector<std::pair<char32_t, NewGid>>& bmp)
{
    // Group consecutive codepoints with consecutive GIDs into segments.
    // Force a mandatory terminator segment [0xFFFF, 0xFFFF] at the end.
    struct Segment
    {
        uint16_t startCode;
        uint16_t endCode;
        int16_t idDelta; // use idDelta (idRangeOffset = 0) — simplest form.
    };
    std::vector<Segment> segments;

    size_t i = 0;
    while (i < bmp.size()) {
        uint16_t startCp = static_cast<uint16_t>(bmp[i].first);
        uint16_t startGid = bmp[i].second.raw();
        size_t j = i;
        while (j + 1 < bmp.size() &&
               static_cast<uint16_t>(bmp[j + 1].first) == static_cast<uint16_t>(bmp[j].first) + 1 &&
               bmp[j + 1].second.raw() == bmp[j].second.raw() + 1) {
            ++j;
        }
        uint16_t endCp = static_cast<uint16_t>(bmp[j].first);
        // idDelta = (gid - cp) mod 2^16
        int16_t delta =
            static_cast<int16_t>(static_cast<uint16_t>(static_cast<int32_t>(startGid) - static_cast<int32_t>(startCp)));
        segments.push_back({startCp, endCp, delta});
        i = j + 1;
    }
    // Mandatory terminator.
    segments.push_back({0xFFFF, 0xFFFF, 1});

    uint16_t segCount = static_cast<uint16_t>(segments.size());
    uint16_t segCountX2 = segCount * 2;

    // OpenType binary-search hints (PDF 32000-1 / OpenType spec):
    //   entrySelector = floor(log2(segCount))
    //   searchRange   = 2 * 2^entrySelector  ( = 2^(entrySelector+1) )
    //   rangeShift    = 2 * segCount - searchRange
    // Algorithm: searchRange starts at 1, double until > segCount;
    // entrySelector counts the doublings. For segCount=1 yields
    // entrySelector=0, searchRange=2, rangeShift=0 — matches spec.
    // (The previous initialisation searchRange=2 yielded searchRange=4,
    // rangeShift=0xFFFE for the empty-BMP case — wraps under uint16.)
    uint16_t searchRange = 1;
    uint16_t entrySelector = 0;
    while (static_cast<uint32_t>(searchRange) * 2u <= static_cast<uint32_t>(segCount)) {
        searchRange *= 2;
        ++entrySelector;
    }
    searchRange *= 2;
    uint16_t rangeShift = segCountX2 - searchRange;

    std::vector<uint8_t> s;
    w16(s, 4); // format
    // length filled at end
    size_t lengthAt = s.size();
    w16(s, 0); // length placeholder
    w16(s, 0); // language
    w16(s, segCountX2);
    w16(s, searchRange);
    w16(s, entrySelector);
    w16(s, rangeShift);
    // endCode[segCount]
    for (auto& seg : segments)
        w16(s, seg.endCode);
    w16(s, 0); // reservedPad
    // startCode[segCount]
    for (auto& seg : segments)
        w16(s, seg.startCode);
    // idDelta[segCount]
    for (auto& seg : segments)
        w16(s, static_cast<uint16_t>(seg.idDelta));
    // idRangeOffset[segCount] — all zero (we encoded everything via idDelta)
    for (size_t k = 0; k < segments.size(); ++k)
        w16(s, 0);
    // No glyphIdArray (unused since idRangeOffset is all-zero).

    // Patch length.
    put16At(s, lengthAt, static_cast<uint16_t>(s.size()));
    return s;
}

// Build a Format 12 (segmented coverage, supplementary codepoints) subtable.
std::vector<uint8_t> buildCmapFormat12(const std::vector<std::pair<char32_t, NewGid>>& supp)
{
    // Group consecutive codepoints with consecutive GIDs into groups.
    struct Group
    {
        uint32_t startCharCode;
        uint32_t endCharCode;
        uint32_t startGlyphId;
    };
    std::vector<Group> groups;

    size_t i = 0;
    while (i < supp.size()) {
        uint32_t startCp = static_cast<uint32_t>(supp[i].first);
        uint32_t startGid = supp[i].second.raw();
        size_t j = i;
        while (j + 1 < supp.size() &&
               static_cast<uint32_t>(supp[j + 1].first) == static_cast<uint32_t>(supp[j].first) + 1 &&
               supp[j + 1].second.raw() == supp[j].second.raw() + 1) {
            ++j;
        }
        uint32_t endCp = static_cast<uint32_t>(supp[j].first);
        groups.push_back({startCp, endCp, startGid});
        i = j + 1;
    }

    std::vector<uint8_t> s;
    w16(s, 12); // format
    w16(s, 0);  // reserved
    // length (uint32) at s.size()
    size_t lengthAt = s.size();
    w32(s, 0); // placeholder length
    w32(s, 0); // language
    w32(s, static_cast<uint32_t>(groups.size()));
    for (auto& g : groups) {
        w32(s, g.startCharCode);
        w32(s, g.endCharCode);
        w32(s, g.startGlyphId);
    }
    put32At(s, lengthAt, static_cast<uint32_t>(s.size()));
    return s;
}

std::vector<uint8_t> buildCmap(const std::vector<std::pair<char32_t, NewGid>>& mappings)
{
    std::vector<std::pair<char32_t, NewGid>> bmp;
    for (const auto& m : mappings) {
        if (static_cast<uint32_t>(m.first) < 0x10000u)
            bmp.push_back(m);
    }
    // mappings are assumed sorted by caller.

    // Format 4 covers the BMP only. Format 12 covers every mapping (BMP +
    // supplementary) so parsers that prefer (3,10) — as our own TtfParser does —
    // still find BMP codepoints, even when there are no supplementary chars.
    auto sub4 = buildCmapFormat4(bmp);
    auto sub12 = buildCmapFormat12(mappings);

    // Header: version(2) numTables(2) + 2 encoding records (8 bytes each).
    constexpr size_t headerSize = 4 + 2 * 8;
    uint32_t off4 = static_cast<uint32_t>(headerSize);
    uint32_t off12 = off4 + static_cast<uint32_t>(sub4.size());

    std::vector<uint8_t> out;
    out.reserve(headerSize + sub4.size() + sub12.size());
    w16(out, 0); // version
    w16(out, 2); // numTables

    // Encoding record 1: platformID = 3 (Windows), encodingID = 1 (BMP Unicode) → Format 4.
    w16(out, 3);
    w16(out, 1);
    w32(out, off4);

    // Encoding record 2: platformID = 3 (Windows), encodingID = 10 (UCS-4) → Format 12.
    w16(out, 3);
    w16(out, 10);
    w32(out, off12);

    out.insert(out.end(), sub4.begin(), sub4.end());
    out.insert(out.end(), sub12.begin(), sub12.end());
    return out;
}

// ---------- head / maxp / hhea rebuilders ----------

std::vector<uint8_t> buildHead(const TtfParser& src)
{
    auto head = src.tableSpan("head");
    std::vector<uint8_t> out(head.begin(), head.end());
    if (out.size() < 54)
        throw std::runtime_error("subsetTtf: head table too small");
    // Zero checkSumAdjustment (offset 8). Fixed up at the end of writeSfnt.
    put32At(out, 8, 0);
    // Force long loca format (offset 50).
    put16At(out, 50, 1);
    return out;
}

std::vector<uint8_t> buildMaxp(const TtfParser& src, uint32_t newNumGlyphs)
{
    auto maxp = src.tableSpan("maxp");
    std::vector<uint8_t> out(maxp.begin(), maxp.end());
    if (out.size() < 6)
        throw std::runtime_error("subsetTtf: maxp table too small");
    put16At(out, 4, static_cast<uint16_t>(newNumGlyphs));
    return out;
}

std::vector<uint8_t> buildHhea(const TtfParser& src, uint32_t newNumGlyphs)
{
    auto hhea = src.tableSpan("hhea");
    std::vector<uint8_t> out(hhea.begin(), hhea.end());
    if (out.size() < 36)
        throw std::runtime_error("subsetTtf: hhea table too small");
    put16At(out, 34, static_cast<uint16_t>(newNumGlyphs));
    return out;
}

// Build a minimal post table in Format 3.0. Format 3 omits all glyph-name
// strings (the source usually ships Format 2, which references original GIDs
// we've dropped — so reusing it would be both bloated and incorrect). PDF
// viewers do not need glyph names to render embedded CID fonts.
std::vector<uint8_t> buildPost(const TtfParser& src)
{
    auto post = src.tableSpan("post");

    std::vector<uint8_t> out;
    out.reserve(32);
    w32(out, 0x00030000u);       // version 3.0 — no glyph names
    w32(out, readU32(post, 4));  // italicAngle (Fixed)
    w16(out, readU16(post, 8));  // underlinePosition (FWord)
    w16(out, readU16(post, 10)); // underlineThickness (FWord)
    w32(out, readU32(post, 12)); // isFixedPitch
    w32(out, readU32(post, 16)); // minMemType42
    w32(out, readU32(post, 20)); // maxMemType42
    w32(out, readU32(post, 24)); // minMemType1
    w32(out, readU32(post, 28)); // maxMemType1
    return out;
}

// ---------- Checksum helpers ----------

// Sum 32-bit big-endian words over the byte span, treating it as if zero-padded
// to a multiple of 4 bytes. Wraps on overflow (mod 2^32).
uint32_t tableChecksum(std::span<const uint8_t> data)
{
    uint32_t sum = 0;
    size_t n = data.size();
    size_t full = n & ~size_t(3);
    for (size_t i = 0; i < full; i += 4) {
        uint32_t w = (uint32_t(data[i]) << 24) | (uint32_t(data[i + 1]) << 16) | (uint32_t(data[i + 2]) << 8) |
                     uint32_t(data[i + 3]);
        sum += w;
    }
    if (n != full) {
        uint8_t buf[4] = {0, 0, 0, 0};
        for (size_t i = full; i < n; ++i)
            buf[i - full] = data[i];
        uint32_t w = (uint32_t(buf[0]) << 24) | (uint32_t(buf[1]) << 16) | (uint32_t(buf[2]) << 8) | uint32_t(buf[3]);
        sum += w;
    }
    return sum;
}

// ---------- SFNT writer ----------

std::vector<uint8_t> writeSfnt(std::vector<Table> tables)
{
    // Sort tables alphabetically by tag (SFNT convention for the directory).
    std::ranges::sort(tables, {}, &Table::tag);

    uint16_t numTables = static_cast<uint16_t>(tables.size());
    // Same algorithm as Format 4 cmap (see buildCmapFormat4), but multiplied
    // by 16 (size of an SFNT table directory entry) instead of 2. Avoids the
    // off-by-one that the prior init=2 loop produced for numTables<4.
    uint16_t searchRange = 1;
    uint16_t entrySelector = 0;
    while (static_cast<uint32_t>(searchRange) * 2u <= static_cast<uint32_t>(numTables)) {
        searchRange *= 2;
        ++entrySelector;
    }
    searchRange *= 16;
    uint16_t rangeShift = numTables * 16 - searchRange;

    // Offsets: header (12) + directory (16 per table).
    size_t headerSize = 12u + 16u * numTables;
    std::vector<uint8_t> out;
    out.reserve(headerSize + 0x10000u);

    // Write offset subtable.
    w32(out, 0x00010000u);
    w16(out, numTables);
    w16(out, searchRange);
    w16(out, entrySelector);
    w16(out, rangeShift);

    // Reserve space for the directory — fill later once we know offsets.
    size_t dirAt = out.size();
    out.resize(dirAt + 16u * numTables, 0);

    struct Placed
    {
        std::string tag;
        uint32_t checksum;
        uint32_t offset;
        uint32_t length;
    };
    std::vector<Placed> placed;
    placed.reserve(numTables);

    // Track where the head table lands so we can patch checkSumAdjustment later.
    size_t headOffsetInFile = 0;
    bool haveHead = false;

    for (auto& t : tables) {
        // Align to 4-byte boundary before writing.
        while (out.size() & 3u)
            out.push_back(0);
        uint32_t off = static_cast<uint32_t>(out.size());
        if (t.tag == "head") {
            headOffsetInFile = off;
            haveHead = true;
        }
        // Checksum is over the padded table data.
        // Build a padded view by temporarily appending (then we keep them).
        uint32_t rawLen = static_cast<uint32_t>(t.data.size());
        // Append raw bytes.
        out.insert(out.end(), t.data.begin(), t.data.end());
        // Pad with zeros to next 4-byte boundary. Padding bytes are included in
        // the checksum (as zeros, they don't affect the sum, but we keep them
        // in the file so directory offsets/lengths line up).
        while (out.size() & 3u)
            out.push_back(0);

        // Compute checksum over the padded region directly out of the file.
        std::span<const uint8_t> padded(out.data() + off, out.size() - off);
        uint32_t csum = tableChecksum(padded);
        placed.push_back({t.tag, csum, off, rawLen});
    }

    // Now write directory entries (also sorted — placed preserves tables' order,
    // which is already alphabetical).
    for (size_t i = 0; i < placed.size(); ++i) {
        size_t e = dirAt + i * 16;
        const auto& p = placed[i];
        // Tag: 4 ASCII bytes, space-padded.
        std::string tag = p.tag;
        while (tag.size() < 4)
            tag.push_back(' ');
        out[e + 0] = static_cast<uint8_t>(tag[0]);
        out[e + 1] = static_cast<uint8_t>(tag[1]);
        out[e + 2] = static_cast<uint8_t>(tag[2]);
        out[e + 3] = static_cast<uint8_t>(tag[3]);
        put32At(out, e + 4, p.checksum);
        put32At(out, e + 8, p.offset);
        put32At(out, e + 12, p.length);
    }

    // File-level checkSumAdjustment: 0xB1B0AFBA − sum(all 32-bit words of file)
    // with the head.checkSumAdjustment field itself set to 0 (buildHead did
    // that). Compute over the final file, then write into head + 8.
    if (haveHead) {
        uint32_t total = tableChecksum(std::span<const uint8_t>(out.data(), out.size()));
        uint32_t adjust = 0xB1B0AFBAu - total;
        put32At(out, headOffsetInFile + 8, adjust);
    }

    return out;
}

} // namespace

TtfSubset subsetTtf(std::span<const uint8_t> fullTtf, const std::unordered_set<char32_t>& codepoints)
{
    TtfParser src(fullTtf);
    if (!src.parse())
        throw std::runtime_error("subsetTtf: malformed input TTF");

    // 1. Compute closure and dense new-GID assignment.
    auto usedGids = computeUsedGids(src, codepoints);
    // oldGidByNewGid[newGidIdx] → OldGid (sorted from std::set<OldGid>).
    std::vector<OldGid> oldGidByNewGid(usedGids.begin(), usedGids.end());
    std::unordered_map<OldGid, NewGid> oldToNew;
    for (size_t newGidIdx = 0; newGidIdx < oldGidByNewGid.size(); ++newGidIdx) {
        oldToNew[oldGidByNewGid[newGidIdx]] = NewGid{static_cast<uint16_t>(newGidIdx)};
    }

    // 2. Build tables.
    auto [glyf, locaOffs] = buildGlyfLoca(src, oldGidByNewGid, oldToNew);
    // loca (long): uint32 per entry, size = newNumGlyphs + 1.
    std::vector<uint8_t> loca;
    loca.reserve(locaOffs.size() * 4);
    for (auto off : locaOffs) {
        w32(loca, off);
    }

    auto hmtx = buildHmtx(src, oldGidByNewGid);

    // cmap mappings: for each requested codepoint that has an original GID,
    // emit (codepoint → new GID).
    std::vector<std::pair<char32_t, NewGid>> cmapMappings;
    for (auto cp : codepoints) {
        OldGid oldGid = src.gidForCodepoint(cp);
        if (oldGid == OldGid{0})
            continue;
        auto it = oldToNew.find(oldGid);
        if (it != oldToNew.end())
            cmapMappings.push_back({cp, it->second});
    }
    std::ranges::sort(cmapMappings);
    auto cmap = buildCmap(cmapMappings);

    uint32_t newNumGlyphs = static_cast<uint32_t>(oldGidByNewGid.size());
    auto head = buildHead(src);
    auto maxp = buildMaxp(src, newNumGlyphs);
    auto hhea = buildHhea(src, newNumGlyphs);
    auto post = buildPost(src);

    // Tables to emit. OS/2 and name copied verbatim from source; post rebuilt
    // as Format 3 so we don't drag along glyph-name strings for dropped GIDs.
    auto osSpan = src.tableSpan("OS/2");
    auto nameSpan = src.tableSpan("name");
    std::vector<Table> tables = {
        {std::vector<uint8_t>(osSpan.begin(), osSpan.end()), "OS/2"},
        {std::move(cmap), "cmap"},
        {std::move(glyf), "glyf"},
        {std::move(head), "head"},
        {std::move(hhea), "hhea"},
        {std::move(hmtx), "hmtx"},
        {std::move(loca), "loca"},
        {std::move(maxp), "maxp"},
        {std::vector<uint8_t>(nameSpan.begin(), nameSpan.end()), "name"},
        {std::move(post), "post"},
    };
    auto sfnt = writeSfnt(std::move(tables));

    // 3. Populate result.
    TtfSubset out;
    out.bytes = std::move(sfnt);
    for (auto& [cp, newGid] : cmapMappings)
        out.gidForCodepoint[cp] = newGid;
    out.widthForGid.resize(newNumGlyphs);
    // widthForGid is uint16-valued and indexed by new-GID raw value.
    for (size_t newGidIdx = 0; newGidIdx < newNumGlyphs; ++newGidIdx) {
        out.widthForGid[newGidIdx] = src.advanceWidth(oldGidByNewGid[newGidIdx]);
    }
    out.unitsPerEm = src.unitsPerEm();
    out.ascent = src.ascent();
    out.descent = src.descent();
    out.capHeight = src.capHeight();
    out.stemV = src.stemV();
    out.bboxMinX = src.bboxMinX();
    out.bboxMinY = src.bboxMinY();
    out.bboxMaxX = src.bboxMaxX();
    out.bboxMaxY = src.bboxMaxY();
    return out;
}

} // namespace libresign
