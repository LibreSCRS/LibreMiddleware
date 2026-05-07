// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware."
#endif

#pragma once

#include "gid.h"

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace libresign {

/// @brief Minimal read-only SFNT / TrueType font parser.
///
/// Accepts a byte span (no ownership). parse() must be called before any
/// other accessor; returns false on malformed input. All subsequent
/// accessors assume parse() succeeded — calling them before parse() is UB.
///
/// Scope limited to tables needed by the LibreSCRS PAdES appearance
/// pipeline: head, hhea, maxp, OS/2, post, name, cmap, glyf, loca, hmtx.
/// Tables outside this list are visible via hasTable()/tableSpan() but
/// never interpreted by the parser itself.
class TtfParser
{
public:
    explicit TtfParser(std::span<const uint8_t> data);

    /// @brief Validate SFNT header + table directory + presence of required
    ///        tables. Returns true on success. Must be called first.
    bool parse();

    // --- Core metrics (from head / hhea / OS/2 / maxp) ---
    uint32_t numGlyphs() const noexcept
    {
        return glyphCount;
    }
    uint16_t unitsPerEm() const noexcept
    {
        return emUnits;
    }
    int16_t ascent() const noexcept
    {
        return hheaAscent;
    }
    int16_t descent() const noexcept
    {
        return hheaDescent;
    }
    int16_t capHeight() const noexcept
    {
        return os2CapHeight;
    }
    uint16_t stemV() const noexcept
    {
        return derivedStemV;
    }
    int16_t bboxMinX() const noexcept
    {
        return headBboxMinX;
    }
    int16_t bboxMinY() const noexcept
    {
        return headBboxMinY;
    }
    int16_t bboxMaxX() const noexcept
    {
        return headBboxMaxX;
    }
    int16_t bboxMaxY() const noexcept
    {
        return headBboxMaxY;
    }
    bool locaIsLong() const noexcept
    {
        return longLocaFormat;
    }

    // --- Table access ---
    bool hasTable(std::string_view tag) const;
    /// @brief Span over the raw bytes of table @p tag. Empty on miss.
    std::span<const uint8_t> tableSpan(std::string_view tag) const;

    // --- cmap ---
    /// @brief Map @p codepoint to its original GID. Returns OldGid{0} (.notdef) on miss.
    OldGid gidForCodepoint(char32_t codepoint) const;

    // --- glyf / loca ---
    /// @brief Byte span of glyph @p gid in the glyf table.
    ///        Empty span for empty (zero-length) glyphs — a valid TTF state.
    std::span<const uint8_t> glyphSpan(OldGid gid) const;
    /// @brief GIDs directly referenced by composite glyph @p gid (not
    ///        transitively). Empty for simple glyphs.
    std::vector<OldGid> compositeReferences(OldGid gid) const;

    // --- hmtx ---
    /// @brief Advance width of @p gid in font units (unitsPerEm).
    uint16_t advanceWidth(OldGid gid) const;

    // --- Raw access to the input (for the subsetter's byte-level rewrite) ---
    std::span<const uint8_t> bytes() const noexcept
    {
        return rawData;
    }

private:
    std::span<const uint8_t> rawData;
    std::unordered_map<std::string, std::pair<uint32_t, uint32_t>> tableDir; // tag → (offset, length)
    uint32_t glyphCount = 0;
    uint16_t emUnits = 0;
    int16_t hheaAscent = 0, hheaDescent = 0, os2CapHeight = 0;
    uint16_t derivedStemV = 80; // default if post.stemV absent
    int16_t headBboxMinX = 0, headBboxMinY = 0, headBboxMaxX = 0, headBboxMaxY = 0;
    bool longLocaFormat = false;
    // cmap / loca / hmtx caches filled lazily.
    std::unordered_map<char32_t, OldGid> cmapTable;
    // Indexed by old-GID raw value (0..glyphCount).
    std::vector<uint32_t> locaOffsets; // length glyphCount + 1
    // Indexed by old-GID raw value (0..glyphCount-1).
    std::vector<uint16_t> hmtxAdvanceWidths;

    bool parseCmap();
    bool parseLoca();
    bool parseHmtx();
};

/// @brief OpenType composite-glyph flag bits (subset used by parser + subsetter).
///
/// These map onto the flag field of each component record in a composite
/// glyph (numContours == -1). The set defined here is the minimum needed
/// to walk a composite glyph's component list and skip the flag-dependent
/// argument bytes — full ARGS_ARE_XY_VALUES / ROUND_XY_TO_GRID handling is
/// the responsibility of the rendering side and is not modelled here.
namespace ttf_constants {
inline constexpr uint16_t kArg1And2AreWords = 0x0001;
inline constexpr uint16_t kWeHaveAScale = 0x0008;
inline constexpr uint16_t kMoreComponents = 0x0020;
inline constexpr uint16_t kWeHaveAnXAndYScale = 0x0040;
inline constexpr uint16_t kWeHaveATwoByTwo = 0x0080;
} // namespace ttf_constants

} // namespace libresign
