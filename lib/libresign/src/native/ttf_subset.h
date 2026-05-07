// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware."
#endif

#pragma once

#include "gid.h"
#include "ttf_parser.h"

#include <cstdint>
#include <set>
#include <span>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace libresign {

/// @brief Result of subsetting a TTF.
///
/// `bytes` is a standalone, valid SFNT file that contains only the glyphs
/// reachable from the requested codepoint set (plus .notdef). The caller
/// uses it as the payload of a PDF /FontFile2 stream.
///
/// `gidForCodepoint` maps each requested codepoint to its *new* GID in
/// the subset (dense, starting at 1; GID 0 is always .notdef). Requested
/// codepoints that were not present in the source font are absent from
/// this map — the caller treats them as .notdef at PDF-writing time.
///
/// `widthForGid[new_gid]` is the advance width in font units (indexed by
/// new GID, not codepoint).
struct TtfSubset
{
    std::vector<uint8_t> bytes;
    std::unordered_map<char32_t, NewGid> gidForCodepoint;
    /// @brief Advance widths in font-unit (unitsPerEm) units, indexed by
    ///        new-GID raw value (0..N-1). Width values themselves are not
    ///        GIDs, so the vector element type stays uint16_t.
    std::vector<uint16_t> widthForGid;
    uint16_t unitsPerEm = 0;
    int16_t ascent = 0, descent = 0, capHeight = 0;
    uint16_t stemV = 80;
    int16_t bboxMinX = 0, bboxMinY = 0, bboxMaxX = 0, bboxMaxY = 0;
};

/// @brief Compute the full set of original-GIDs that the subset must contain,
///        starting from @p codepoints and transitively adding every GID
///        referenced by composite glyphs. OldGid{0} (.notdef) is always included.
///
/// Intermediate helper exposed for unit testing; most callers use subsetTtf().
[[nodiscard]] std::set<OldGid> computeUsedGids(const TtfParser& parser, const std::unordered_set<char32_t>& codepoints);

/// @brief Produce a minimal TTF subset containing only the glyphs needed
///        for @p codepoints, plus the required .notdef glyph at GID 0.
///
/// @throws std::runtime_error on malformed input TTF.
[[nodiscard]] TtfSubset subsetTtf(std::span<const uint8_t> fullTtf, const std::unordered_set<char32_t>& codepoints);

} // namespace libresign
