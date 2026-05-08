// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware."
#endif

#pragma once

#include "ttf_subset.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace libresign {

/// @brief Measure the rendered advance width of a UTF-8 text run using @p subset.
///
/// Sums per-glyph advance widths (in font units) for each codepoint in
/// @p utf8, mapping codepoints to new GIDs via @ref TtfSubset::gidForCodepoint
/// and reading widths from @ref TtfSubset::widthForGid. Codepoints absent
/// from the subset's cmap are measured at GID 0 (.notdef) — matching how the
/// PAdES emitter renders unmappable codepoints in a content stream. The
/// font-unit sum is converted to PDF user units via
/// `fontSize * sum / unitsPerEm`.
///
/// Invalid UTF-8 is consumed as one byte at a time mapped to U+FFFD, which
/// resolves to .notdef under any sane subset, so the function is robust to
/// malformed input. It never throws and never reads past the end of @p utf8.
///
/// @param subset    Subsetted font produced by @ref subsetTtf. Must contain
///                  every codepoint the caller wishes to measure precisely;
///                  missing codepoints fall back to .notdef.
/// @param utf8      UTF-8 text run. May be empty (returns 0.0). May contain
///                  embedded NULs (treated as ordinary codepoints).
/// @param fontSize  Font size in PDF user units (typographic points). Must be
///                  finite and non-negative; behaviour is undefined otherwise.
/// @return Rendered advance width in PDF user units. Always non-negative.
///
/// @par Thread-safety
/// Pure function; thread-safe given @p subset is not concurrently mutated.
///
/// @par Determinism
/// IEEE-754 single-precision arithmetic only; identical inputs yield
/// bit-identical outputs across Linux/macOS/MSVC SSE.
///
/// @since 4.0
[[nodiscard]] float measureTextWidth(const TtfSubset& subset, std::string_view utf8, float fontSize) noexcept;

/// @brief Text and bytes of the six PDF objects that make up a Type0 font.
///
/// Dict strings are ready to be wrapped in an `N 0 obj\n...\nendobj\n`
/// sequence by the caller. Stream bodies (`toUnicodeStream`,
/// `fontFile2Stream`, `cidSetStream`) are the raw bytes; caller wraps
/// them in `<< /Length ... >>\nstream\n...\nendstream\n`.
struct PdfFontObjects
{
    std::string type0Dict;
    std::string cidFontDict;
    std::string fontDescriptorDict;
    std::string toUnicodeStream;          // CMap ASCII text (not binary)
    std::vector<uint8_t> fontFile2Stream; // raw TTF bytes
    /// @brief CIDSet bitmap for PDF/A-2/3 conformance (ISO 19005-2 §6.2.11.4.2).
    ///        MSB-first per ISO 32000-1 §9.7.4: byte i bit (7-k) is set when
    ///        CID 8i+k is used. Caller wraps in stream object.
    std::vector<uint8_t> cidSetStream;
    /// @brief Object numbers assigned to each object, relative to
    ///        @p firstObjNum passed to emitPdfFontObjects(). The six
    ///        named ObjNum fields collectively document the structure
    ///        (Type0 + CIDFontType2 + FontDescriptor + ToUnicode +
    ///        FontFile2 + CIDSet).
    uint32_t type0ObjNum = 0;
    uint32_t cidFontObjNum = 0;
    uint32_t fontDescriptorObjNum = 0;
    uint32_t toUnicodeObjNum = 0;
    uint32_t fontFile2ObjNum = 0;
    uint32_t cidSetObjNum = 0;
};

/// @brief Build the six PDF object texts for the given TTF subset.
/// @param subset       Subset produced by subsetTtf().
/// @param firstObjNum  First available PDF object number; subsequent
///                     objects are allocated at firstObjNum+1..+5.
/// @param[out] out     Populated with dict text and stream bodies.
void emitPdfFontObjects(const TtfSubset& subset, uint32_t firstObjNum, PdfFontObjects& out);

} // namespace libresign
