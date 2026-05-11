// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

/// @file
/// @brief @ref LibreSCRS::Signing::layoutVisualSignature — pure auto-fit
///        layout for PAdES visual signature appearances; plus
///        @ref LibreSCRS::Signing::embeddedAppearanceFontData for GUI
///        consumers that need to render the same font as the embedded PDF
///        subset.
///
/// The PAdES native engine and every GUI preview surface (LibreCelik,
/// LibreMac, future LibreKDE) feed the same `(text, box)` pair into
/// @ref LibreSCRS::Signing::layoutVisualSignature and render the returned
/// lines verbatim — there is no second layout pass downstream. This is the
/// single source of truth for visual-signature auto-fit.

#include <LibreSCRS/Export.h>
#include <LibreSCRS/Signing/VisualSignatureParams.h>

#include <cstddef>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace LibreSCRS::Signing {

/// @brief Hard floor on the auto-fit font size in PDF user units.
///
/// On overflow at this size the layout returns `clipped == true` so the
/// caller (PAdES emitter or GUI preview) can install a clipping path /
/// clip rect. 6pt is the smallest size that still reads as text on
/// typical PDF viewers and matches the iText FILL_BOX floor.
/// @since 4.0
inline constexpr float kFloorAppearanceFontSize = 6.0f;

/// @brief Hard ceiling on the auto-fit font size in PDF user units.
///
/// 72pt = one inch. Useful only for wide-aspect annotation boxes; the
/// binary search will normally never reach this value for the typical
/// 200×50 default rectangle.
/// @since 4.0
inline constexpr float kMaxAppearanceFontSize = 72.0f;

/// @brief Inset, in PDF user units, applied to every edge of the
///        annotation rectangle before layout.
///
/// Available width = `box.width - 2 * kAppearanceTextMargin`.
/// Available height = `box.height - 2 * kAppearanceTextMargin`.
/// @since 4.0
inline constexpr float kAppearanceTextMargin = 4.0f;

/// @brief Multiplier applied to the selected font size to derive the
///        per-line baseline-to-baseline distance.
///
/// `lineHeight = fontSize * kAppearanceLineLeading`. The 1.2× ratio
/// matches the historical PAdES emitter (12pt leading at 9pt body) and
/// the iText FILL_BOX default.
/// @since 4.0
inline constexpr float kAppearanceLineLeading = 1.2f;

/// @brief Auto-fit layout result for a visual signature appearance.
///
/// Returned by @ref layoutVisualSignature. Consumers (the PAdES emitter,
/// the LC preview widget, the LMAC native preview) read these fields
/// verbatim — there is no second layout pass downstream.
///
/// @par Invariants (postconditions of @ref layoutVisualSignature)
///  - `fontSize ∈ [kFloorAppearanceFontSize, kMaxAppearanceFontSize]`
///  - `lineHeight == fontSize × kAppearanceLineLeading`
///  - `lines.size() ≥ 1` (a successful return ALWAYS yields ≥1 line,
///    even for empty input — `lines == {""}`)
///  - Each `lines[i]` is valid UTF-8.
///  - `clipped == true` iff floor-font wrap exceeds the box (some line's
///    measured width exceeds `availW`, OR total height exceeds `availH`).
///  - Determinism — identical input ⟹ bit-identical output, all platforms.
///
/// @since 4.0
struct VisualSignatureLayout
{
    /// @brief Selected font size in PDF user units.
    float fontSize = kFloorAppearanceFontSize;

    /// @brief Baseline-to-baseline distance in PDF user units.
    float lineHeight = kFloorAppearanceFontSize * kAppearanceLineLeading;

    /// @brief Wrapped lines of UTF-8 text. `lines.size() ≥ 1` is invariant.
    std::vector<std::string> lines;

    /// @brief True when the layout would not fit the box even at the
    ///        floor font size; the caller should install a PDF clipping
    ///        path or `painter.setClipRect`.
    bool clipped = false;
};

/// @brief Compute the auto-fit appearance layout for a visual signature.
///
/// Pure, deterministic, platform-independent. Identical inputs produce
/// bit-identical outputs across runs and platforms. Single source of
/// truth for visual-signature auto-fit across LM, LC, LMAC, future
/// LibreKDE.
///
/// @par Algorithm
/// Binary search the font size in `[kFloorAppearanceFontSize,
/// min(kMaxAppearanceFontSize, availH/leading)]`. For each candidate run
/// a greedy whitespace word-wrap to width `availW = box.width −
/// 2·kAppearanceTextMargin` measuring each line through the bundled
/// Liberation Sans subset. Accept a candidate when all wrapped lines fit
/// `availW` AND total height (`lines × fontSize × leading`) fits
/// `availH = box.height − 2·kAppearanceTextMargin`. Hard line breaks
/// (`\n`) split paragraphs; each paragraph wraps independently.
/// `\r\n` collapses to `\n`; bare `\r` is ignored; `\t` is treated as
/// space. UTF-8 boundaries are respected — wrap never splits a codepoint.
///
/// @par Edge cases
///  - Empty input ⟹ `{fontSize: kFloor, lines: {""}, clipped: false}`.
///  - Whitespace-only input ⟹ same as empty after trim.
///  - Single huge unbreakable token wider than the box at every font
///    size ⟹ `fontSize` falls to floor, single line emitted,
///    `clipped = true`.
///  - Pathological `box.width − 2·margin ≤ 0` or `box.height − 2·margin
///    ≤ 0` ⟹ `clipped = true`, single floor-font line.
///  - Glyphs absent from Liberation Sans (e.g. emoji, CJK) measure at
///    `.notdef` — preview and PDF render identical empty boxes.
///
/// @param textUtf8 Resolved UTF-8 text (any `{placeholder}` tokens
///                 already substituted by the caller). May contain `\n`
///                 for forced line breaks. May be empty.
/// @param box      Annotation rectangle in PDF user units. Width and
///                 height SHOULD be positive (validated by
///                 @ref VisualSignatureParams::Builder); pathological
///                 values are handled gracefully — the function never
///                 throws.
///
/// @return @ref VisualSignatureLayout. `lines` is never empty.
///         `clipped == true` indicates the caller should emit a PDF
///         clipping path (PAdES emitter) or `painter.setClipRect`
///         (GUI preview).
///
/// @par Thread-safety
/// Thread-safe. Pure function with no shared state; callers may invoke
/// concurrently from any thread.
///
/// @par Complexity
/// `O(N · log(K))` where N is the input byte count and K is the font-size
/// search range. Empirically < 1 ms per call for a 4-line English
/// appearance in a 200×50 box on a modern x86_64 host.
///
/// @since 4.0
[[nodiscard]] LIBRESCRS_PUBLIC_API VisualSignatureLayout layoutVisualSignature(std::string_view textUtf8,
                                                                               Rect box) noexcept;

/// @brief Raw bytes of the bundled Liberation Sans Regular TTF.
///
/// The returned span points into compile-time program data and remains
/// valid for the program lifetime. GUI consumers (LibreCelik,
/// LibreMac/BridgeNative, future LibreKDE) pass these bytes to their
/// font system to render preview-mode appearance text using the same
/// font as the embedded PDF subset, ensuring preview-vs-PDF parity.
///
/// @par Lifetime
/// The span aliases program-data; the underlying bytes are valid until
/// the process exits. Do NOT free, do NOT copy unless you must — the
/// pointer is stable.
///
/// @par Thread-safety
/// Thread-safe; pure function, returns an immutable view.
///
/// @return Span over the embedded Liberation Sans Regular TTF. Always
///         non-empty.
///
/// @since 4.0
[[nodiscard]] LIBRESCRS_PUBLIC_API std::span<const std::byte> embeddedAppearanceFontData() noexcept;

} // namespace LibreSCRS::Signing
