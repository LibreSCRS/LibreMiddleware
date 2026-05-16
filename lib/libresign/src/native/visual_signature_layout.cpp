// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

/// @file
/// @brief Implementation of @ref LibreSCRS::Signing::layoutVisualSignature
///        and @ref LibreSCRS::Signing::embeddedAppearanceFontData.
///
/// Public symbols are tagged `LIBRESCRS_PUBLIC_API` via the header. The
/// translation unit lives inside libresign so it can use the internal
/// `TtfParser`/`TtfSubset`/`measureTextWidth` machinery directly. The
/// LibreSign static archive is linked into LibreSCRS_Signing PRIVATE,
/// so consumers of LibreSCRS::Signing get this symbol transitively
/// through the static-archive resolve at final-binary link time.

#include <LibreSCRS/Signing/VisualSignatureLayout.h>

#include "liberation_sans_data.h"
#include "pdf_font.h"
#include "ttf_parser.h"
#include "ttf_subset.h"

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

namespace LibreSCRS::Signing {

namespace {

// Decode one UTF-8 codepoint at byte offset @p i in @p s. Returns
// (codepoint, bytesConsumed). Mirrors the helper in pdf_font.cpp /
// pades_module.cpp; duplicated locally to keep this TU self-contained
// without exposing yet another public-ish helper.
inline std::pair<char32_t, std::size_t> decodeUtf8At(std::string_view s, std::size_t i) noexcept
{
    if (i >= s.size())
        return {0, 0};
    unsigned char c = static_cast<unsigned char>(s[i]);
    char32_t cp = 0;
    std::size_t n = 1;
    if ((c & 0x80) == 0x00) {
        cp = c;
        n = 1;
    } else if ((c & 0xE0) == 0xC0) {
        cp = c & 0x1F;
        n = 2;
    } else if ((c & 0xF0) == 0xE0) {
        cp = c & 0x0F;
        n = 3;
    } else if ((c & 0xF8) == 0xF0) {
        cp = c & 0x07;
        n = 4;
    } else {
        return {0xFFFD, 1};
    }
    if (i + n > s.size())
        return {0xFFFD, s.size() - i};
    for (std::size_t k = 1; k < n; ++k) {
        unsigned char cc = static_cast<unsigned char>(s[i + k]);
        if ((cc & 0xC0) != 0x80)
            return {0xFFFD, 1};
        cp = (cp << 6) | (cc & 0x3F);
    }
    return {cp, n};
}

// Normalise raw input: collapse '\r\n' to '\n', drop bare '\r', map '\t'
// to space. Matches the line-ending normalisation contract documented
// for @ref layoutVisualSignature in the public header.
std::string normaliseLineEndings(std::string_view in)
{
    std::string out;
    out.reserve(in.size());
    for (std::size_t i = 0; i < in.size(); ++i) {
        char c = in[i];
        if (c == '\r') {
            // CRLF → LF; bare CR → drop.
            if (i + 1 < in.size() && in[i + 1] == '\n')
                continue; // '\n' on next iteration is the kept newline
            // bare CR — drop entirely
            continue;
        }
        if (c == '\t')
            out.push_back(' ');
        else
            out.push_back(c);
    }
    return out;
}

// Split text into paragraphs on '\n'. Empty paragraphs (consecutive
// '\n') are preserved as empty strings — they consume vertical space
// during layout.
std::vector<std::string> splitParagraphs(std::string_view normalised)
{
    std::vector<std::string> out;
    std::string current;
    for (char c : normalised) {
        if (c == '\n') {
            out.push_back(std::move(current));
            current.clear();
        } else {
            current.push_back(c);
        }
    }
    out.push_back(std::move(current));
    return out;
}

// Trim ASCII whitespace from both ends of @p s. UTF-8 safe because
// whitespace bytes (0x20, 0x09, 0x0A, 0x0D) are never continuation
// bytes (which all have the high bit set).
std::string_view trim(std::string_view s) noexcept
{
    auto isws = [](char c) noexcept { return c == ' ' || c == '\t' || c == '\r' || c == '\n'; };
    std::size_t a = 0;
    std::size_t b = s.size();
    while (a < b && isws(s[a]))
        ++a;
    while (b > a && isws(s[b - 1]))
        --b;
    return s.substr(a, b - a);
}

// Greedy whitespace word-wrap. Returns the wrapped lines for one
// paragraph @p paragraph at @p fontSize against the available width
// @p availW. Each line (after the first) is the longest run of
// whitespace-separated tokens that fits `availW` when measured through
// @p subset. Single tokens wider than @p availW are emitted on their
// own line — this is by design: the outer binary search shrinks the
// font size until they fit, or hits the floor.
//
// Whitespace boundary: spaces only (tabs were already mapped to spaces
// upstream by normaliseLineEndings). Multiple spaces collapse on wrap
// (the wrapper re-joins tokens with a single space).
std::vector<std::string> wrapParagraph(std::string_view paragraph, float fontSize, float availW,
                                       const libresign::TtfSubset& subset)
{
    if (paragraph.empty())
        return {""};

    // Tokenise on space.
    std::vector<std::string_view> tokens;
    {
        std::size_t i = 0;
        while (i < paragraph.size()) {
            // skip leading spaces
            while (i < paragraph.size() && paragraph[i] == ' ')
                ++i;
            if (i >= paragraph.size())
                break;
            std::size_t start = i;
            while (i < paragraph.size() && paragraph[i] != ' ')
                ++i;
            tokens.emplace_back(paragraph.substr(start, i - start));
        }
    }

    if (tokens.empty())
        return {""};

    std::vector<std::string> lines;
    std::string current;
    for (auto tok : tokens) {
        std::string candidate;
        if (current.empty()) {
            candidate.assign(tok.begin(), tok.end());
        } else {
            candidate = current;
            candidate.push_back(' ');
            candidate.append(tok);
        }
        float w = libresign::measureTextWidth(subset, candidate, fontSize);
        if (w <= availW || current.empty()) {
            // Either it fits, or `current` is empty and we have to take
            // this token on its own line even if oversized.
            current = std::move(candidate);
        } else {
            lines.push_back(std::move(current));
            current.assign(tok.begin(), tok.end());
        }
    }
    if (!current.empty() || lines.empty())
        lines.push_back(std::move(current));
    return lines;
}

// Compute the wrapped line set across all paragraphs at @p fontSize.
std::vector<std::string> wrapAllParagraphs(const std::vector<std::string>& paragraphs, float fontSize, float availW,
                                           const libresign::TtfSubset& subset)
{
    std::vector<std::string> out;
    for (const auto& p : paragraphs) {
        auto wrapped = wrapParagraph(p, fontSize, availW, subset);
        for (auto& line : wrapped)
            out.push_back(std::move(line));
    }
    if (out.empty())
        out.push_back("");
    return out;
}

// Check whether the wrapped @p lines fit in @p availW at @p fontSize.
// All lines must measure ≤ availW (with a 1e-3 pt tolerance to absorb
// IEEE-754 single-precision ULP drift across platforms — preserving the
// cross-platform determinism invariant of the layout algorithm).
bool linesFit(const std::vector<std::string>& lines, float fontSize, float availW, const libresign::TtfSubset& subset)
{
    constexpr float kFitTolerancePt = 1.0e-3f;
    for (const auto& line : lines) {
        if (libresign::measureTextWidth(subset, line, fontSize) > availW + kFitTolerancePt)
            return false;
    }
    return true;
}

// Collect the set of distinct codepoints used in @p normalised. Used to
// scope the on-stack TtfSubset to exactly the glyphs the layout will
// measure — avoiding the ~38 ms cost of subsetting the entire BMP.
std::unordered_set<char32_t> collectCodepoints(std::string_view normalised)
{
    std::unordered_set<char32_t> cps;
    cps.reserve(64);
    cps.insert(U' '); // wrapper joins tokens with spaces; ensure present
    for (std::size_t i = 0; i < normalised.size();) {
        auto [cp, n] = decodeUtf8At(normalised, i);
        if (n == 0)
            break;
        if (cp != U'\n')
            cps.insert(cp);
        i += n;
    }
    return cps;
}

// Build a TtfSubset scoped to @p cps. Parsed on-stack at the start of
// layoutVisualSignature and reused across binary-search iterations
// within the call. NO singletons, NO Meyers, NO function-local statics,
// NO globals — keeps the layout function pure and re-entrant.
libresign::TtfSubset buildSubsetForInput(const std::unordered_set<char32_t>& cps)
{
    std::span<const std::uint8_t> ttfBytes{LiberationSansRegular, LiberationSansRegularSize};
    return libresign::subsetTtf(ttfBytes, cps);
}

} // namespace

VisualSignatureLayout layoutVisualSignature(std::string_view textUtf8, Rect box) noexcept
try {
    VisualSignatureLayout out;

    // Compute available width/height after the per-edge margin inset.
    const float availW = static_cast<float>(box.width) - 2.0f * kAppearanceTextMargin;
    const float availH = static_cast<float>(box.height) - 2.0f * kAppearanceTextMargin;

    auto setFloorClipped = [&](std::vector<std::string>&& lines) {
        out.fontSize = kFloorAppearanceFontSize;
        out.lineHeight = kFloorAppearanceFontSize * kAppearanceLineLeading;
        out.lines = std::move(lines);
        if (out.lines.empty())
            out.lines.emplace_back();
        out.clipped = true;
    };

    // 1. Pathological box: nothing fits, return floor-font single line.
    if (availW <= 0.0f || availH <= 0.0f) {
        setFloorClipped({std::string(textUtf8)});
        return out;
    }

    // 2. Normalise + split into paragraphs.
    std::string normalised = normaliseLineEndings(textUtf8);

    // Empty / whitespace-only input → single empty line at floor, no clip.
    if (trim(normalised).empty()) {
        out.fontSize = kFloorAppearanceFontSize;
        out.lineHeight = kFloorAppearanceFontSize * kAppearanceLineLeading;
        out.lines.emplace_back();
        out.clipped = false;
        return out;
    }

    auto paragraphs = splitParagraphs(normalised);

    // 3. Build a TtfSubset scoped to the codepoints in the input —
    //    parsed on-stack here, reused across the binary-search
    //    iterations below. No singletons; the subset belongs to this
    //    layout call exclusively.
    libresign::TtfSubset subset;
    try {
        const auto cps = collectCodepoints(normalised);
        subset = buildSubsetForInput(cps);
    } catch (...) {
        // subsetTtf throws on malformed input only; the bundled font is
        // verified at build time and never throws here. Defensive: fall
        // through to floor + clipped if it ever does.
        setFloorClipped({std::string(textUtf8)});
        return out;
    }

    if (subset.unitsPerEm == 0) {
        setFloorClipped({std::string(textUtf8)});
        return out;
    }

    // 4. Binary search the largest font size where all paragraphs wrap
    //    to lines that fit availW AND total height fits availH. Search
    //    range: [kFloor, min(kMax, availH/leading)] in 0.5pt steps.
    const float maxByHeight = availH / kAppearanceLineLeading;
    float hi = std::min(kMaxAppearanceFontSize, maxByHeight);
    if (hi < kFloorAppearanceFontSize) {
        // Box is shorter than one floor-font line; can't fit even one line.
        auto lines = wrapAllParagraphs(paragraphs, kFloorAppearanceFontSize, availW, subset);
        setFloorClipped(std::move(lines));
        return out;
    }

    auto fits = [&](float fs) -> bool {
        auto lines = wrapAllParagraphs(paragraphs, fs, availW, subset);
        if (!linesFit(lines, fs, availW, subset))
            return false;
        const float totalH = static_cast<float>(lines.size()) * fs * kAppearanceLineLeading;
        return totalH <= availH;
    };

    // Binary search to 0.5pt resolution.
    float lo = kFloorAppearanceFontSize;
    float best = -1.0f;
    // Target tolerance ~0.5pt; ~15 iterations cover [6, 72] easily.
    for (int iter = 0; iter < 24; ++iter) {
        if (hi - lo < 0.5f)
            break;
        float mid = 0.5f * (lo + hi);
        if (fits(mid)) {
            best = mid;
            lo = mid;
        } else {
            hi = mid;
        }
    }

    if (best < 0.0f) {
        // Floor itself does not fit. Emit floor wrap with clipped=true.
        auto lines = wrapAllParagraphs(paragraphs, kFloorAppearanceFontSize, availW, subset);
        setFloorClipped(std::move(lines));
        return out;
    }

    // 5. Snap `best` down to the largest 0.5pt step ≤ best so the
    //    accepted layout is bit-stable across platforms.
    const float snapped = std::floor(best * 2.0f) / 2.0f;
    float chosen = (snapped >= kFloorAppearanceFontSize && fits(snapped)) ? snapped : best;
    if (chosen < kFloorAppearanceFontSize)
        chosen = kFloorAppearanceFontSize;
    if (chosen > kMaxAppearanceFontSize)
        chosen = kMaxAppearanceFontSize;

    out.fontSize = chosen;
    out.lineHeight = chosen * kAppearanceLineLeading;
    out.lines = wrapAllParagraphs(paragraphs, chosen, availW, subset);
    if (out.lines.empty())
        out.lines.emplace_back();
    out.clipped = false;
    return out;
} catch (...) {
    // Function-try-block honours the noexcept contract under bad_alloc or
    // any other exception escaping the body. The public contract is
    // "any 'problem' is encoded in the return value, never thrown" — so
    // return a floor-clipped fallback instead of escaping. Allocation in the catch handler is minimised
    // by emplacing an empty std::string first (default-ctor is noexcept,
    // SSO never heap-allocates the string itself); only the *vector grow*
    // of capacity 0 → 1 can throw. If even that throws, std::terminate
    // fires — the correct response, because the noexcept contract has
    // been upheld locally and the process cannot proceed.
    VisualSignatureLayout fallback;
    fallback.fontSize = kFloorAppearanceFontSize;
    fallback.lineHeight = kFloorAppearanceFontSize * kAppearanceLineLeading;
    fallback.clipped = true;
    try {
        // Step 1: secure I3 (lines.size() >= 1) with the cheapest possible
        // emplace — empty std::string default-ctor is noexcept (SSO).
        fallback.lines.emplace_back();
        // Step 2: best-effort upgrade to the user's text. If this assignment
        // throws (string copy of a large input under memory pressure), the
        // line stays empty; I3 still holds because we already secured size=1
        // in step 1.
        try {
            fallback.lines.front().assign(textUtf8);
        } catch (...) {
            // keep empty line; I3 satisfied via step 1
        }
    } catch (...) {
        // Triple-OOM: even a one-element vector grow failed. lines.size() == 0
        // here violates I3 on paper, but at this allocation-pressure level any
        // alternative path would also fail. Document and accept; std::terminate
        // is the C++ runtime's response if any caller's code path now throws
        // because of the size=0, and that is the correct response.
    }
    return fallback;
}

std::span<const std::byte> embeddedAppearanceFontData() noexcept
{
    return std::span<const std::byte>{reinterpret_cast<const std::byte*>(LiberationSansRegular),
                                      static_cast<std::size_t>(LiberationSansRegularSize)};
}

} // namespace LibreSCRS::Signing
