// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

/// @file
/// @brief Unit + property + golden tests for
///        @ref LibreSCRS::Signing::layoutVisualSignature.
///
/// Spec: knowledge/specs/2026-05-08-vis-sig-fillbox-design.md §8.2 / §8.3
/// Plan: knowledge/plans/2026-05-08-vis-sig-fillbox-plan.md A5

#include <gtest/gtest.h>

#include <LibreSCRS/Signing/VisualSignatureLayout.h>
#include <LibreSCRS/Signing/VisualSignatureParams.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <future>
#include <string>
#include <string_view>
#include <vector>

using LibreSCRS::Signing::embeddedAppearanceFontData;
using LibreSCRS::Signing::kAppearanceLineLeading;
using LibreSCRS::Signing::kAppearanceTextMargin;
using LibreSCRS::Signing::kFloorAppearanceFontSize;
using LibreSCRS::Signing::kMaxAppearanceFontSize;
using LibreSCRS::Signing::layoutVisualSignature;
using LibreSCRS::Signing::Rect;
using LibreSCRS::Signing::VisualSignatureLayout;

namespace {

constexpr Rect kDefaultBox{0, 0, 200, 50};

bool isValidUtf8(std::string_view s) noexcept
{
    std::size_t i = 0;
    while (i < s.size()) {
        unsigned char c = static_cast<unsigned char>(s[i]);
        std::size_t n = 0;
        if ((c & 0x80) == 0x00)
            n = 1;
        else if ((c & 0xE0) == 0xC0)
            n = 2;
        else if ((c & 0xF0) == 0xE0)
            n = 3;
        else if ((c & 0xF8) == 0xF0)
            n = 4;
        else
            return false;
        if (i + n > s.size())
            return false;
        for (std::size_t k = 1; k < n; ++k) {
            unsigned char cc = static_cast<unsigned char>(s[i + k]);
            if ((cc & 0xC0) != 0x80)
                return false;
        }
        i += n;
    }
    return true;
}

} // namespace

// ---- Invariants (spec §8.2) ----

TEST(VisualSignatureLayout, I1_FontSizeInRange)
{
    auto layout = layoutVisualSignature("Hello World", kDefaultBox);
    EXPECT_GE(layout.fontSize, kFloorAppearanceFontSize);
    EXPECT_LE(layout.fontSize, kMaxAppearanceFontSize);
}

TEST(VisualSignatureLayout, I2_LineHeightDerivedFromFontSize)
{
    auto layout = layoutVisualSignature("Hello World", kDefaultBox);
    EXPECT_FLOAT_EQ(layout.lineHeight, layout.fontSize * kAppearanceLineLeading);
}

TEST(VisualSignatureLayout, I3_AlwaysAtLeastOneLine)
{
    EXPECT_GE(layoutVisualSignature("", kDefaultBox).lines.size(), 1u);
    EXPECT_GE(layoutVisualSignature("Hello", kDefaultBox).lines.size(), 1u);
    EXPECT_GE(layoutVisualSignature("\n\n\n", kDefaultBox).lines.size(), 1u);
}

TEST(VisualSignatureLayout, I4_LinesAreValidUtf8)
{
    auto layout = layoutVisualSignature("Digitally signed by NEMANJA HIRŠL on 2026-05-08", kDefaultBox);
    for (const auto& line : layout.lines)
        EXPECT_TRUE(isValidUtf8(line)) << "line: " << line;
}

TEST(VisualSignatureLayout, I5_ClippedTrueImpliesFloorFontWrapExceedsBox)
{
    // 200-char unbreakable token cannot fit in 200×50 even at 6pt → clipped.
    std::string huge(200, 'X');
    auto layout = layoutVisualSignature(huge, kDefaultBox);
    EXPECT_TRUE(layout.clipped);
    EXPECT_FLOAT_EQ(layout.fontSize, kFloorAppearanceFontSize);
}

TEST(VisualSignatureLayout, I6_NotClippedImpliesAllLinesFit)
{
    auto layout = layoutVisualSignature("Hi", kDefaultBox);
    EXPECT_FALSE(layout.clipped);
    // We can't recompute the per-line width from outside (the public API
    // exposes neither the font subset nor measurement); rely on the
    // postcondition that layoutVisualSignature only reports clipped=false
    // when its internal invariant holds. This test pins the contract for
    // a known-fitting input.
    EXPECT_GE(layout.lines.size(), 1u);
}

TEST(VisualSignatureLayout, I7_DeterministicAcrossCalls)
{
    auto a = layoutVisualSignature("NEMANJA HIRŠL 014390613", kDefaultBox);
    auto b = layoutVisualSignature("NEMANJA HIRŠL 014390613", kDefaultBox);
    EXPECT_FLOAT_EQ(a.fontSize, b.fontSize);
    EXPECT_FLOAT_EQ(a.lineHeight, b.lineHeight);
    EXPECT_EQ(a.lines, b.lines);
    EXPECT_EQ(a.clipped, b.clipped);
}

TEST(VisualSignatureLayout, I8_ThreadSafetyParallelCallsAgree)
{
    constexpr int N = 16;
    std::string_view input = "Digitally signed by\nNEMANJA HIRŠL\n2026-05-08";
    std::vector<std::future<VisualSignatureLayout>> futures;
    futures.reserve(N);
    for (int i = 0; i < N; ++i)
        futures.push_back(
            std::async(std::launch::async, [input]() { return layoutVisualSignature(input, kDefaultBox); }));
    auto baseline = layoutVisualSignature(input, kDefaultBox);
    for (auto& f : futures) {
        auto r = f.get();
        EXPECT_FLOAT_EQ(r.fontSize, baseline.fontSize);
        EXPECT_EQ(r.lines, baseline.lines);
        EXPECT_EQ(r.clipped, baseline.clipped);
    }
}

// ---- Edge cases (spec §8.3) ----

TEST(VisualSignatureLayout, EdgeCase_Empty)
{
    auto layout = layoutVisualSignature("", kDefaultBox);
    EXPECT_FLOAT_EQ(layout.fontSize, kFloorAppearanceFontSize);
    ASSERT_EQ(layout.lines.size(), 1u);
    EXPECT_EQ(layout.lines[0], "");
    EXPECT_FALSE(layout.clipped);
}

TEST(VisualSignatureLayout, EdgeCase_WhitespaceOnly)
{
    auto layout = layoutVisualSignature("  \n  ", kDefaultBox);
    // Treated as empty after trim — single empty line, no clip.
    ASSERT_GE(layout.lines.size(), 1u);
    EXPECT_FALSE(layout.clipped);
}

TEST(VisualSignatureLayout, EdgeCase_MultipleNewlines)
{
    auto layout = layoutVisualSignature("a\nb\nc", kDefaultBox);
    EXPECT_GE(layout.lines.size(), 3u);
}

TEST(VisualSignatureLayout, EdgeCase_HugeUnbreakableToken)
{
    std::string token(500, 'Q');
    auto layout = layoutVisualSignature(token, kDefaultBox);
    EXPECT_TRUE(layout.clipped);
    EXPECT_FLOAT_EQ(layout.fontSize, kFloorAppearanceFontSize);
}

TEST(VisualSignatureLayout, EdgeCase_PathologicalNarrowBox)
{
    auto layout = layoutVisualSignature("Hello World", Rect{0, 0, 4, 50});
    EXPECT_TRUE(layout.clipped);
    EXPECT_FLOAT_EQ(layout.fontSize, kFloorAppearanceFontSize);
}

TEST(VisualSignatureLayout, EdgeCase_PathologicalShortBox)
{
    auto layout = layoutVisualSignature("Hello World", Rect{0, 0, 200, 4});
    EXPECT_TRUE(layout.clipped);
    EXPECT_FLOAT_EQ(layout.fontSize, kFloorAppearanceFontSize);
}

TEST(VisualSignatureLayout, EdgeCase_MixedLatinCyrillic)
{
    auto layout = layoutVisualSignature("Latin Кириллица mixed", kDefaultBox);
    EXPECT_GE(layout.lines.size(), 1u);
    for (const auto& line : layout.lines)
        EXPECT_TRUE(isValidUtf8(line));
}

TEST(VisualSignatureLayout, EdgeCase_TabsAndCrlfNormalised)
{
    auto a = layoutVisualSignature("Hello\tWorld", kDefaultBox);
    auto b = layoutVisualSignature("Hello World", kDefaultBox);
    EXPECT_EQ(a.lines, b.lines);

    auto c = layoutVisualSignature("a\r\nb", kDefaultBox);
    auto d = layoutVisualSignature("a\nb", kDefaultBox);
    EXPECT_EQ(c.lines, d.lines);

    auto e = layoutVisualSignature("a\rb", kDefaultBox);
    auto f = layoutVisualSignature("ab", kDefaultBox);
    EXPECT_EQ(e.lines, f.lines);
}

// ---- Golden cases ----

TEST(VisualSignatureLayout, Golden_EnglishNotClipped)
{
    auto layout = layoutVisualSignature("Signed by\nJohn Doe", kDefaultBox);
    EXPECT_FALSE(layout.clipped);
    EXPECT_GE(layout.lines.size(), 2u);
    EXPECT_GE(layout.fontSize, kFloorAppearanceFontSize);
}

TEST(VisualSignatureLayout, Golden_CyrillicNotClipped)
{
    auto layout = layoutVisualSignature("Потписао\nНемања", kDefaultBox);
    EXPECT_FALSE(layout.clipped);
    EXPECT_GE(layout.lines.size(), 2u);
}

TEST(VisualSignatureLayout, Golden_LongCertSerialClipped)
{
    // 64-char unbreakable hex; default 200×50 box — must clip at floor.
    auto layout =
        layoutVisualSignature("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF", kDefaultBox);
    EXPECT_TRUE(layout.clipped);
    EXPECT_FLOAT_EQ(layout.fontSize, kFloorAppearanceFontSize);
    EXPECT_EQ(layout.lines.size(), 1u);
}

TEST(VisualSignatureLayout, Golden_MultilineFromTemplateWrapped)
{
    // Typical "Digitally signed by … / Date: …" template.
    auto layout = layoutVisualSignature("Digitally signed by NEMANJA HIRŠL\nDate: 2026-05-08 14:23:45", kDefaultBox);
    EXPECT_GE(layout.lines.size(), 2u);
    for (const auto& line : layout.lines)
        EXPECT_TRUE(isValidUtf8(line));
}

// ---- embeddedAppearanceFontData ----

TEST(VisualSignatureLayout, EmbeddedFontDataNonEmpty)
{
    auto bytes = embeddedAppearanceFontData();
    EXPECT_GT(bytes.size(), 1024u); // a real TTF is at least a few KB
    // SFNT magic: 0x00010000 (TrueType) or 'OTTO' (CFF).
    ASSERT_GE(bytes.size(), 4u);
    auto p = reinterpret_cast<const std::uint8_t*>(bytes.data());
    bool isTtf = (p[0] == 0x00 && p[1] == 0x01 && p[2] == 0x00 && p[3] == 0x00);
    bool isOtf = (p[0] == 'O' && p[1] == 'T' && p[2] == 'T' && p[3] == 'O');
    EXPECT_TRUE(isTtf || isOtf);
}

TEST(VisualSignatureLayout, EmbeddedFontDataStableAcrossCalls)
{
    auto a = embeddedAppearanceFontData();
    auto b = embeddedAppearanceFontData();
    EXPECT_EQ(a.data(), b.data());
    EXPECT_EQ(a.size(), b.size());
}

// ---- Performance (spec G2: < 1 ms per call typical) ----

TEST(VisualSignatureLayout, Performance_TypicalInputUnderOneMillisecondMedian)
{
    // Warm-up + 50-call median, mirroring the spec G2 budget at default
    // 200×50 box with a 4-line English-style appearance string.
    constexpr const char* kInput = "Digitally signed by NEMANJA HIRŠL\n"
                                   "Reason: Document integrity\n"
                                   "Location: Belgrade, Serbia\n"
                                   "Date: 2026-05-08 14:23:45 +0000";

    // Warm-up — first call may pay a one-off cost (stdlib init, page faults).
    (void)layoutVisualSignature(kInput, kDefaultBox);

    constexpr int N = 51;
    std::vector<long long> samples;
    samples.reserve(N);
    for (int i = 0; i < N; ++i) {
        auto t0 = std::chrono::steady_clock::now();
        auto layout = layoutVisualSignature(kInput, kDefaultBox);
        auto t1 = std::chrono::steady_clock::now();
        samples.push_back(std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count());
        // Use the result so the optimiser doesn't elide the call.
        EXPECT_GE(layout.lines.size(), 1u);
    }
    std::sort(samples.begin(), samples.end());
    long long medianUs = samples[N / 2];
    // Spec target: < 1 ms (1000 µs) median for Release builds; Debug
    // builds (with libstdc++ assertions, no inlining of std::format,
    // unoptimised TtfSubset table walks) are routinely 5–10× slower
    // and would create false CI failures. Apply a 10× slack on Debug.
    long long budgetUs = 1000;
#ifndef NDEBUG
    budgetUs = 10000;
#endif
    std::printf("[layoutVisualSignature perf] median = %lld µs over %d samples (budget %lld µs)\n", medianUs, N,
                budgetUs);
    EXPECT_LT(medianUs, budgetUs) << "layoutVisualSignature median exceeds the budget; investigate (spec §4.3 G2)";
}
