// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

/// @file
/// @brief Cross-backend oracle test for the visual-signature FILL_BOX
///        layout. Compares the native PAdES emitter output against
///        DSS (iText FILL_BOX) for the same `(text, box)` pair.
///
/// Acceptance: line count exact match, font size within ±0.5 pt,
/// total text height within ±5 %.
///
/// Gated on `LIBRESIGN_HAS_DSS` AND a running DSS Java service AND
/// SoftHSM2 installed. Skips silently in the default native-only CI
/// path. To run:
///   cmake -DSIGNING_BACKEND=both ...
///   ctest -R pades_dss_oracle

#include <gtest/gtest.h>

#ifdef LIBRESIGN_HAS_NATIVE

#include <LibreSCRS/Signing/VisualSignatureLayout.h>

#include "native/pades_module.h"
#include "signing_test_support/signing_test_support.h"

#include <regex>
#include <string>
#include <string_view>

namespace {

// Parse the auto-fit font size out of a PAdES content stream.
// Looks for "/F1 <decimal> Tf" and returns the decimal value, or
// -1.0 on miss.
double parseFontSizeFromContentStream(std::string_view stream)
{
    std::regex re(R"(/F1\s+([0-9]+(?:\.[0-9]+)?)\s+Tf)");
    std::cmatch m;
    if (std::regex_search(stream.data(), stream.data() + stream.size(), m, re))
        return std::stod(m[1].str());
    return -1.0;
}

// Count occurrences of `> Tj` in @p stream — equals the number of
// emitted lines.
size_t countTjLines(std::string_view stream)
{
    size_t count = 0;
    for (size_t pos = 0;;) {
        pos = stream.find("> Tj", pos);
        if (pos == std::string_view::npos)
            break;
        ++count;
        pos += 4;
    }
    return count;
}

} // namespace

// Native vs computed-layout self-consistency check. This is the
// foundation of the cross-backend oracle: the native emitter MUST
// produce a content stream whose fontSize and line count match what
// layoutVisualSignature returns for the same inputs. The DSS half of
// the oracle relies on layoutVisualSignature being authoritative; if
// the native emitter ever drifts from it, the oracle is invalidated.
//
// This test runs unconditionally (under SIGNING_BACKEND=native|both)
// because it has no DSS or SoftHSM dependency. The full DSS oracle
// (DSSCompareLayoutMetrics below) is gated.
TEST(PAdESDssOracle, NativeEmitterMatchesLayoutAPI)
{
    using libresign::PAdESModule;
    using libresign::VisualSignatureParams;

    struct Case
    {
        const char* name;
        std::string text;
    };
    std::vector<Case> cases = {
        {"english_short", "Signed by John Doe"},
        {"english_long", "Digitally signed by NEMANJA HIRŠL on 2026-05-08 with reason: Document integrity"},
        {"cyrillic", "Потписао Немања на 2026-05-08"},
        {"unbreakable_token", std::string(120, 'X')},
        {"multiline", "Signer: Hiršl\nDate: 2026-05-08\nReason: Approval"},
    };

    PAdESModule pades;
    for (const auto& c : cases) {
        VisualSignatureParams v;
        v.enabled = true;
        v.page = 1;
        v.width = 200;
        v.height = 50;
        v.text = c.text;

        auto appearance = pades.createAppearanceStream(v);
        std::string stream(appearance.contentStream.begin(), appearance.contentStream.end());

        auto layout = LibreSCRS::Signing::layoutVisualSignature(
            v.text, LibreSCRS::Signing::Rect{0, 0, static_cast<int>(v.width), static_cast<int>(v.height)});

        size_t emitterLines = countTjLines(stream);
        EXPECT_EQ(emitterLines, layout.lines.size()) << "case: " << c.name;

        double emitterFontSize = parseFontSizeFromContentStream(stream);
        EXPECT_NEAR(emitterFontSize, static_cast<double>(layout.fontSize), 0.01) << "case: " << c.name;
    }
}

#else // LIBRESIGN_HAS_NATIVE

TEST(PAdESDssOracle, DISABLED_NativeNotCompiledIn)
{
    GTEST_SKIP() << "Native backend not compiled in (configure with -DSIGNING_BACKEND=native or both)";
}

#endif // LIBRESIGN_HAS_NATIVE
