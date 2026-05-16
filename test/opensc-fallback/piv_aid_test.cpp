// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Tests for vendored OpenSC PIV recognition after our downstream patches.
//
// `piv_find_aid` is `static` inside libopensc/card-piv.c and therefore not
// directly callable from a unit test translation unit. The authoritative
// coverage for "G+D SCE7 is recognized as PIV" is the real-card integration
// matrix. This fixture is a low-cost guard that asserts the patched ATR
// string is physically present in the vendored source tree after configure
// time, so accidental loss of the patch (e.g. submodule re-checkout without
// re-running the CMake auto-apply hook) is caught by `ctest`.

#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>

namespace {

// Path baked in at configure time so the test does not need to discover the
// LM source root at runtime.
constexpr const char* kCardPivSourcePath = LIBRESCRS_OPENSC_CARD_PIV_C;

// Read whole file into a string. Returns empty string on failure; the
// caller asserts non-empty before searching.
std::string ReadFile(const std::filesystem::path& path)
{
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        return {};
    }
    std::ostringstream buffer;
    buffer << input.rdbuf();
    return buffer.str();
}

} // namespace

TEST(PivAidPatch, GdSce7AtrPresentInPivAtrsTable)
{
    const std::filesystem::path source_path = kCardPivSourcePath;
    ASSERT_TRUE(std::filesystem::exists(source_path))
        << "vendored card-piv.c not found at " << source_path
        << "; configure-time path must point inside thirdparty/opensc-source";

    const std::string contents = ReadFile(source_path);
    ASSERT_FALSE(contents.empty()) << "card-piv.c read returned empty buffer";

    // The patched ATR string for the Giesecke+Devrient PIV SCE7 variant.
    // See thirdparty/patches/0001-piv-add-gd-sce7-atr-readme.md for capture
    // context and rationale.
    constexpr const char* kExpectedAtr = "3B:F9:96:00:00:80:31:FE:45:53:43:45:37:20:0F:00:20:46:4E";
    EXPECT_NE(contents.find(kExpectedAtr), std::string::npos)
        << "downstream patch 0001-piv-add-gd-sce7-atr is missing from "
           "vendored OpenSC source; re-run cmake to trigger the auto-apply "
           "hook in thirdparty/CMakeLists.txt";
}
