// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "internal/BundledCertsProvider.h"

#include <gtest/gtest.h>

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>
#include <system_error>
#include <unistd.h>

namespace fs = std::filesystem;
using LibreSCRS::Trust::detail::resolveBundledCertsDir;

namespace {

// Certificate directory this binary is compiled against. The target stages an
// FHS-like prefix at configure time and points the installed-location define
// at it; the dev-tree define is forced empty. That combination reproduces a
// packaged runtime, where no source tree exists and the certificates live
// under a data root the binary cannot reach by walking up its own path.
const fs::path kStagedCertsDir{LIBRESCRS_STAGED_CERTS_DIR};

class BundledCertsInstallLayoutTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        ::unsetenv("LIBRESCRS_CERTIFICATES_DIR");
    }
    void TearDown() override
    {
        ::unsetenv("LIBRESCRS_CERTIFICATES_DIR");
    }
};

// Regression sentinel. A build with no source tree behind it must still find
// its bundled anchors. Without an installed-location candidate the walker
// runs off the end of the ladder and every bundled root silently disappears
// from an installed build — the failure mode that reaches users as
// "certificate chain incomplete" against a perfectly good card.
TEST_F(BundledCertsInstallLayoutTest, PackagedLayoutResolvesWithoutDevTree)
{
#ifdef __linux__
    // Guard the premise: the exe-relative rung must be a dead end here, or a
    // pass would prove nothing about the installed-location rung.
    std::error_code ec;
    const auto exeDir = fs::read_symlink("/proc/self/exe", ec).parent_path();
    ASSERT_FALSE(ec) << "cannot locate test binary to verify the premise";
    ASSERT_FALSE(fs::exists(exeDir / ".." / "share" / "librescrs" / "certificates", ec))
        << "exe-relative candidate exists — this test no longer isolates the installed location";
#endif

    auto resolved = resolveBundledCertsDir();
    ASSERT_TRUE(resolved.has_value()) << "packaged build resolved no certificate directory at all";
}

TEST_F(BundledCertsInstallLayoutTest, InstalledLocationIsTheResolvedDirectory)
{
    auto resolved = resolveBundledCertsDir();
    ASSERT_TRUE(resolved.has_value());
    std::error_code ec;
    EXPECT_EQ(*resolved, fs::weakly_canonical(kStagedCertsDir, ec));
}

#ifdef __linux__
// A self-contained relocatable package (an AppImage staged with prefix /usr)
// carries its payload NEXT TO its binaries while the baked install path
// points at the HOST system. The self-relative candidates must therefore
// outrank the absolute installed location, or a relocated package silently
// loads the host's trust anchors instead of its own. This binary compiles
// the resolver in directly, so dladdr collapses the library rung into the
// exe rung — staging the payload exe-relative exercises the same ordering
// property (self-relative before installed) through the same ladder walk.
TEST_F(BundledCertsInstallLayoutTest, SelfRelativePayloadOutranksInstalledLocation)
{
    std::error_code ec;
    const auto exePath = fs::read_symlink("/proc/self/exe", ec);
    ASSERT_FALSE(ec) << "cannot locate the test binary";

    const auto shareDir = fs::weakly_canonical(exePath.parent_path() / ".." / "share", ec);
    ASSERT_FALSE(ec);
    const auto candidate = shareDir / "librescrs" / "certificates";
    // Premise guard: the candidate must not pre-exist, or this test would
    // prove nothing about the ordering (and would destroy real data below).
    ASSERT_FALSE(fs::exists(candidate, ec)) << "library-relative candidate already exists: " << candidate;

    // Remember how deep the pre-existing tree goes so cleanup removes only
    // what this test created — never a sibling's data.
    const fs::path cleanupRoot = !fs::exists(shareDir, ec)                 ? shareDir
                                 : !fs::exists(shareDir / "librescrs", ec) ? shareDir / "librescrs"
                                                                           : candidate;
    fs::create_directories(candidate);
    std::ofstream(candidate / "relocated.crt") << "stub";

    auto resolved = resolveBundledCertsDir();

    // Clean up before asserting so a failure cannot leave the payload behind
    // to poison the sibling tests.
    fs::remove_all(cleanupRoot);

    ASSERT_TRUE(resolved.has_value());
    EXPECT_EQ(*resolved, candidate) << "the absolute installed location outranked the package's own payload";
}
#endif

// The installed location sits below the env override, so a developer pointing
// LIBRESCRS_CERTIFICATES_DIR at a scratch bundle still wins on a packaged build.
TEST_F(BundledCertsInstallLayoutTest, EnvOverrideStillOutranksInstalledLocation)
{
    const auto envDir = fs::temp_directory_path() / ("lm-install-layout-test-" + std::to_string(::getpid()));
    fs::remove_all(envDir);
    fs::create_directories(envDir);
    std::ofstream(envDir / "fake.crt") << "stub";
    ::setenv("LIBRESCRS_CERTIFICATES_DIR", envDir.c_str(), 1);

    auto resolved = resolveBundledCertsDir();
    ASSERT_TRUE(resolved.has_value());
    EXPECT_EQ(*resolved, envDir);

    fs::remove_all(envDir);
}

} // namespace
