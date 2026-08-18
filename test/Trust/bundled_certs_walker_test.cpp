// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "internal/BundledCertsProvider.h"

#include <gtest/gtest.h>

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>
#include <unistd.h>

namespace fs = std::filesystem;
using LibreSCRS::Trust::detail::certsDirCandidatesForLibrary;
using LibreSCRS::Trust::detail::resolveBundledCertsDir;

namespace {

class BundledCertsWalkerTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        tmpDir = fs::temp_directory_path() / ("lm-certs-test-" + std::to_string(::getpid()));
        fs::remove_all(tmpDir);
        fs::create_directories(tmpDir);
    }
    void TearDown() override
    {
        fs::remove_all(tmpDir);
        ::unsetenv("LIBRESCRS_CERTIFICATES_DIR");
    }

    // Drop a minimal stub file with a cert-like extension so isUsableCertsDir
    // recognises @p dir as non-empty. The walker does not parse contents — only
    // checks extension on at least one regular file.
    static void writeStubCert(const fs::path& dir, const std::string& name)
    {
        fs::create_directories(dir);
        std::ofstream(dir / name) << "stub";
    }

    fs::path tmpDir;
};

TEST_F(BundledCertsWalkerTest, EnvOverrideTakesPriority)
{
    auto envDir = tmpDir / "env-certs";
    writeStubCert(envDir, "fake.crt");
    ::setenv("LIBRESCRS_CERTIFICATES_DIR", envDir.c_str(), 1);

    auto resolved = resolveBundledCertsDir();
    ASSERT_TRUE(resolved.has_value());
    EXPECT_EQ(*resolved, envDir);
}

TEST_F(BundledCertsWalkerTest, FallsBackToCompileTimeWhenEnvUnset)
{
    ::unsetenv("LIBRESCRS_CERTIFICATES_DIR");
    // Compile-time path is set by the test target to the source-tree
    // thirdparty/certificates directory (already populated with rs-mup etc.);
    // walker should return it.
    auto resolved = resolveBundledCertsDir();
    ASSERT_TRUE(resolved.has_value()) << "Source-tree path should be present in dev build";
}

TEST_F(BundledCertsWalkerTest, EnvNonExistentFallsThroughToCompileTime)
{
    ::setenv("LIBRESCRS_CERTIFICATES_DIR", "/nonexistent/path/that/does/not/exist", 1);
    auto resolved = resolveBundledCertsDir();
    ASSERT_TRUE(resolved.has_value()) << "Walker must fall through to next candidate when env path does not exist";
    EXPECT_NE(resolved->string(), "/nonexistent/path/that/does/not/exist");
}

// A directory that exists but holds nothing cert-like is not an answer — an
// empty override must not shadow the candidates below it.
TEST_F(BundledCertsWalkerTest, EmptyEnvDirectoryRollsThroughToNextCandidate)
{
    auto emptyDir = tmpDir / "empty-certs";
    fs::create_directories(emptyDir);
    ::setenv("LIBRESCRS_CERTIFICATES_DIR", emptyDir.c_str(), 1);

    auto resolved = resolveBundledCertsDir();
    ASSERT_TRUE(resolved.has_value()) << "Walker must roll through an empty directory";
    EXPECT_NE(*resolved, emptyDir);
}

// The bundle ships its anchors in per-issuer subdirectories, matching the
// constructor's one-level descent. A candidate whose certificates sit one
// level down still qualifies.
TEST_F(BundledCertsWalkerTest, OneLevelDescentAcceptsCertInSubdirectory)
{
    auto nestedRoot = tmpDir / "nested-certs";
    fs::create_directories(nestedRoot);
    writeStubCert(nestedRoot / "rs-mup", "fake.crt");
    ::setenv("LIBRESCRS_CERTIFICATES_DIR", nestedRoot.c_str(), 1);

    auto resolved = resolveBundledCertsDir();
    ASSERT_TRUE(resolved.has_value());
    EXPECT_EQ(*resolved, nestedRoot);
}

// certsDirCandidatesForLibrary is pure, so it can be checked against install
// layouts that do not exist on this machine — including the macOS bundle shape.

TEST(CertsDirCandidatesForLibraryTest, DerivesDataRootSiblingOfTheLibraryDir)
{
    const auto candidates = certsDirCandidatesForLibrary("/opt/librescrs/lib/libLibreSCRS_Trust.so.4");
    ASSERT_FALSE(candidates.empty());
    EXPECT_EQ(candidates.back().lexically_normal(), fs::path("/opt/librescrs/share/librescrs/certificates"));
}

TEST(CertsDirCandidatesForLibraryTest, MacBundleResourcesOutrankTheDataRoot)
{
    const auto candidates =
        certsDirCandidatesForLibrary("/Applications/Host.app/Contents/Frameworks/libLibreSCRS_Trust.dylib");
#ifdef __APPLE__
    ASSERT_EQ(candidates.size(), 2u);
    EXPECT_EQ(candidates.front().lexically_normal(),
              fs::path("/Applications/Host.app/Contents/Resources/certificates"));
#else
    // Only Darwin ships the Resources layout; elsewhere the data root is the
    // single candidate.
    EXPECT_EQ(candidates.size(), 1u);
#endif
}

// A bare filename carries no directory to walk up from, so there is nothing to
// derive and the resolver moves on to the next rung.
TEST(CertsDirCandidatesForLibraryTest, PathWithoutDirectoryYieldsNoCandidates)
{
    EXPECT_TRUE(certsDirCandidatesForLibrary("libLibreSCRS_Trust.so").empty());
    EXPECT_TRUE(certsDirCandidatesForLibrary("").empty());
}

} // namespace
