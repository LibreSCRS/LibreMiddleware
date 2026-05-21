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

} // namespace
