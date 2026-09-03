// SPDX-License-Identifier: LGPL-2.1-or-later
//
// Install-layout coverage for the PKCS#11 module lookup.
//
// The lookup spelled the library directory as the literal "lib", so any build
// whose install layout uses lib64 or a multiarch triplet probed beside a
// directory that does not exist there and fell through to a bare name the
// loader cannot find. On such a host signing fails with an opaque engine error
// AFTER the PIN has been collected. It stayed latent because the one
// distribution package this project builds uses a library directory literally
// called lib, where the probe happens to succeed.
//
// Seven synthetic install trees, no card, no PIN, no network.

#include "Signing/detail/Pkcs11ModulePath.h"

#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <string>

namespace fs = std::filesystem;
using LibreSCRS::Signing::detail::resolvePkcs11ModulePath;

namespace {

constexpr const char* kModule = "librescrs-pkcs11.so";

class Pkcs11ModulePathTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        const auto* info = ::testing::UnitTest::GetInstance()->current_test_info();
        root_ = fs::temp_directory_path() / (std::string{"librescrs-p11path-"} + info->name());
        fs::remove_all(root_);
        fs::create_directories(root_);
    }

    void TearDown() override
    {
        std::error_code ec;
        fs::remove_all(root_, ec);
    }

    /// Create @p rel under the synthetic root and return its absolute path.
    fs::path touch(const std::string& rel) const
    {
        const fs::path p = root_ / rel;
        fs::create_directories(p.parent_path());
        std::ofstream{p} << "not really an ELF object";
        return p;
    }

    fs::path dir(const std::string& rel) const
    {
        const fs::path p = root_ / rel;
        fs::create_directories(p);
        return p;
    }

    /// The resolver returns canonical paths, so an expectation must be one too.
    static std::string canonical(const fs::path& p)
    {
        return fs::canonical(p).string();
    }

    fs::path root_;
};

// Fedora and friends install into lib64. The old list looked beside "lib",
// found nothing, and returned a bare name the loader cannot resolve.
TEST_F(Pkcs11ModulePathTest, FedoraLib64)
{
    const fs::path exe = dir("usr/libexec");
    const fs::path mod = touch(std::string{"usr/lib64/pkcs11/"} + kModule);
    EXPECT_EQ(resolvePkcs11ModulePath(exe, kModule, "lib64", ""), canonical(mod));
}

// Debian's multiarch triplet is a two-segment library directory, so it is not
// merely "lib" with a suffix: nothing about the old spelling could reach it.
TEST_F(Pkcs11ModulePathTest, DebianMultiarch)
{
    const fs::path exe = dir("usr/libexec");
    const fs::path mod = touch(std::string{"usr/lib/x86_64-linux-gnu/pkcs11/"} + kModule);
    EXPECT_EQ(resolvePkcs11ModulePath(exe, kModule, "lib/x86_64-linux-gnu", ""), canonical(mod));
}

// The layout that already worked, and the only one this project packages
// today. It must come out byte-identical, or the fix traded one broken host
// for another.
TEST_F(Pkcs11ModulePathTest, ArchLib)
{
    const fs::path exe = dir("usr/libexec");
    const fs::path mod = touch(std::string{"usr/lib/pkcs11/"} + kModule);
    EXPECT_EQ(resolvePkcs11ModulePath(exe, kModule, "lib", ""), canonical(mod));
}

// A prefix of its own: the module is neither beside the executable nor one
// level up from it, so only the absolute the build was configured with can
// find it. This is the layout the dogfood machine runs.
TEST_F(Pkcs11ModulePathTest, DogfoodPrefix)
{
    const fs::path exe = dir(".local/libexec");
    const fs::path mod = touch(std::string{".local/librescrs/lib/pkcs11/"} + kModule);
    EXPECT_EQ(resolvePkcs11ModulePath(exe, kModule, "lib", mod.string()), canonical(mod));
}

// Both files exist: the bundled one and a system one named by the configured
// absolute. The bundle must win, which is why the absolute is the LAST
// candidate — otherwise a relocatable app would load a system module of a
// different version. Without both files on disk this asserts only that the
// absolute exists, not that it comes last.
TEST_F(Pkcs11ModulePathTest, BundlePrefersItsOwnOverTheConfiguredAbsolute)
{
    const fs::path exe = dir("App/Contents/MacOS");
    const fs::path bundled = touch(std::string{"App/Contents/Frameworks/"} + kModule);
    const fs::path systemMod = touch(std::string{"usr/lib/pkcs11/"} + kModule);
    ASSERT_TRUE(fs::exists(systemMod));
    EXPECT_EQ(resolvePkcs11ModulePath(exe, kModule, "lib", systemMod.string()), canonical(bundled));
}

// An uninstalled build tree: test binary in build/test, module in build/lib.
// "lib" here is the literal directory the build makes, not a distro libdir,
// which is why candidates 2, 6, 7 and 8 keep it spelled that way.
TEST_F(Pkcs11ModulePathTest, DevBuildTree)
{
    const fs::path exe = dir("build/test");
    const fs::path mod = touch(std::string{"build/lib/pkcs11/"} + kModule);
    EXPECT_EQ(resolvePkcs11ModulePath(exe, kModule, "lib", ""), canonical(mod));
}

// Nothing is installed anywhere, and the configured absolute names a file that
// does not exist. The bare name is correct here: the decision passes to the
// dynamic loader rather than to a path known to be wrong.
TEST_F(Pkcs11ModulePathTest, NothingInstalledFallsBackToBareName)
{
    const fs::path exe = dir("empty");
    const fs::path absent = root_ / "usr/lib64/pkcs11" / kModule;
    EXPECT_EQ(resolvePkcs11ModulePath(exe, kModule, "lib64", absent.string()), kModule);
}

} // namespace
