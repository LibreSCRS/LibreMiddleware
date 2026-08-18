// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "internal/BundledCertsProvider.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <set>
#include <string>
#include <system_error>
#include <unistd.h>

namespace fs = std::filesystem;
using LibreSCRS::Trust::detail::BundledCertsProvider;
using LibreSCRS::Trust::detail::certsDirCandidatesForLibrary;
using LibreSCRS::Trust::detail::resolveBundledCertsDir;

namespace {

// Source-tree bundle, as pinned into every dev build by the same define the
// resolver reads. Tests here assert on the tree that ships, not on a fixture.
const fs::path kSourceCertsDir{LIBREMIDDLEWARE_CERTIFICATES_DIR};

// Archived material, deliberately a SIBLING of the bundle rather than a child.
// Derived rather than configured: the sibling relation is the property under
// test, so spelling it out here would let a moved directory pass unnoticed.
const fs::path kLegacyCertsDir = kSourceCertsDir.parent_path() / "certificates-legacy";

const std::string kSubdirectoriesHeading = "## Subdirectories";

// Subdirectory names the bundle README documents: the ``- `name/` — ...``
// bullets under the "## Subdirectories" heading, up to the next heading. A
// missing or renamed heading yields an empty set, which fails the comparison
// below rather than passing vacuously.
std::set<std::string> readmeSubdirectories(const fs::path& readme)
{
    std::ifstream in(readme);
    std::set<std::string> names;
    std::string line;
    bool inSection = false;
    while (std::getline(in, line)) {
        if (line.rfind("## ", 0) == 0) {
            inSection = (line == kSubdirectoriesHeading);
            continue;
        }
        if (!inSection || line.rfind("- `", 0) != 0)
            continue;
        const auto open = line.find('`');
        const auto close = line.find('`', open + 1);
        if (close == std::string::npos)
            continue;
        auto token = line.substr(open + 1, close - open - 1);
        // Only trailing-slash tokens name a directory; anything else in a
        // bullet (a certificate CN, a define) is prose.
        if (token.size() < 2 || token.back() != '/')
            continue;
        token.pop_back();
        if (token.find('/') == std::string::npos)
            names.insert(token);
    }
    return names;
}

std::set<std::string> onDiskSubdirectories(const fs::path& dir)
{
    std::set<std::string> names;
    std::error_code ec;
    for (const auto& entry : fs::directory_iterator(dir, ec)) {
        if (entry.is_directory(ec) && !ec)
            names.insert(entry.path().filename().string());
    }
    return names;
}

// First loadable certificate in the bundle, used as material for the sibling
// test below. Picked by walking rather than by name so renaming a bundled file
// does not silently turn that test into a no-op.
fs::path anyBundledCertFile()
{
    std::error_code ec;
    for (const auto& sub : fs::directory_iterator(kSourceCertsDir, ec)) {
        if (!sub.is_directory(ec) || ec)
            continue;
        for (const auto& f : fs::directory_iterator(sub.path(), ec)) {
            if (!f.is_regular_file(ec) || ec)
                continue;
            const auto ext = f.path().extension();
            if (ext == ".cer" || ext == ".crt" || ext == ".pem" || ext == ".der")
                return f.path();
        }
    }
    return {};
}

class BundledCertsBundleContentsTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        ::unsetenv("LIBRESCRS_CERTIFICATES_DIR");
        tmpDir = fs::temp_directory_path() / ("lm-bundle-contents-test-" + std::to_string(::getpid()));
        fs::remove_all(tmpDir);
        fs::create_directories(tmpDir);
    }
    void TearDown() override
    {
        fs::remove_all(tmpDir);
        ::unsetenv("LIBRESCRS_CERTIFICATES_DIR");
    }

    fs::path tmpDir;
};

// An empty bundle is a silent outage: the resolver rolls past an empty
// directory, every chain loses its anchors, and cards that verified yesterday
// report an incomplete chain with nothing in the logs pointing at the bundle.
TEST_F(BundledCertsBundleContentsTest, SourceBundleIsNotEmpty)
{
    std::error_code ec;
    ASSERT_TRUE(fs::is_directory(kSourceCertsDir, ec)) << kSourceCertsDir << " is not a directory";

    const auto subdirs = onDiskSubdirectories(kSourceCertsDir);
    EXPECT_FALSE(subdirs.empty()) << "bundle has no issuer subdirectories left";

    // Stronger than counting files: the anchors must actually parse, so a tree
    // of unloadable certificates does not read as a healthy bundle.
    const BundledCertsProvider provider(kSourceCertsDir.string());
    EXPECT_FALSE(provider.anchors().empty()) << "bundle produced no loadable trust anchor";
}

// Drift catcher, both directions. The README is the only description of what
// the bundle holds; a subdirectory added without a README entry (or a README
// entry left behind by a removal) is exactly how the previous description came
// to advertise a directory that no longer existed.
TEST_F(BundledCertsBundleContentsTest, ReadmeSubdirectoriesMatchDisk)
{
    const auto readme = kSourceCertsDir / "README.md";
    std::error_code ec;
    ASSERT_TRUE(fs::is_regular_file(readme, ec)) << "bundle README is missing";

    const auto documented = readmeSubdirectories(readme);
    const auto onDisk = onDiskSubdirectories(kSourceCertsDir);

    std::set<std::string> undocumented;
    std::set_difference(onDisk.begin(), onDisk.end(), documented.begin(), documented.end(),
                        std::inserter(undocumented, undocumented.end()));
    std::set<std::string> missing;
    std::set_difference(documented.begin(), documented.end(), onDisk.begin(), onDisk.end(),
                        std::inserter(missing, missing.end()));

    for (const auto& name : undocumented)
        ADD_FAILURE() << "subdirectory '" << name << "' exists on disk but is not named under \""
                      << kSubdirectoriesHeading << "\" in " << readme;
    for (const auto& name : missing)
        ADD_FAILURE() << "README names subdirectory '" << name << "' under \"" << kSubdirectoriesHeading
                      << "\" but it does not exist in " << kSourceCertsDir;
}

// The archived tree must stay archived. It is a sibling of the bundle, and the
// provider descends exactly one level below the root it is given, so no
// resolved root can reach it — this pins that shape against a future "recurse
// properly" change that would quietly re-admit expired and malformed material.
TEST_F(BundledCertsBundleContentsTest, ArchivedSiblingIsNeverLoaded)
{
    std::error_code ec;
    ASSERT_TRUE(fs::is_directory(kLegacyCertsDir, ec))
        << "premise gone: no archived tree at " << kLegacyCertsDir << " — this test proves nothing";

    const BundledCertsProvider provider(kSourceCertsDir.string());
    for (const auto& anchor : provider.anchors()) {
        EXPECT_EQ(anchor.sourceLabel.find("certificates-legacy"), std::string::npos)
            << "archived material loaded into the bundle: " << anchor.sourceLabel;
        EXPECT_EQ(anchor.sourceLabel.find(".."), std::string::npos)
            << "anchor resolved outside the bundle root: " << anchor.sourceLabel;
    }
}

// Same shape, built from scratch so the sibling holds a certificate that is
// known-loadable: were the descent ever widened, this bundle would gain an
// anchor. Without the control assertion below, a sibling full of unloadable
// certificates would make this pass for the wrong reason.
TEST_F(BundledCertsBundleContentsTest, SiblingOfResolvedRootContributesNoAnchor)
{
    const auto material = anyBundledCertFile();
    ASSERT_FALSE(material.empty()) << "no loadable certificate in the bundle to build the fixture from";

    const auto root = tmpDir / "certificates";
    const auto sibling = tmpDir / "certificates-legacy";
    fs::create_directories(root / "rs-mup");
    fs::create_directories(sibling / "rs-mup");
    fs::copy_file(material, root / "rs-mup" / "anchor.cer");
    fs::copy_file(material, sibling / "rs-mup" / "anchor.cer");

    // Control: the sibling's copy is loadable, so its absence below is the
    // descent refusing to leave the root, not a parse failure.
    const BundledCertsProvider siblingProvider(sibling.string());
    ASSERT_EQ(siblingProvider.anchors().size(), 1u) << "fixture is inert — the sibling copy did not load";

    ::setenv("LIBRESCRS_CERTIFICATES_DIR", root.c_str(), 1);
    const auto resolved = resolveBundledCertsDir();
    ASSERT_TRUE(resolved.has_value());
    EXPECT_EQ(*resolved, root) << "resolver did not settle on the bundle root";

    const BundledCertsProvider provider(resolved->string());
    EXPECT_EQ(provider.anchors().size(), 1u) << "provider reached beyond the resolved root";
}

// Every rung of the ladder names a directory called "certificates" — the env
// override aside, which is the operator's own choice. The archived tree is
// named "certificates-legacy", so no rung can name it however the prefix is
// laid out.
TEST_F(BundledCertsBundleContentsTest, EveryResolverCandidateNamesTheBundleDirectory)
{
    for (const char* compiled : {LIBREMIDDLEWARE_CERTIFICATES_DIR, LIBREMIDDLEWARE_INSTALLED_CERTIFICATES_DIR}) {
        if (compiled == nullptr || compiled[0] == '\0')
            continue;
        EXPECT_EQ(fs::path(compiled).filename(), fs::path("certificates"))
            << "compile-time candidate does not name the bundle directory: " << compiled;
    }

    for (const char* lib : {"/opt/librescrs/lib/libLibreSCRS_Trust.so.4",
                            "/Applications/Host.app/Contents/Frameworks/libLibreSCRS_Trust.dylib"}) {
        for (const auto& cand : certsDirCandidatesForLibrary(lib)) {
            EXPECT_EQ(cand.lexically_normal().filename(), fs::path("certificates"))
                << "library-relative candidate does not name the bundle directory: " << cand;
        }
    }
}

} // namespace
