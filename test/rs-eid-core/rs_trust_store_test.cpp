// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <gtest/gtest.h>

#include "rs_signed_object.h"
#include "rs_trust_store.h"
#include "synthetic_annex.h"

#include <filesystem>
#include <fstream>
#include <random>

using namespace LibreSCRS::RsEId::Core;
namespace Fx = LibreSCRS::RsEId::Core::TestData;

namespace {

/// Writes `der` into a fresh directory and removes it again on destruction.
class TempAnchorDir
{
public:
    explicit TempAnchorDir(const std::vector<std::uint8_t>& der)
    {
        std::random_device rd;
        path = std::filesystem::temp_directory_path() /
               ("librescrs-anchor-" + std::to_string(rd()) + "-" + std::to_string(rd()));
        std::filesystem::create_directories(path);
        std::ofstream ofs(path / "anchor.cer", std::ios::binary);
        ofs.write(reinterpret_cast<const char*>(der.data()), static_cast<std::streamsize>(der.size()));
    }

    ~TempAnchorDir()
    {
        std::error_code ec;
        std::filesystem::remove_all(path, ec);
    }

    TempAnchorDir(const TempAnchorDir&) = delete;
    TempAnchorDir& operator=(const TempAnchorDir&) = delete;

    [[nodiscard]] std::string str() const
    {
        return path.string();
    }

private:
    std::filesystem::path path;
};

std::vector<std::uint8_t> someContent()
{
    return std::vector<std::uint8_t>(32, 0x5A);
}

} // namespace

// The two ways of adding an anchor do not treat validity windows alike, and that
// split is long-standing behaviour on shipped cards. Pinned here so a refactor
// cannot quietly switch expired anchors on for the byte-wise path.
TEST(RsTrustStore, ByteWiseAnchorStillHonoursValidityWindow)
{
    const auto fixture = Fx::makeSignedObject(someContent(), /*expiredSigner=*/true);
    ASSERT_FALSE(fixture.signerCertDer.empty());

    TrustStore trust;
    trust.addCertificate(fixture.signerCertDer);
    ASSERT_EQ(trust.certificateCount(), 1);

    const auto report = verifySignedObject(fixture.cms, {}, DigestBinding::Positional, trust);
    EXPECT_EQ(report.signer, VerificationResult::Invalid);
}

TEST(RsTrustStore, FolderAnchorIgnoresValidityWindow)
{
    const auto fixture = Fx::makeSignedObject(someContent(), /*expiredSigner=*/true);
    const TempAnchorDir dir(fixture.signerCertDer);

    TrustStore trust;
    trust.loadFromFolder(dir.str());
    ASSERT_EQ(trust.certificateCount(), 1);

    // Chain builds despite the closed window; the signer is simply not ours.
    const auto report = verifySignedObject(fixture.cms, {}, DigestBinding::Positional, trust);
    EXPECT_EQ(report.signer, VerificationResult::Unknown);
}

TEST(RsTrustStore, MissingFolderIsNotAnError)
{
    TrustStore trust;
    trust.loadFromFolder("/nonexistent/librescrs/anchors");
    EXPECT_EQ(trust.certificateCount(), 0);
}

TEST(RsTrustStore, EmptyCertificateIsIgnored)
{
    TrustStore trust;
    trust.addCertificate({});
    EXPECT_EQ(trust.certificateCount(), 0);
}
