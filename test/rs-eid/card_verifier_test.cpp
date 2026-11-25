// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// CardVerifier unit tests. Covers construction with and without a cert folder,
// addCertificate (DER intake), filesystem-folder loading, and the verdicts when
// the signed object itself was not read (no card access: the verifier judges
// files already read).

#include <gtest/gtest.h>

#include "card_verifier.h"
#include "eidtypes.h"

#include <rs_document_profile.h>

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <vector>

#ifndef LIBREMIDDLEWARE_TEST_DATA_DIR
#error "LIBREMIDDLEWARE_TEST_DATA_DIR must be defined by the build system"
#endif

namespace fs = std::filesystem;

namespace {

std::vector<uint8_t> readFile(const fs::path& p)
{
    std::ifstream ifs(p, std::ios::binary);
    return std::vector<uint8_t>((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
}

const LibreSCRS::RsEId::Core::DocumentProfile& citizenProfile()
{
    return LibreSCRS::RsEId::Core::documentProfiles()[0];
}

} // namespace

TEST(CardVerifierTest, ConstructWithEmptyPathDoesNotThrow)
{
    EXPECT_NO_THROW({ eidcard::CardVerifier v(""); });
}

TEST(CardVerifierTest, ConstructWithNonexistentPathDoesNotThrow)
{
    EXPECT_NO_THROW({ eidcard::CardVerifier v("/nonexistent/path/that/does/not/exist"); });
}

TEST(CardVerifierTest, AddCertificateAcceptsValidDer)
{
    eidcard::CardVerifier v(""); // empty-path mode
    auto der = readFile(fs::path(LIBREMIDDLEWARE_TEST_DATA_DIR) / "cert" / "serbian-rs-eid-issuer.der");
    ASSERT_FALSE(der.empty());
    EXPECT_NO_THROW({ v.addCertificate(der); });
}

TEST(CardVerifierTest, AddCertificateIgnoresEmptyInput)
{
    eidcard::CardVerifier v("");
    EXPECT_NO_THROW({ v.addCertificate({}); });
}

TEST(CardVerifierTest, AddCertificateIgnoresInvalidDer)
{
    eidcard::CardVerifier v("");
    std::vector<uint8_t> junk = {0x00, 0x01, 0x02, 0x03, 0x04};
    EXPECT_NO_THROW({ v.addCertificate(junk); });
}

TEST(CardVerifierTest, LoadFromFolderHandlesSuffixFilter)
{
    // Create a transient folder with valid .cer + bogus extension + bogus content.
    auto tmpRoot = fs::temp_directory_path() / "librescrs-cardverifier-test";
    fs::create_directories(tmpRoot);

    auto src = fs::path(LIBREMIDDLEWARE_TEST_DATA_DIR) / "cert" / "serbian-rs-eid-issuer.der";
    fs::copy_file(src, tmpRoot / "issuer.cer", fs::copy_options::overwrite_existing);

    // Wrong extension — should be skipped
    fs::copy_file(src, tmpRoot / "issuer.unknown", fs::copy_options::overwrite_existing);

    // Right extension, bogus content — should be silently ignored
    {
        std::ofstream bogus(tmpRoot / "bogus.crt", std::ios::binary);
        bogus << "not a certificate";
    }

    EXPECT_NO_THROW({ eidcard::CardVerifier v(tmpRoot.string()); });

    fs::remove_all(tmpRoot);
}

// A signed object that was not read (absent, protected) vouches for nothing.
TEST(CardVerifierTest, VerifyCardWithoutSignedObjectIsInvalid)
{
    eidcard::CardVerifier v("");
    EXPECT_EQ(v.verifyCard(citizenProfile(), {}), eidcard::VerificationResult::Invalid);
}

TEST(CardVerifierTest, VerifyFixedDataWithoutSignedObjectIsInvalid)
{
    eidcard::CardVerifier v("");
    EXPECT_EQ(v.verifyFixedData(citizenProfile(), {}), eidcard::VerificationResult::Invalid);
}

TEST(CardVerifierTest, VerifyVariableDataWithoutSignedObjectIsInvalid)
{
    eidcard::CardVerifier v("");
    EXPECT_EQ(v.verifyVariableData(citizenProfile(), {}), eidcard::VerificationResult::Invalid);
}
