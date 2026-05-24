// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// CardVerifier unit tests. Covers construction with and without a cert folder,
// addCertificate (DER intake), filesystem-folder loading, and the high-level
// dispatch entry points with CardType::Unknown (which exits before any APDU).

#include <gtest/gtest.h>

#include "card_protocol.h"
#include "card_reader_base.h"
#include "card_verifier.h"
#include "eidtypes.h"

#include "apdu.h"
#include "pcsc_connection.h"

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

class NullReader : public eidcard::CardReaderBase
{
public:
    std::vector<uint8_t> readFile(LibreSCRS::SmartCard::Internal::PCSCConnection&, uint8_t, uint8_t) override
    {
        return {};
    }
    std::vector<uint8_t> readFileRaw(LibreSCRS::SmartCard::Internal::PCSCConnection&, uint8_t, uint8_t) override
    {
        return {};
    }
};

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

TEST(CardVerifierTest, VerifyCardUnknownTypeReturnsUnknownWithoutAnyApdu)
{
    eidcard::CardVerifier v("");
    LibreSCRS::SmartCard::Internal::PCSCConnection conn(LibreSCRS::SmartCard::Internal::PCSCConnection::DetachedTag{},
                                                        "fake");
    int callCount = 0;
    conn.setTransmitFilter([&](const auto&) {
        ++callCount;
        return LibreSCRS::SmartCard::Internal::APDUResponse{};
    });

    NullReader reader;
    auto result = v.verifyCard(conn, reader, eidcard::CardType::Unknown);
    EXPECT_EQ(result, eidcard::VerificationResult::Unknown);
    EXPECT_EQ(callCount, 0);
}

TEST(CardVerifierTest, VerifyFixedDataUnknownTypeReturnsUnknown)
{
    eidcard::CardVerifier v("");
    LibreSCRS::SmartCard::Internal::PCSCConnection conn(LibreSCRS::SmartCard::Internal::PCSCConnection::DetachedTag{},
                                                        "fake");

    NullReader reader;
    auto result = v.verifyFixedData(conn, reader, eidcard::CardType::Unknown);
    EXPECT_EQ(result, eidcard::VerificationResult::Unknown);
}

TEST(CardVerifierTest, VerifyVariableDataUnknownTypeReturnsUnknown)
{
    eidcard::CardVerifier v("");
    LibreSCRS::SmartCard::Internal::PCSCConnection conn(LibreSCRS::SmartCard::Internal::PCSCConnection::DetachedTag{},
                                                        "fake");

    NullReader reader;
    auto result = v.verifyVariableData(conn, reader, eidcard::CardType::Unknown);
    EXPECT_EQ(result, eidcard::VerificationResult::Unknown);
}
