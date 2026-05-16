// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <gtest/gtest.h>
#include <pace.h>
#include <data_group.h>
#include <emrtd_card.h>
#include <emrtd_types.h>
#include <smartcard/pcsc_connection.h>

#include <LibreSCRS/Auth/PaceSecretKind.h>
#include <LibreSCRS/CancelToken.h>
#include <LibreSCRS/Secure/String.h>
#include <LibreSCRS/SecureChannel/ChannelErrors.h>
#include <LibreSCRS/SmartCard/ActiveChannelHolder.h>
#include <LibreSCRS/SmartCard/AppletAid.h>
#include <LibreSCRS/SmartCard/CardSession.h>
#include <LibreSCRS/SmartCard/SmProtocolRequest.h>

#include <algorithm>
#include <cstdlib>
#include <iomanip>
#include <iostream>

using namespace emrtd::crypto;

// ---------------------------------------------------------------------------
// Hardware PACE tests — require eMRTD card + LIBRESCRS_TEST_CAN env var.
// Skipped automatically if the env var is not set or no reader is present.
// ---------------------------------------------------------------------------

static std::string getTestCAN()
{
    const char* can = std::getenv("LIBRESCRS_TEST_CAN");
    return can ? std::string(can) : std::string();
}

TEST(PACEHardwareTest, PaceWithCAN)
{
    auto can = getTestCAN();
    if (can.empty())
        GTEST_SKIP() << "Set LIBRESCRS_TEST_CAN to run";

    auto readers = LibreSCRS::SmartCard::Internal::PCSCConnection::listReaders();
    if (readers.empty())
        GTEST_SKIP() << "No smart card readers found";

    LibreSCRS::SmartCard::Internal::PCSCConnection conn(readers[0]);

    // Read EF.CardAccess from MF
    conn.transmit({0x00, 0xA4, 0x00, 0x00, {0x3F, 0x00}, 0x00, true});
    auto selCA = conn.transmit({0x00, 0xA4, 0x00, 0x00, {0x01, 0x1C}, 0x00, true});
    if (!selCA.isSuccess())
        GTEST_SKIP() << "No EF.CardAccess on card";

    auto caResp = conn.transmit({0x00, 0xB0, 0x00, 0x00, {}, 0x00, true});
    auto paceEntries = parseCardAccessWithParams(caResp.data);
    ASSERT_FALSE(paceEntries.empty()) << "No PACE entries in CardAccess";

    // Try PACE with the first entry
    auto& [oid, paramId] = paceEntries[0];
    std::vector<uint8_t> password(can.begin(), can.end());
    PACEParams params{oid, PACEPasswordType::CAN, password, paramId};

    auto session = performPACE(conn, params);
    ASSERT_TRUE(session.has_value()) << "PACE failed for OID=" << oid << " paramId=" << paramId;
    EXPECT_FALSE(session->encKey.empty());
    EXPECT_FALSE(session->macKey.empty());
    EXPECT_FALSE(session->ssc.empty());
}

namespace {

// Establish a PACE-CAN channel via CardSession and return the holder + the
// session. The holder must stay alive for the lifetime of any EMRTDCard
// constructed from the channel; the session must outlive the holder.
struct PaceFixture
{
    LibreSCRS::SmartCard::CardSession session;
    LibreSCRS::SmartCard::ActiveChannelHolder holder;
};

std::optional<PaceFixture> openPaceCanFixture(const std::string& reader, const std::string& can)
{
    auto sessionResult = LibreSCRS::SmartCard::CardSession::open(reader);
    if (!sessionResult.has_value())
        return std::nullopt;
    auto session = std::move(*sessionResult);
    session.setPaceSecret(LibreSCRS::Auth::PaceSecretKind::Can, LibreSCRS::Secure::String{can});
    LibreSCRS::SmartCard::AppletAid emrtdAid{0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01};
    auto holderResult = session.activateChannelWithSm(
        emrtdAid, LibreSCRS::SmartCard::PaceRequest{LibreSCRS::Auth::PaceSecretKind::Can}, LibreSCRS::CancelToken{});
    if (!holderResult)
        return std::nullopt;
    return PaceFixture{std::move(session), std::move(*holderResult)};
}

} // namespace

TEST(PACEHardwareTest, PaceAuthenticateAndReadCOM)
{
    auto can = getTestCAN();
    if (can.empty())
        GTEST_SKIP() << "Set LIBRESCRS_TEST_CAN to run";

    auto readers = LibreSCRS::SmartCard::Internal::PCSCConnection::listReaders();
    if (readers.empty())
        GTEST_SKIP() << "No smart card readers found";

    auto fixture = openPaceCanFixture(readers[0], can);
    ASSERT_TRUE(fixture.has_value()) << "PACE channel activation failed";
    auto* channel = fixture->holder.activeChannel();
    ASSERT_NE(channel, nullptr);

    emrtd::EMRTDCard card(*channel);

    // After PACE + applet selection, read COM (EF.COM lists available DGs)
    auto dgList = card.readCOM();
    EXPECT_FALSE(dgList.empty()) << "COM should list at least one data group";

    // DG1 (MRZ) and DG2 (photo) are mandatory in all passports
    bool hasDG1 = std::find(dgList.begin(), dgList.end(), 1) != dgList.end();
    bool hasDG2 = std::find(dgList.begin(), dgList.end(), 2) != dgList.end();
    EXPECT_TRUE(hasDG1) << "DG1 (MRZ) missing from COM";
    EXPECT_TRUE(hasDG2) << "DG2 (photo) missing from COM";
}

TEST(PACEHardwareTest, ReadAndParseDG1)
{
    auto can = getTestCAN();
    if (can.empty())
        GTEST_SKIP() << "Set LIBRESCRS_TEST_CAN to run";

    auto readers = LibreSCRS::SmartCard::Internal::PCSCConnection::listReaders();
    if (readers.empty())
        GTEST_SKIP() << "No smart card readers found";

    auto fixture = openPaceCanFixture(readers[0], can);
    ASSERT_TRUE(fixture.has_value()) << "PACE channel activation failed";
    auto* channel = fixture->holder.activeChannel();
    ASSERT_NE(channel, nullptr);

    emrtd::EMRTDCard card(*channel);

    // Read DG1 (MRZ data)
    auto dg1Raw = card.readDataGroup(1);
    ASSERT_TRUE(dg1Raw.has_value()) << "Failed to read DG1";
    EXPECT_GT(dg1Raw->size(), 10u) << "DG1 too small";

    // Dump raw DG1 for debugging
    std::cerr << "[DG1] raw (" << dg1Raw->size() << " bytes):";
    for (size_t i = 0; i < std::min(dg1Raw->size(), size_t(80)); ++i)
        std::cerr << " " << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>((*dg1Raw)[i]);
    std::cerr << std::dec << std::endl;

    // Parse it
    std::map<int, std::vector<uint8_t>> rawDGs;
    rawDGs[1] = *dg1Raw;
    auto parsed = emrtd::parseDataGroups(rawDGs);

    ASSERT_TRUE(parsed.dg1.has_value()) << "DG1 parsing failed";
    EXPECT_FALSE(parsed.dg1->surname.empty()) << "Surname empty";
    EXPECT_FALSE(parsed.dg1->givenNames.empty()) << "Given names empty";
    EXPECT_FALSE(parsed.dg1->documentNumber.empty()) << "Document number empty";
    EXPECT_FALSE(parsed.dg1->nationality.empty()) << "Nationality empty";
    EXPECT_FALSE(parsed.dg1->dateOfBirth.empty()) << "DOB empty";
    EXPECT_FALSE(parsed.dg1->dateOfExpiry.empty()) << "DOE empty";

    std::cerr << "[DG1] Document: " << parsed.dg1->documentCode << " " << parsed.dg1->documentNumber << std::endl;
    std::cerr << "[DG1] Name: " << parsed.dg1->surname << ", " << parsed.dg1->givenNames << std::endl;
    std::cerr << "[DG1] Nationality: " << parsed.dg1->nationality << std::endl;
    std::cerr << "[DG1] DOB: " << parsed.dg1->dateOfBirth << " DOE: " << parsed.dg1->dateOfExpiry << std::endl;
}

TEST(PACEHardwareTest, ReadDG2Photo)
{
    auto can = getTestCAN();
    if (can.empty())
        GTEST_SKIP() << "Set LIBRESCRS_TEST_CAN to run";

    auto readers = LibreSCRS::SmartCard::Internal::PCSCConnection::listReaders();
    if (readers.empty())
        GTEST_SKIP() << "No smart card readers found";

    auto fixture = openPaceCanFixture(readers[0], can);
    ASSERT_TRUE(fixture.has_value()) << "PACE channel activation failed";
    auto* channel = fixture->holder.activeChannel();
    ASSERT_NE(channel, nullptr);

    emrtd::EMRTDCard card(*channel);

    auto dg2Raw = card.readDataGroup(2);
    ASSERT_TRUE(dg2Raw.has_value()) << "Failed to read DG2";
    EXPECT_GT(dg2Raw->size(), 100u) << "DG2 too small for a photo";

    std::map<int, std::vector<uint8_t>> rawDGs;
    rawDGs[2] = *dg2Raw;
    auto parsed = emrtd::parseDataGroups(rawDGs);

    ASSERT_TRUE(parsed.dg2.has_value()) << "DG2 parsing failed";
    EXPECT_FALSE(parsed.dg2->imageData.empty()) << "Photo data empty";
    EXPECT_GT(parsed.dg2->imageData.size(), 100u) << "Photo too small";

    std::cerr << "[DG2] Photo: " << parsed.dg2->imageData.size() << " bytes, type=" << parsed.dg2->mimeType
              << std::endl;
}
