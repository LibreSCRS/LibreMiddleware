// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <gtest/gtest.h>
#include <emrtd/crypto/pace.h>
#include <emrtd/data_group.h>
#include <emrtd/emrtd_card.h>
#include <emrtd/emrtd_types.h>
#include <smartcard/pcsc_connection.h>

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

    auto readers = smartcard::PCSCConnection::listReaders();
    if (readers.empty())
        GTEST_SKIP() << "No smart card readers found";

    smartcard::PCSCConnection conn(readers[0]);

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

TEST(PACEHardwareTest, PaceAuthenticateAndReadCOM)
{
    auto can = getTestCAN();
    if (can.empty())
        GTEST_SKIP() << "Set LIBRESCRS_TEST_CAN to run";

    auto readers = smartcard::PCSCConnection::listReaders();
    if (readers.empty())
        GTEST_SKIP() << "No smart card readers found";

    smartcard::PCSCConnection conn(readers[0]);
    emrtd::EMRTDCard card(conn, can);

    auto result = card.authenticate();
    ASSERT_TRUE(result.success) << "Authentication failed: " << result.error;
    EXPECT_EQ(result.method, emrtd::AuthMethod::PACE_CAN);

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

    auto readers = smartcard::PCSCConnection::listReaders();
    if (readers.empty())
        GTEST_SKIP() << "No smart card readers found";

    smartcard::PCSCConnection conn(readers[0]);
    emrtd::EMRTDCard card(conn, can);

    auto result = card.authenticate();
    ASSERT_TRUE(result.success) << "Authentication failed: " << result.error;

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

    auto readers = smartcard::PCSCConnection::listReaders();
    if (readers.empty())
        GTEST_SKIP() << "No smart card readers found";

    smartcard::PCSCConnection conn(readers[0]);
    emrtd::EMRTDCard card(conn, can);

    auto result = card.authenticate();
    ASSERT_TRUE(result.success) << "Authentication failed: " << result.error;

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
