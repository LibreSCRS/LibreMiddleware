// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "card_scanner.h"

#include <smartcard/apdu.h>

#include <card_protocol.h>
#include <cardedge_protocol.h>
#include <health_protocol.h>
#include <eu_vrc_protocol.h>
#include <emrtd/emrtd_types.h>

#include <gtest/gtest.h>

#include <algorithm>

using namespace card_mapper;

TEST(CardScanner, ProbeRangesContainsExpected)
{
    auto ranges = getProbeRanges();
    EXPECT_EQ(ranges.size(), 7u);

    // Existing ranges
    EXPECT_EQ(ranges[0].first, 0x0F00);
    EXPECT_EQ(ranges[0].second, 0x0FFF);
    EXPECT_EQ(ranges[1].first, 0x0D00);
    EXPECT_EQ(ranges[1].second, 0x0DFF);
    EXPECT_EQ(ranges[2].first, 0xC000);
    EXPECT_EQ(ranges[2].second, 0xC0FF);
    EXPECT_EQ(ranges[3].first, 0xD000);
    EXPECT_EQ(ranges[3].second, 0xD0FF);
    EXPECT_EQ(ranges[4].first, 0xE000);
    EXPECT_EQ(ranges[4].second, 0xE0FF);

    // PKCS#15 ranges
    EXPECT_EQ(ranges[5].first, 0x4400);
    EXPECT_EQ(ranges[5].second, 0x440F);
    EXPECT_EQ(ranges[6].first, 0x5030);
    EXPECT_EQ(ranges[6].second, 0x5035);
}

TEST(CardScanner, AllKnownProbesIncludesAll)
{
    auto probes = getAllKnownProbes();

    // Should have: 3 eID + 1 CardEdge + 1 Health + 1 eMRTD + 1 EU VRC + 3 Serbian = 10
    EXPECT_EQ(probes.size(), 10u);

    // Check eID SERID is present
    auto hasSerid = std::any_of(probes.begin(), probes.end(),
                                [](const AidProbe& p) { return p.canonicalAid == eidcard::protocol::AID_SERID; });
    EXPECT_TRUE(hasSerid);

    // Check CardEdge is present
    auto hasCardEdge = std::any_of(probes.begin(), probes.end(),
                                   [](const AidProbe& p) { return p.canonicalAid == cardedge::protocol::AID_PKCS15; });
    EXPECT_TRUE(hasCardEdge);

    // Check eMRTD is present
    auto emrtdAid = std::vector<uint8_t>(emrtd::EMRTD_AID, emrtd::EMRTD_AID + emrtd::EMRTD_AID_LEN);
    auto hasEmrtd =
        std::any_of(probes.begin(), probes.end(), [&](const AidProbe& p) { return p.canonicalAid == emrtdAid; });
    EXPECT_TRUE(hasEmrtd);
}

TEST(CardScanner, SimpleProbesHaveSingleSelectCommand)
{
    auto probes = getAllKnownProbes();
    for (const auto& p : probes) {
        if (p.name.find("EU-VRC-RS") == std::string::npos) {
            EXPECT_EQ(p.selectSequence.size(), 1u) << "Probe " << p.name << " should have 1 SELECT command";
        }
    }
}

TEST(CardScanner, EuVrcSerbianProbesHaveThreeSelectCommands)
{
    auto probes = getAllKnownProbes();
    for (const auto& p : probes) {
        if (p.name.find("EU-VRC-RS") != std::string::npos) {
            EXPECT_EQ(p.selectSequence.size(), 3u) << "Probe " << p.name << " should have 3 SELECT commands";
            EXPECT_EQ(p.lastP2, 0x0C) << "EU VRC Serbian last SELECT should use P2=0x0C";
        }
    }
}

TEST(CardScanner, MatchProfileEid)
{
    std::vector<std::vector<uint8_t>> detected = {
        eidcard::protocol::AID_SERID,
        cardedge::protocol::AID_PKCS15,
    };
    EXPECT_EQ(matchProfile(detected), "rs-eid-profile");
}

TEST(CardScanner, MatchProfileEidForeigner)
{
    std::vector<std::vector<uint8_t>> detected = {
        eidcard::protocol::AID_SERIF,
        cardedge::protocol::AID_PKCS15,
    };
    EXPECT_EQ(matchProfile(detected), "rs-eid-profile");
}

TEST(CardScanner, MatchProfileHealth)
{
    std::vector<std::vector<uint8_t>> detected = {
        healthcard::protocol::AID_SERVSZK,
        cardedge::protocol::AID_PKCS15,
    };
    EXPECT_EQ(matchProfile(detected), "rs-health-profile");
}

TEST(CardScanner, MatchProfileVehicle)
{
    std::vector<std::vector<uint8_t>> detected = {
        euvrc::protocol::SEQ1_CMD1,
    };
    EXPECT_EQ(matchProfile(detected), "rs-vehicle-profile");
}

TEST(CardScanner, MatchProfileVehicleEuAid)
{
    std::vector<std::vector<uint8_t>> detected = {
        euvrc::protocol::EU_VRC_AID,
    };
    EXPECT_EQ(matchProfile(detected), "rs-vehicle-profile");
}

TEST(CardScanner, MatchProfilePassportIcao)
{
    // eMRTD only (no PKCS#15/CardEdge) = ICAO passport
    std::vector<std::vector<uint8_t>> detected = {
        std::vector<uint8_t>(emrtd::EMRTD_AID, emrtd::EMRTD_AID + emrtd::EMRTD_AID_LEN),
    };
    EXPECT_EQ(matchProfile(detected), "passport-icao-profile");
}

TEST(CardScanner, MatchProfileEmrtdPkcs15)
{
    // eMRTD + PKCS#15/CardEdge AID = eID with eMRTD
    std::vector<std::vector<uint8_t>> detected = {
        std::vector<uint8_t>(emrtd::EMRTD_AID, emrtd::EMRTD_AID + emrtd::EMRTD_AID_LEN),
        cardedge::protocol::AID_PKCS15,
    };
    EXPECT_EQ(matchProfile(detected), "emrtd-pkcs15-profile");
}

TEST(CardScanner, MatchProfileCardEdgeOnly)
{
    std::vector<std::vector<uint8_t>> detected = {
        cardedge::protocol::AID_PKCS15,
    };
    EXPECT_EQ(matchProfile(detected), "cardedge-only-profile");
}

TEST(CardScanner, MatchProfileUnknown)
{
    std::vector<std::vector<uint8_t>> detected = {};
    EXPECT_EQ(matchProfile(detected), "");
}

TEST(SmartCardApdu, IsSelectRetryable)
{
    EXPECT_TRUE(smartcard::isSelectRetryable(0x6700));  // Wrong length
    EXPECT_TRUE(smartcard::isSelectRetryable(0x6982));  // Security status not satisfied
    EXPECT_TRUE(smartcard::isSelectRetryable(0x6A86));  // Incorrect P1 P2
    EXPECT_FALSE(smartcard::isSelectRetryable(0x6A82)); // File not found
    EXPECT_FALSE(smartcard::isSelectRetryable(0x6A88)); // Referenced data not found
    EXPECT_FALSE(smartcard::isSelectRetryable(0x9000)); // Success
    EXPECT_FALSE(smartcard::isSelectRetryable(0x6282)); // Warning (end of file)
}
