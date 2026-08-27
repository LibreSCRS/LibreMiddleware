// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "card_scanner.h"

#include <apdu.h>

#include <card_protocol.h>
#include "../cardedge_protocol_constants.h"
#include <health_protocol.h>
#include <eu_vrc_protocol.h>
#include <emrtd_types.h>

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

    // Should have: 3 eID + 1 CardEdge + 1 Health + 1 eMRTD + 1 PIV + 1 EU VRC + 3 Serbian = 11
    EXPECT_EQ(probes.size(), 11u);

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

    // Check PIV is present
    auto pivAid = std::vector<uint8_t>{0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10};
    auto hasPiv =
        std::any_of(probes.begin(), probes.end(), [&](const AidProbe& p) { return p.canonicalAid == pivAid; });
    EXPECT_TRUE(hasPiv);
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

TEST(CardScanner, MatchProfilePiv)
{
    std::vector<std::vector<uint8_t>> detected = {
        {0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10},
    };
    EXPECT_EQ(matchProfile(detected), "piv-profile");
}

TEST(CardScanner, MatchProfilePivWithPkcs15)
{
    // PIV + PKCS#15 on same card — PIV should win
    std::vector<std::vector<uint8_t>> detected = {
        {0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10},
        cardedge::protocol::AID_PKCS15,
    };
    EXPECT_EQ(matchProfile(detected), "piv-profile");
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
    EXPECT_TRUE(LibreSCRS::SmartCard::Internal::isSelectRetryable(0x6700));  // Wrong length
    EXPECT_TRUE(LibreSCRS::SmartCard::Internal::isSelectRetryable(0x6982));  // Security status not satisfied
    EXPECT_TRUE(LibreSCRS::SmartCard::Internal::isSelectRetryable(0x6A86));  // Incorrect P1 P2
    EXPECT_FALSE(LibreSCRS::SmartCard::Internal::isSelectRetryable(0x6A82)); // File not found
    EXPECT_FALSE(LibreSCRS::SmartCard::Internal::isSelectRetryable(0x6A88)); // Referenced data not found
    EXPECT_FALSE(LibreSCRS::SmartCard::Internal::isSelectRetryable(0x9000)); // Success
    EXPECT_FALSE(LibreSCRS::SmartCard::Internal::isSelectRetryable(0x6282)); // Warning (end of file)
}

// 6A86 to every identifier in a sweep is not a description of the card. It is
// what a card answers while some other applet is current -- a state a tool that
// ran earlier can leave behind, and one that survives a disconnect. Reporting
// "no files" there measures the session, not the card.
TEST(CardScanner, UniformRejectionSweepIsReportedAsNoAppletSelected)
{
    // The observed case: thousands of identifiers, every one rejected.
    EXPECT_TRUE(card_mapper::sweepSuggestsNoAppletSelected(5120, 5120, 0));
}

TEST(CardScanner, AGenuinelyEmptyRangeIsNotMistakenForADeselectedApplet)
{
    // Rejections, but not ALL of them -- the card is answering about files.
    EXPECT_FALSE(card_mapper::sweepSuggestsNoAppletSelected(5120, 5119, 0));
    // Files were found, so the applet is plainly selected however many
    // identifiers came back rejected.
    EXPECT_FALSE(card_mapper::sweepSuggestsNoAppletSelected(5120, 5119, 7));
    // Nothing probed at all says nothing about anything.
    EXPECT_FALSE(card_mapper::sweepSuggestsNoAppletSelected(0, 0, 0));
}

// A scripted four-entry EF.DIR modeled on the Serbian LK finding: two entries
// share one AID at different paths, one entry's DF answers no AID SELECT and
// is reachable only through its tag-51 path, and two MF-level DFs plus one
// MF-level EF are discoverable only by the brute-force sweep (`00 A4 00 00`
// returns their FCI while the child SELECT answers 6A82).
TEST(CardScannerDiscover, EfDirEntriesSurviveDedupAndMfFindsParentUnderMf)
{
    using namespace LibreSCRS::SmartCard::Internal;
    PCSCConnection conn(PCSCConnection::DetachedTag{}, "scripted-lk");

    const std::vector<uint8_t> aidA = {0xD0, 0x11, 0x22, 0x33, 0x01};
    const std::vector<uint8_t> aidB = {0xD0, 0x11, 0x22, 0x33, 0x02};
    const std::vector<uint8_t> aidC = {0xD0, 0x11, 0x22, 0x33, 0x03};

    auto tlv = [](uint8_t tag, std::vector<uint8_t> value) {
        std::vector<uint8_t> out{tag, static_cast<uint8_t>(value.size())};
        out.insert(out.end(), value.begin(), value.end());
        return out;
    };
    auto appTemplate = [&](const std::vector<uint8_t>& aid, const std::string& label,
                           const std::vector<uint8_t>& path) {
        std::vector<uint8_t> body = tlv(0x4F, aid);
        if (!label.empty()) {
            auto l = tlv(0x50, std::vector<uint8_t>(label.begin(), label.end()));
            body.insert(body.end(), l.begin(), l.end());
        }
        if (!path.empty()) {
            auto p = tlv(0x51, path);
            body.insert(body.end(), p.begin(), p.end());
        }
        return tlv(0x61, body);
    };

    std::vector<uint8_t> efDir;
    for (const auto& t : {appTemplate(aidA, "First", {0x3F, 0x00, 0x51, 0x00}), //
                          appTemplate(aidB, "Second", {}),                      //
                          appTemplate(aidA, "", {0x3F, 0x00, 0x53, 0x00}),      //
                          appTemplate(aidC, "Annex", {0x3F, 0x00, 0x0F, 0xF3})}) {
        efDir.insert(efDir.end(), t.begin(), t.end());
    }

    const std::vector<uint8_t> fciDf = {0x62, 0x03, 0x82, 0x01, 0x38};
    bool efDirSelected = false;

    conn.setTransmitFilter([&](const APDUCommand& cmd) -> APDUResponse {
        auto ok = [](std::vector<uint8_t> data = {}) {
            return APDUResponse{.data = std::move(data), .sw1 = 0x90, .sw2 = 0x00};
        };
        auto notFound = [] { return APDUResponse{.data = {}, .sw1 = 0x6A, .sw2 = 0x82}; };
        const std::vector<uint8_t>& d = cmd.data;

        if (cmd.ins == 0xA4) {
            efDirSelected = false;
            if (cmd.p1 == 0x04) {
                // aidC answers no AID SELECT; its DF is path-only.
                return (d == aidA || d == aidB) ? ok() : notFound();
            }
            if (d == std::vector<uint8_t>{0x3F, 0x00})
                return ok();
            if (cmd.p1 == 0x08 && d == std::vector<uint8_t>{0x2F, 0x00}) {
                efDirSelected = true;
                return ok();
            }
            // The annex DF: reachable as a path from MF, never as a child.
            if (cmd.p1 == 0x08 && d == std::vector<uint8_t>{0x0F, 0xF3})
                return cmd.p2 == 0x0C ? ok() : ok(fciDf);
            // MF-level finds: the child SELECT forms answer 6A82; only
            // `00 A4 00 00` reaches them (the measured 0DF5 behaviour).
            if (cmd.p1 == 0x00 && d == std::vector<uint8_t>{0x0D, 0xF5})
                return ok(fciDf);
            if (cmd.p1 == 0x00 && d == std::vector<uint8_t>{0xD0, 0x03})
                return ok();
            return notFound();
        }
        if (cmd.ins == 0xB0)
            return efDirSelected ? APDUResponse{.data = efDir, .sw1 = 0x90, .sw2 = 0x00} : notFound();
        return notFound();
    });

    auto result = card_mapper::discoverCard(conn, false);

    ASSERT_EQ(result.detectedApplets.size(), 4u);

    // Labels (tag 50) reach the applet names; on-card order is preserved.
    EXPECT_NE(result.detectedApplets[0].name.find("First"), std::string::npos);
    EXPECT_NE(result.detectedApplets[1].name.find("Second"), std::string::npos);
    EXPECT_NE(result.detectedApplets[3].name.find("Annex"), std::string::npos);

    // Entries 1 and 3 share an AID but not a path: both survive, and their
    // generated documents get distinct names.
    EXPECT_NE(result.detectedApplets[0].pluginName, result.detectedApplets[2].pluginName);

    for (const auto& applet : result.detectedApplets) {
        const auto& mf = applet.rootNode;
        EXPECT_EQ(mf.name, "MF");
        ASSERT_FALSE(mf.children.empty());

        // The applet's own DF holds none of the MF-level finds.
        const auto& df = mf.children.front();
        for (const auto& child : df.children) {
            EXPECT_FALSE(child.fidHi == 0x0D && child.fidLo == 0xF5) << child.name;
            EXPECT_FALSE(child.fidHi == 0xD0 && child.fidLo == 0x03) << child.name;
        }

        // The MF sweep's finds sit under MF, and the FCI's file descriptor
        // (82 01 38) decides DF vs EF.
        auto mfChild = [&](const std::string& name, uint8_t hi, uint8_t lo) {
            return std::any_of(mf.children.begin(), mf.children.end(),
                               [&](const FileNode& n) { return n.name == name && n.fidHi == hi && n.fidLo == lo; });
        };
        EXPECT_TRUE(mfChild("DF", 0x0F, 0xF3));
        EXPECT_TRUE(mfChild("DF", 0x0D, 0xF5));
        EXPECT_TRUE(mfChild("EF", 0xD0, 0x03));
    }
}
