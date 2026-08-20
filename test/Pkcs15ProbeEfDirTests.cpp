// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

// Integration coverage for PKCS15Card::probeViaEfDir's selection-by-
// verification: EF.DIR can list several application templates sharing one
// AID at different paths, and the correct one is whichever one actually
// exposes EF.ODF underneath it -- not whichever one sorts first.
// ef_dir_test.cpp only covers the parser (parseEfDir never selects
// anything); this drives the real PKCS15Card::probe()/readProfile()
// against a scripted card behind a detached PCSCConnection's transmit
// filter -- no hardware, no PC/SC.

#include <pkcs15_card.h>

#include <LibreSCRS/SmartCard/AppletAid.h>
#include <LibreSCRS_internal/SecureChannel/PlainChannel.h>

#include <apdu.h>
#include <pcsc_connection.h>

#include <gtest/gtest.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <map>
#include <vector>

using LibreSCRS::SmartCard::Internal::APDUCommand;
using LibreSCRS::SmartCard::Internal::APDUResponse;
using LibreSCRS::SmartCard::Internal::PCSCConnection;

namespace {

// EF.DIR with THREE application templates, the first two sharing one AID
// at different paths: MF/3F00 (wrong), PKCS15/3F00-5015 (right), ICAO
// (unrelated). Byte-identical to ef_dir_test.cpp's EF_DIR_DUPLICATE_AID --
// verified there against parseEfDir() directly; reused here so both
// suites exercise the exact same on-card layout.
const std::vector<std::uint8_t> kEfDirDuplicateAid = {
    0x61, 0x16, 0x4F, 0x0C, 0xA0, 0x00, 0x00, 0x00, 0x63, 0x50, 0x4B, 0x43, 0x53, 0x2D, 0x31, 0x35,
    0x50, 0x02, 0x4D, 0x46, 0x51, 0x02, 0x3F, 0x00, 0x61, 0x1C, 0x4F, 0x0C, 0xA0, 0x00, 0x00, 0x00,
    0x63, 0x50, 0x4B, 0x43, 0x53, 0x2D, 0x31, 0x35, 0x50, 0x06, 0x50, 0x4B, 0x43, 0x53, 0x31, 0x35,
    0x51, 0x04, 0x3F, 0x00, 0x50, 0x15, 0x61, 0x18, 0x4F, 0x07, 0xA0, 0x00, 0x00, 0x02, 0x47, 0x10,
    0x01, 0x50, 0x04, 0x49, 0x43, 0x41, 0x4F, 0x51, 0x07, 0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01};

constexpr std::uint16_t kFidMf = 0x3F00;
constexpr std::uint16_t kFidEfDir = 0x2F00;
constexpr std::uint16_t kFidPkcs15Df = 0x5015;
constexpr std::uint16_t kFidEfOdf = 0x5031;
// readProfile() re-selects the applet and reads EF.TokenInfo right after
// EF.ODF, throwing if that SELECT fails -- so the positive scenario below
// must make it selectable under the PKCS15 DF too. Its content is left
// out of `files`: an unselected/absent file's READ BINARY comes back
// empty in this scripted card, and parseTokenInfo(empty) is a defined
// no-throw default, so the SELECT succeeding is all this test needs.
constexpr std::uint16_t kFidTokenInfo = 0x5032;

// Minimal valid EF.ODF: SEQUENCE of length 0 -- a PKCS#15 token with no
// key/cert/PIN directories yet. readProfile() parses this into an empty
// ObjectDirectory and returns without further reads, which is exactly
// what this test needs: proof that the RIGHT application got selected,
// not a full profile.
const std::vector<std::uint8_t> kEmptyOdf = {0x30, 0x00};

// A scripted PKCS#15 card whose file tree is NOT flat: SELECT succeeds
// only for a FID that is an actual child of whatever is currently
// selected (0x3F00/MF is the universal root, always selectable). The
// flat "any known FID selects regardless of context" scripted cards used
// elsewhere in test/ cannot express this, and it is exactly the property
// this test needs: EF.ODF (5031) must be reachable under 3F00/5015 but
// NOT directly under 3F00, so the fixture's two AID-sharing entries are
// actually distinguishable by verification rather than by luck.
struct ScriptedProbeCard
{
    std::map<std::uint16_t, std::vector<std::uint8_t>> files;
    // child FID -> required parent FID (absent from this map => never
    // selectable, except 0x3F00, the hardcoded root).
    std::map<std::uint16_t, std::uint16_t> parentOf;
    bool selectAidSucceeds = false;

    std::uint16_t selectedFid = 0;
    std::vector<APDUCommand> log;

    APDUResponse operator()(const APDUCommand& cmd)
    {
        log.push_back(cmd);

        if (cmd.ins == 0xA4 && cmd.p1 == 0x04) // SELECT by AID
            return selectAidSucceeds ? APDUResponse{{}, 0x90, 0x00} : APDUResponse{{}, 0x6A, 0x82};

        if (cmd.ins == 0xA4 && cmd.p1 == 0x00 && cmd.data.size() == 2) { // SELECT by FID
            const auto fid = static_cast<std::uint16_t>((cmd.data[0] << 8) | cmd.data[1]);
            if (fid == kFidMf) {
                selectedFid = fid;
                return {{}, 0x90, 0x00};
            }
            const auto parentIt = parentOf.find(fid);
            if (parentIt == parentOf.end() || parentIt->second != selectedFid)
                return {{}, 0x6A, 0x82}; // not a child of wherever we currently are
            selectedFid = fid;
            return {{}, 0x90, 0x00};
        }

        if (cmd.ins == 0xB0) { // READ BINARY
            const auto it = files.find(selectedFid);
            if (it == files.end())
                return {{}, 0x69, 0x86};
            const std::size_t offset = (static_cast<std::size_t>(cmd.p1 & 0x7F) << 8) | cmd.p2;
            if (offset >= it->second.size())
                return {{}, 0x62, 0x82}; // EOF
            const std::size_t n = std::min<std::size_t>(cmd.le != 0 ? cmd.le : 256, it->second.size() - offset);
            std::vector<std::uint8_t> chunk(it->second.begin() + static_cast<std::ptrdiff_t>(offset),
                                            it->second.begin() + static_cast<std::ptrdiff_t>(offset + n));
            return {std::move(chunk), 0x90, 0x00};
        }

        return {{}, 0x6D, 0x00}; // anything else: instruction not supported
    }
};

bool isSelectFid(const APDUCommand& cmd, std::uint16_t fid)
{
    return cmd.ins == 0xA4 && cmd.p1 == 0x00 && cmd.data.size() == 2 &&
           static_cast<std::uint16_t>((cmd.data[0] << 8) | cmd.data[1]) == fid;
}

} // namespace

// ---------------------------------------------------------------------------
// Positive: SELECT AID fails (forcing the EF.DIR fallback), EF.DIR carries
// the MF/3F00-then-PKCS15/3F00-5015 duplicate-AID layout, and EF.ODF is
// reachable only under 3F00/5015. probeViaEfDir must land on the SECOND
// (verified) candidate; readProfile() must then succeed end to end.
// ---------------------------------------------------------------------------
TEST(Pkcs15ProbeViaEfDir, SelectsVerifiedPathNotFirstMatch)
{
    ScriptedProbeCard card;
    card.selectAidSucceeds = false;
    card.files = {
        {kFidEfDir, kEfDirDuplicateAid},
        {kFidEfOdf, kEmptyOdf},
    };
    card.parentOf = {
        {kFidEfDir, kFidMf},
        {kFidPkcs15Df, kFidMf},
        {kFidEfOdf, kFidPkcs15Df},     // EF.ODF lives under the PKCS15 DF ONLY
        {kFidTokenInfo, kFidPkcs15Df}, // readProfile() reads this right after EF.ODF
    };

    PCSCConnection conn(PCSCConnection::DetachedTag{}, "Probe EF.DIR Reader (verified)");
    conn.setTransmitFilter([&card](const APDUCommand& cmd) { return card(cmd); });
    LibreSCRS::SecureChannel::PlainChannel channel(conn, LibreSCRS::SmartCard::AppletAid{});

    pkcs15::PKCS15Card pkcs15Card(channel);
    ASSERT_TRUE(pkcs15Card.probe()) << "probe() must succeed via the EF.DIR fallback";
    EXPECT_EQ(pkcs15Card.pkcs15PathView(), (std::vector<std::uint8_t>{0x3F, 0x00, 0x50, 0x15}))
        << "must select the verified PKCS15/3F00-5015 entry, not the first-matched MF/3F00 one";

    EXPECT_NO_THROW({
        auto profile = pkcs15Card.readProfile();
        (void)profile;
    }) << "readProfile() must succeed once the right application is selected";

    // Positive proof the correct path reached the wire: SELECT FID 5015
    // (the PKCS15 DF) appears in the APDU log.
    const bool selectedPkcs15Df = std::any_of(card.log.begin(), card.log.end(),
                                              [](const APDUCommand& c) { return isSelectFid(c, kFidPkcs15Df); });
    EXPECT_TRUE(selectedPkcs15Df) << "SELECT 5015 (the verified PKCS15 DF) never reached the wire";
}

// ---------------------------------------------------------------------------
// Negative: EF.DIR has the same duplicate-AID layout, but EF.ODF is
// reachable under NEITHER candidate path. probeViaEfDir must fail
// outright -- it must NOT fall back to "take the first AID match" (the
// exact regression this task exists to close).
// ---------------------------------------------------------------------------
TEST(Pkcs15ProbeViaEfDir, FailsWhenNoCandidateSelectsEfOdf)
{
    ScriptedProbeCard card;
    card.selectAidSucceeds = false;
    card.files = {
        {kFidEfDir, kEfDirDuplicateAid},
    };
    card.parentOf = {
        {kFidEfDir, kFidMf},
        {kFidPkcs15Df, kFidMf},
        // Deliberately no parent entry for kFidEfOdf: EF.ODF is
        // unreachable from anywhere on this card.
    };

    PCSCConnection conn(PCSCConnection::DetachedTag{}, "Probe EF.DIR Reader (unreachable ODF)");
    conn.setTransmitFilter([&card](const APDUCommand& cmd) { return card(cmd); });
    LibreSCRS::SecureChannel::PlainChannel channel(conn, LibreSCRS::SmartCard::AppletAid{});

    pkcs15::PKCS15Card pkcs15Card(channel);
    EXPECT_FALSE(pkcs15Card.probe()) << "probe() must fail, not silently accept an unverified AID match";
    EXPECT_TRUE(pkcs15Card.pkcs15PathView().empty())
        << "must not have latched onto the first-matched MF/3F00 path when nothing verified";
}
