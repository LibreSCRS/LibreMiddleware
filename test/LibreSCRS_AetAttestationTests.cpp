// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

// Unit test for the AET SafeSign QSCD attestation unlock in
// pkcs15::PKCS15Card::selectApplet(). Uses the FakePCSCConnection seam +
// real PlainChannel so the production selectApplet path runs unmodified.

#include <LibreSCRS/CancelToken.h>
#include <LibreSCRS_internal/SecureChannel/PlainChannel.h>
#include <LibreSCRS/SmartCard/AppletAid.h>

#include "apdu.h"
#include "fake_pcsc_connection.h"
#include "pkcs15_card.h"

#include <gtest/gtest.h>

#include <string>
#include <vector>

namespace {

using LibreSCRS::CancelToken;
using LibreSCRS::SecureChannel::PlainChannel;
using LibreSCRS::SecureChannel::TestSupport::FakePCSCConnection;
using LibreSCRS::SmartCard::AppletAid;
using LibreSCRS::SmartCard::Internal::APDUCommand;
using LibreSCRS::SmartCard::Internal::APDUResponse;

// The exact prompt the locked AET applet returns in its SELECT AID body.
const std::string kLockPrompt = "I am the SafeSign Applet of A.E.T. Europe B.V. please authenticate yourself.\n";

APDUResponse ok()
{
    APDUResponse r;
    r.sw1 = 0x90;
    r.sw2 = 0x00;
    return r;
}

// Expected PUT DATA unlock APDU: 00 DA 01 00 3C + 60-byte ASCII body.
std::vector<std::uint8_t> expectedAttestationApdu()
{
    APDUCommand cmd;
    cmd.cla = 0x00;
    cmd.ins = 0xDA;
    cmd.p1 = 0x01;
    cmd.p2 = 0x00;
    cmd.hasLe = false;
    const std::string body = "I am A.E.T. Europe B.V. SafeSign or BlueX approved software.";
    cmd.data.assign(body.begin(), body.end());
    return cmd.toBytes();
}

// Count PUT DATA (INS=0xDA, P1P2=0x0100) commands in the recorded history.
std::size_t countPutData(const FakePCSCConnection& conn)
{
    std::size_t n = 0;
    for (const auto& cmd : conn.history())
        if (cmd.ins == 0xDA && cmd.p1 == 0x01 && cmd.p2 == 0x00)
            ++n;
    return n;
}

} // namespace

// Locked AET card: SELECT AID returns 9000 + prompt; selectApplet must send
// the attestation PUT DATA exactly once, with the exact bytes.
TEST(AetAttestation, LockedCardSendsAttestation)
{
    FakePCSCConnection conn;
    bool unlocked = false;
    conn.setResponder([&](const APDUCommand& cmd) -> APDUResponse {
        APDUResponse r = ok();
        if (cmd.ins == 0xA4 && cmd.p1 == 0x04) { // SELECT AID
            if (!unlocked)
                r.data.assign(kLockPrompt.begin(), kLockPrompt.end());
        } else if (cmd.ins == 0xDA && cmd.p1 == 0x01 && cmd.p2 == 0x00) {
            unlocked = true; // PUT DATA attestation accepted
        }
        return r;
    });

    PlainChannel channel(conn, AppletAid{});
    pkcs15::PKCS15Card card(channel);

    ASSERT_TRUE(card.selectApplet());
    ASSERT_EQ(countPutData(conn), 1u);

    // Find the PUT DATA and verify exact bytes.
    for (const auto& cmd : conn.history()) {
        if (cmd.ins == 0xDA && cmd.p1 == 0x01 && cmd.p2 == 0x00) {
            EXPECT_EQ(cmd.toBytes(), expectedAttestationApdu());
            break;
        }
    }
}

// Already-unlocked AET card: SELECT AID returns 9000 + empty data; no
// attestation must be sent (prevents the 6D00 non-idempotency footgun).
TEST(AetAttestation, UnlockedCardSendsNoAttestation)
{
    FakePCSCConnection conn;
    conn.setResponder([](const APDUCommand&) { return ok(); }); // empty data, 9000

    PlainChannel channel(conn, AppletAid{});
    pkcs15::PKCS15Card card(channel);

    ASSERT_TRUE(card.selectApplet());
    EXPECT_EQ(countPutData(conn), 0u);
}

// Generic non-AET card: SELECT AID returns 9000 + non-prompt FCI data; the
// attestation branch must stay inert (regression guard for all other cards).
TEST(AetAttestation, GenericCardSendsNoAttestation)
{
    FakePCSCConnection conn;
    conn.setResponder([](const APDUCommand&) {
        APDUResponse r = ok();
        const std::vector<std::uint8_t> fci = {0x6F, 0x07, 0x80, 0x02, 0x00, 0x40, 0x82, 0x01, 0x01};
        r.data = fci;
        return r;
    });

    PlainChannel channel(conn, AppletAid{});
    pkcs15::PKCS15Card card(channel);

    ASSERT_TRUE(card.selectApplet());
    EXPECT_EQ(countPutData(conn), 0u);
}
