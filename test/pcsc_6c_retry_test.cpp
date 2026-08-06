// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

// T=0 SW1=6C ("wrong Le") retry semantics of PCSCConnection::transmit().
//
// ISO 7816-4: 6C XX instructs the host to resend the SAME command with
// Le = XX. Only a command that actually carries an Le byte can be
// corrected this way. For an Le-less command (case 1 / case 3 — every
// PIN verb: VERIFY, CHANGE REFERENCE DATA, RESET RETRY COUNTER) the last
// serialized byte is command DATA (or P2), so it must never be rewritten;
// the 6C status is surfaced to the caller instead.
//
// No card I/O: this binary provides its own SCardTransmit/SCardReconnect
// definitions, which take precedence over libpcsclite's at link time, and
// drives the real transmit() implementation through a detached connection.

#include <apdu.h>
#include <gtest/gtest.h>
#include <pcsc_connection.h>

#include <cstring>
#include <vector>

namespace {

using LibreSCRS::SmartCard::Internal::APDUCommand;
using LibreSCRS::SmartCard::Internal::PCSCConnection;
using LibreSCRS::SmartCard::Internal::verifyPIN;

// Wire log of every APDU the stub receives, plus the scripted replies
// (consumed front to back; when exhausted the stub answers SW=9000).
std::vector<std::vector<uint8_t>> g_sentApdus;
std::vector<std::vector<uint8_t>> g_scriptedReplies;

class Pcsc6cRetryTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        g_sentApdus.clear();
        g_scriptedReplies.clear();
    }
};

} // namespace

extern "C" {

// Overrides libpcsclite's SCardReconnect: reports success and selects T=0,
// the only protocol for which the 6C retry path is live.
LONG SCardReconnect(SCARDHANDLE, DWORD, DWORD, DWORD, LPDWORD pdwActiveProtocol)
{
    *pdwActiveProtocol = SCARD_PROTOCOL_T0;
    return SCARD_S_SUCCESS;
}

// Overrides libpcsclite's SCardTransmit: records the sent APDU and plays
// back the next scripted reply.
LONG SCardTransmit(SCARDHANDLE, const SCARD_IO_REQUEST*, LPCBYTE pbSendBuffer, DWORD cbSendLength, SCARD_IO_REQUEST*,
                   LPBYTE pbRecvBuffer, LPDWORD pcbRecvLength)
{
    g_sentApdus.emplace_back(pbSendBuffer, pbSendBuffer + cbSendLength);

    std::vector<uint8_t> reply = {0x90, 0x00};
    if (!g_scriptedReplies.empty()) {
        reply = std::move(g_scriptedReplies.front());
        g_scriptedReplies.erase(g_scriptedReplies.begin());
    }
    std::memcpy(pbRecvBuffer, reply.data(), reply.size());
    *pcbRecvLength = static_cast<DWORD>(reply.size());
    return SCARD_S_SUCCESS;
}

} // extern "C"

// Regression: a case-3 PIN-shaped command (dummy bytes, not a real PIN)
// answered with 6C must NOT be resent with its last data byte rewritten —
// that would resend a VERIFY with a corrupted PIN and consume a retry.
TEST_F(Pcsc6cRetryTest, LeLessCommandIsNeverMutatedOn6C)
{
    PCSCConnection conn(PCSCConnection::DetachedTag{}, "test-reader");
    conn.reconnect(); // stubbed: activates T=0

    const std::vector<uint8_t> dummyPin = {0xAA, 0xBB, 0xCC, 0xDD};
    const APDUCommand cmd = verifyPIN(0x01, dummyPin);
    const std::vector<uint8_t> wire = cmd.toBytes();
    ASSERT_FALSE(cmd.hasLe);
    ASSERT_EQ(wire.back(), 0xDD); // last wire byte is PIN data

    g_scriptedReplies.push_back({0x6C, 0x07});
    const auto response = conn.transmit(cmd);

    // No resend: the single transmitted APDU is byte-identical to the
    // original, and the 6C status reaches the caller.
    ASSERT_EQ(g_sentApdus.size(), 1u);
    EXPECT_EQ(g_sentApdus[0], wire);
    EXPECT_EQ(response.statusWord(), 0x6C07);
}

// The legitimate 6C flow still works: a command WITH an Le byte is resent
// once with Le corrected to SW2.
TEST_F(Pcsc6cRetryTest, LeCommandIsResentWithCorrectedLe)
{
    PCSCConnection conn(PCSCConnection::DetachedTag{}, "test-reader");
    conn.reconnect(); // stubbed: activates T=0

    const APDUCommand cmd = LibreSCRS::SmartCard::Internal::readBinary(0x0000, 0x10);
    ASSERT_TRUE(cmd.hasLe);

    g_scriptedReplies.push_back({0x6C, 0x07});
    g_scriptedReplies.push_back({0x01, 0x02, 0x03, 0x90, 0x00});
    const auto response = conn.transmit(cmd);

    ASSERT_EQ(g_sentApdus.size(), 2u);
    const std::vector<uint8_t> expectedRetry = {0x00, 0xB0, 0x00, 0x00, 0x07};
    EXPECT_EQ(g_sentApdus[1], expectedRetry);
    EXPECT_TRUE(response.isSuccess());
    EXPECT_EQ(response.data, (std::vector<uint8_t>{0x01, 0x02, 0x03}));
}
