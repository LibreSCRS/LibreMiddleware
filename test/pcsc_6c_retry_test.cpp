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
#include <span>
#include <vector>

namespace {

using LibreSCRS::SmartCard::Internal::APDUCommand;
using LibreSCRS::SmartCard::Internal::PCSCConnection;
using LibreSCRS::SmartCard::Internal::verifyPIN;

// Wire log of every APDU the stub receives, plus the scripted replies
// (consumed front to back; when exhausted the stub answers SW=9000).
std::vector<std::vector<uint8_t>> g_sentApdus;
std::vector<std::vector<uint8_t>> g_scriptedReplies;
// Return codes for SCardTransmit, consumed front to back; SCARD_S_SUCCESS once
// exhausted. A call answered with an error records the APDU and returns no data.
std::vector<LONG> g_transmitRvs;
int g_reconnects = 0;
// The receive buffer of the last SCardTransmit: the connection's own, which
// outlives the call.
const uint8_t* g_lastRecvBuffer = nullptr;

class Pcsc6cRetryTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        g_sentApdus.clear();
        g_scriptedReplies.clear();
        g_transmitRvs.clear();
        g_reconnects = 0;
        g_lastRecvBuffer = nullptr;
    }
};

} // namespace

extern "C" {

// Overrides libpcsclite's SCardReconnect: reports success and selects T=0,
// the only protocol for which the 6C retry path is live.
LONG SCardReconnect(SCARDHANDLE, DWORD, DWORD, DWORD, LPDWORD pdwActiveProtocol)
{
    ++g_reconnects;
    *pdwActiveProtocol = SCARD_PROTOCOL_T0;
    return SCARD_S_SUCCESS;
}

// Overrides libpcsclite's SCardTransmit: records the sent APDU and plays
// back the next scripted reply.
LONG SCardTransmit(SCARDHANDLE, const SCARD_IO_REQUEST*, LPCBYTE pbSendBuffer, DWORD cbSendLength, SCARD_IO_REQUEST*,
                   LPBYTE pbRecvBuffer, LPDWORD pcbRecvLength)
{
    g_sentApdus.emplace_back(pbSendBuffer, pbSendBuffer + cbSendLength);
    if (!g_transmitRvs.empty()) {
        const LONG rv = g_transmitRvs.front();
        g_transmitRvs.erase(g_transmitRvs.begin());
        if (rv != SCARD_S_SUCCESS)
            return rv;
    }

    std::vector<uint8_t> reply = {0x90, 0x00};
    if (!g_scriptedReplies.empty()) {
        reply = std::move(g_scriptedReplies.front());
        g_scriptedReplies.erase(g_scriptedReplies.begin());
    }
    std::memcpy(pbRecvBuffer, reply.data(), reply.size());
    *pcbRecvLength = static_cast<DWORD>(reply.size());
    g_lastRecvBuffer = pbRecvBuffer;
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

// After SCARD_W_RESET_CARD the connection reconnects and resends a command
// once. A command that carries a PIN is never resent: the resend could reach a
// different card, or one whose state the reset cleared, and spend a try there.
// The INS is byte 1 in a secure-messaging wrapped APDU as well.
class Pcsc6cRetrySensitiveTest : public Pcsc6cRetryTest, public ::testing::WithParamInterface<std::vector<uint8_t>>
{};

TEST_P(Pcsc6cRetrySensitiveTest, SensitiveCommandIsNeverResentAfterReset)
{
    PCSCConnection conn(PCSCConnection::DetachedTag{}, "test-reader");
    const std::vector<uint8_t> apdu = GetParam();
    g_transmitRvs.push_back(static_cast<LONG>(SCARD_W_RESET_CARD));

    try {
        (void)conn.transmitRaw(std::span<const uint8_t>(apdu));
        ADD_FAILURE() << "a PIN-carrying command after a reset must not succeed";
    } catch (const LibreSCRS::SmartCard::Internal::PCSCError& e) {
        EXPECT_EQ(e.code(), static_cast<LONG>(SCARD_W_RESET_CARD));
    }
    EXPECT_EQ(g_sentApdus.size(), 1u) << "sent once, never resent";
    EXPECT_EQ(g_reconnects, 1) << "the handle is re-established for the next call";
}

INSTANTIATE_TEST_SUITE_P(PinVerbs, Pcsc6cRetrySensitiveTest,
                         ::testing::Values(std::vector<uint8_t>{0x00, 0x20, 0x00, 0x01, 0x04, 0xAA, 0xBB, 0xCC, 0xDD},
                                           std::vector<uint8_t>{0x00, 0x24, 0x00, 0x01, 0x04, 0xAA, 0xBB, 0xCC, 0xDD},
                                           std::vector<uint8_t>{0x00, 0x2C, 0x00, 0x01, 0x04, 0xAA, 0xBB, 0xCC, 0xDD},
                                           std::vector<uint8_t>{0x0C, 0x20, 0x00, 0x01, 0x04, 0x87, 0x02, 0x01, 0x00},
                                           // Any secure-messaging command: the reset ended the SM session.
                                           std::vector<uint8_t>{0x0C, 0xB0, 0x00, 0x00, 0x04, 0x97, 0x01, 0x00, 0x00}));

TEST_F(Pcsc6cRetryTest, PlainCommandIsResentOnceAfterReset)
{
    PCSCConnection conn(PCSCConnection::DetachedTag{}, "test-reader");
    const std::vector<uint8_t> readBinary{0x00, 0xB0, 0x00, 0x00, 0x04};
    g_transmitRvs.push_back(static_cast<LONG>(SCARD_W_RESET_CARD));
    g_scriptedReplies.push_back({0x01, 0x02, 0x03, 0x04, 0x90, 0x00});

    const auto response = conn.transmitRaw(std::span<const uint8_t>(readBinary));

    EXPECT_EQ(g_sentApdus.size(), 2u);
    EXPECT_EQ(g_reconnects, 1);
    EXPECT_TRUE(response.isSuccess());
}

// A card that keeps answering 61xx past 64 KiB gets no answer at all: 6700
// with no data, never the first 64 KiB under a success status word.
TEST_F(Pcsc6cRetryTest, GetResponseChainPastTheCapIsNoAnswer)
{
    PCSCConnection conn(PCSCConnection::DetachedTag{}, "test-reader");
    const std::vector<uint8_t> chunk(256, 0x5A);
    for (int i = 0; i < 300; ++i) {
        auto reply = chunk;
        reply.push_back(0x61);
        reply.push_back(0x00);
        g_scriptedReplies.push_back(std::move(reply));
    }

    const auto response = conn.transmit(LibreSCRS::SmartCard::Internal::readBinary(0x0000, 0x00));

    EXPECT_EQ(response.statusWord(), 0x6700);
    EXPECT_TRUE(response.data.empty());
}

// The connection receives every answer into a buffer its thread keeps for the
// next call. What the card answered -- a decrypted block, a personal record --
// reaches the caller and is not left behind in that buffer.
using PcscReceiveBufferTest = Pcsc6cRetryTest;

TEST_F(PcscReceiveBufferTest, TheCardsAnswerDoesNotStayInTheReceiveBuffer)
{
    PCSCConnection conn(PCSCConnection::DetachedTag{}, "test-reader");
    const std::vector<uint8_t> answer(48, 0xA5);
    auto reply = answer;
    reply.push_back(0x90);
    reply.push_back(0x00);
    g_scriptedReplies.push_back(reply);
    const std::vector<uint8_t> readBinary{0x00, 0xB0, 0x00, 0x00, 0x30};

    const auto response = conn.transmitRaw(std::span<const uint8_t>(readBinary));

    ASSERT_TRUE(response.isSuccess());
    EXPECT_EQ(response.data, answer) << "the caller still gets the answer";
    ASSERT_NE(g_lastRecvBuffer, nullptr);
    const std::vector<uint8_t> left(g_lastRecvBuffer, g_lastRecvBuffer + reply.size());
    EXPECT_EQ(left, std::vector<uint8_t>(reply.size(), 0x00)) << "the answer stayed in the receive buffer";
}
