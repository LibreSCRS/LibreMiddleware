// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

// What PCSCConnection learns about the Le a card accepts (nothing at connect, one
// command in learnReadLengthBeforeSm), and the READ BINARY rule in transmit(),
// over the real PC/SC body.
//
// No card I/O: this binary provides its own PC/SC entry points, which take
// precedence over libpcsclite's at link time. The connection is the one
// LibreSCRS_SmartCard_RawDiagnostic compiles into the executable, reached
// through openRawDiagnostic because open() is private; it carries the PC/SC
// body on this platform, so the stubs below are what it calls. The source
// never opens a CardSession.

#include <apdu.h>
#include <gtest/gtest.h>
#include <pcsc_connection.h>
#include <pcsc_raw_diagnostic.h>

#include <cstring>
#include <expected>
#include <format>
#include <memory>
#include <span>
#include <string>
#include <vector>

namespace {

using LibreSCRS::SmartCard::Internal::PCSCConnection;
using LibreSCRS::SmartCard::Internal::ReadLengthState;
using Bytes = std::vector<std::uint8_t>;

// Calls the stubs saw, in order: "begin", "end", and "tx:<hex of the command>".
std::vector<std::string> g_events;
// Replies of SCardTransmit, front to back; 9000 once exhausted.
std::vector<Bytes> g_replies;
// Return codes of SCardTransmit, front to back; success once exhausted.
std::vector<LONG> g_transmitRvs;
LONG g_beginRv = SCARD_S_SUCCESS;
DWORD g_protocol = SCARD_PROTOCOL_T1;

std::string hex(const Bytes& bytes)
{
    std::string out;
    for (const auto b : bytes)
        out += std::format("{:02X}", b);
    return out;
}

// The commands sent, as hex.
std::vector<std::string> sentCommands()
{
    std::vector<std::string> sent;
    for (const auto& event : g_events) {
        if (event.rfind("tx:", 0) == 0)
            sent.push_back(event.substr(3));
    }
    return sent;
}

class PcscReadLengthTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        g_events.clear();
        g_replies.clear();
        g_transmitRvs.clear();
        g_beginRv = SCARD_S_SUCCESS;
        g_protocol = SCARD_PROTOCOL_T1;
    }

    // Opens a connection; connecting sends nothing.
    static std::unique_ptr<PCSCConnection> open()
    {
        auto opened = LibreSCRS::SmartCard::Internal::openRawDiagnostic("stub");
        return opened ? std::move(*opened) : nullptr;
    }
};

} // namespace

extern "C" {

LONG SCardEstablishContext(DWORD, LPCVOID, LPCVOID, LPSCARDCONTEXT phContext)
{
    *phContext = 1;
    return SCARD_S_SUCCESS;
}

LONG SCardConnect(SCARDCONTEXT, LPCSTR, DWORD, DWORD, LPSCARDHANDLE phCard, LPDWORD pdwActiveProtocol)
{
    *phCard = 1;
    *pdwActiveProtocol = g_protocol;
    return SCARD_S_SUCCESS;
}

LONG SCardStatus(SCARDHANDLE, LPSTR, LPDWORD, LPDWORD, LPDWORD, LPBYTE pbAtr, LPDWORD pcbAtrLen)
{
    const Bytes atr{0x3B, 0x00};
    std::memcpy(pbAtr, atr.data(), atr.size());
    *pcbAtrLen = static_cast<DWORD>(atr.size());
    return SCARD_S_SUCCESS;
}

LONG SCardBeginTransaction(SCARDHANDLE)
{
    if (g_beginRv != SCARD_S_SUCCESS)
        return g_beginRv;
    g_events.emplace_back("begin");
    return SCARD_S_SUCCESS;
}

LONG SCardEndTransaction(SCARDHANDLE, DWORD)
{
    g_events.emplace_back("end");
    return SCARD_S_SUCCESS;
}

LONG SCardTransmit(SCARDHANDLE, const SCARD_IO_REQUEST*, LPCBYTE pbSendBuffer, DWORD cbSendLength, SCARD_IO_REQUEST*,
                   LPBYTE pbRecvBuffer, LPDWORD pcbRecvLength)
{
    g_events.push_back("tx:" + hex(Bytes(pbSendBuffer, pbSendBuffer + cbSendLength)));
    if (!g_transmitRvs.empty()) {
        const LONG rv = g_transmitRvs.front();
        g_transmitRvs.erase(g_transmitRvs.begin());
        if (rv != SCARD_S_SUCCESS)
            return rv;
    }
    Bytes reply{0x90, 0x00};
    if (!g_replies.empty()) {
        reply = std::move(g_replies.front());
        g_replies.erase(g_replies.begin());
    }
    std::memcpy(pbRecvBuffer, reply.data(), reply.size());
    *pcbRecvLength = static_cast<DWORD>(reply.size());
    return SCARD_S_SUCCESS;
}

LONG SCardDisconnect(SCARDHANDLE, DWORD)
{
    return SCARD_S_SUCCESS;
}

LONG SCardReleaseContext(SCARDCONTEXT)
{
    return SCARD_S_SUCCESS;
}

} // extern "C"

TEST_F(PcscReadLengthTest, ConnectSendsNothingAndLeavesTheStateUntested)
{
    auto conn = open();
    ASSERT_TRUE(conn);

    EXPECT_TRUE(g_events.empty());
    EXPECT_EQ(conn->readLengthPolicy()->state(), ReadLengthState::Untested);
}

TEST_F(PcscReadLengthTest, LearningBeforeSecureMessagingSendsOneCommandAndNoTransactionOfItsOwn)
{
    // The caller holds the transaction; a refusal to begin one must not matter here.
    g_beginRv = static_cast<LONG>(SCARD_E_SHARING_VIOLATION);
    auto conn = open();
    ASSERT_TRUE(conn);
    g_replies = {{0x7F, 0x66, 0x08, 0x02, 0x02, 0x07, 0xFF, 0x02, 0x02, 0x03, 0xC0, 0x90, 0x00}};

    conn->learnReadLengthBeforeSm();

    EXPECT_EQ(g_events, (std::vector<std::string>{"tx:00B08100000800"}));
    EXPECT_EQ(conn->readLengthPolicy()->state(), ReadLengthState::Declared);
    EXPECT_EQ(conn->readLengthPolicy()->declaredResponseMax(), 960U);
}

TEST_F(PcscReadLengthTest, T0IsShortWithoutACommand)
{
    g_protocol = SCARD_PROTOCOL_T0;

    auto conn = open();

    ASSERT_TRUE(conn);
    EXPECT_TRUE(g_events.empty());
    EXPECT_EQ(conn->readLengthPolicy()->state(), ReadLengthState::Short);
}

TEST_F(PcscReadLengthTest, DeclaredCardIsAskedForTheDeclaredLeOnly)
{
    auto conn = open();
    ASSERT_TRUE(conn);
    conn->readLengthPolicy()->learn(ReadLengthState::Declared, 960);

    ASSERT_TRUE(conn->transmit(LibreSCRS::SmartCard::Internal::readBinary(0, 20000)));
    ASSERT_TRUE(conn->transmit(LibreSCRS::SmartCard::Internal::readBinary(0, 100)));

    EXPECT_EQ(sentCommands(), (std::vector<std::string>{"00B000000003BE", "00B0000064"}));
}

TEST_F(PcscReadLengthTest, WrongLengthFromAnUntestedCardIsRepeatedShort)
{
    auto conn = open();
    ASSERT_TRUE(conn);
    g_replies = {{0x67, 0x00}, {0xAA, 0x90, 0x00}};

    const auto response = conn->transmit(LibreSCRS::SmartCard::Internal::readBinary(0x0010, 20000));

    ASSERT_TRUE(response);
    EXPECT_EQ(response->data, (Bytes{0xAA}));
    EXPECT_EQ(sentCommands(), (std::vector<std::string>{"00B00010000800", "00B0001000"}));
    EXPECT_EQ(conn->readLengthPolicy()->state(), ReadLengthState::Short);
}

TEST_F(PcscReadLengthTest, TransportFailureOnAnAcceptedCardDropsToShort)
{
    auto conn = open();
    ASSERT_TRUE(conn);
    conn->readLengthPolicy()->learn(ReadLengthState::Accepted);
    g_transmitRvs = {static_cast<LONG>(SCARD_F_COMM_ERROR)};
    g_replies = {{0xAA, 0x90, 0x00}};

    const auto response = conn->transmit(LibreSCRS::SmartCard::Internal::readBinary(0, 20000));

    ASSERT_TRUE(response);
    EXPECT_TRUE(response->isSuccess());
    EXPECT_EQ(conn->readLengthPolicy()->state(), ReadLengthState::Short);
}
