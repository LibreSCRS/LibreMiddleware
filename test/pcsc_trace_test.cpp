// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

// The PC/SC trace channel: off by default, and when on it never carries what
// the card answered or the PIN a command sent.
//
// No card I/O: this binary provides its own SCardTransmit, which takes
// precedence over libpcsclite's at link time, and drives the real transmit
// path through a detached connection.

#include <LibreSCRS/Logging.h>

#include <apdu.h>
#include <gtest/gtest.h>
#include <pcsc_connection.h>

#include <cstdlib>
#include <cstring>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace {

using LibreSCRS::SmartCard::Internal::PCSCConnection;

std::vector<std::uint8_t> g_reply;

struct Line
{
    LibreSCRS::log::Level level;
    std::string text;
};

class PcscTraceTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        // A recognisable payload: any trace line that carries it leaks the
        // card's answer.
        g_reply = {0xDE, 0xAD, 0xBE, 0xEF, 0x90, 0x00};
    }

    void TearDown() override
    {
        ::unsetenv("LIBRESCRS_PCSC_TRACE");
        LibreSCRS::log::resetForTest();
    }

    void captureWithTrace(bool on)
    {
        if (on)
            ::setenv("LIBRESCRS_PCSC_TRACE", "1", 1);
        else
            ::unsetenv("LIBRESCRS_PCSC_TRACE");
        LibreSCRS::log::resetForTest();
        LibreSCRS::log::init([this](LibreSCRS::log::Level level, std::string_view line) {
            lines.push_back({level, std::string(line)});
        });
    }

    [[nodiscard]] bool anyLineContains(std::string_view needle) const
    {
        for (const auto& l : lines)
            if (l.text.find(needle) != std::string::npos)
                return true;
        return false;
    }

    std::vector<Line> lines;
};

} // namespace

extern "C" {

LONG SCardTransmit(SCARDHANDLE, const SCARD_IO_REQUEST*, LPCBYTE, DWORD, SCARD_IO_REQUEST*, LPBYTE pbRecvBuffer,
                   LPDWORD pcbRecvLength)
{
    std::memcpy(pbRecvBuffer, g_reply.data(), g_reply.size());
    *pcbRecvLength = static_cast<DWORD>(g_reply.size());
    return SCARD_S_SUCCESS;
}

} // extern "C"

TEST_F(PcscTraceTest, OffByDefaultEmitsNothing)
{
    captureWithTrace(false);
    PCSCConnection conn(PCSCConnection::DetachedTag{}, "test-reader");

    const auto response = conn.transmit(LibreSCRS::SmartCard::Internal::readBinary(0x0000, 0x04));

    EXPECT_TRUE(response.isSuccess());
    EXPECT_TRUE(lines.empty()) << "first line: " << (lines.empty() ? "" : lines.front().text);
}

TEST_F(PcscTraceTest, ResponseIsTracedAsLengthAndStatusWordOnly)
{
    captureWithTrace(true);
    PCSCConnection conn(PCSCConnection::DetachedTag{}, "test-reader");

    const auto response = conn.transmit(LibreSCRS::SmartCard::Internal::readBinary(0x0000, 0x04));

    ASSERT_TRUE(response.isSuccess());
    ASSERT_FALSE(lines.empty());
    for (const auto& l : lines)
        EXPECT_EQ(l.level, LibreSCRS::log::Level::Trace) << l.text;
    EXPECT_TRUE(anyLineContains("rx=6 bytes sw=9000"));
    EXPECT_FALSE(anyLineContains("DEADBEEF"));
    EXPECT_FALSE(anyLineContains("DE AD BE EF"));
    EXPECT_FALSE(anyLineContains("deadbeef"));
    EXPECT_FALSE(anyLineContains("de ad be ef"));
}

TEST_F(PcscTraceTest, PinBytesOfAVerifyAreNeverTraced)
{
    captureWithTrace(true);
    PCSCConnection conn(PCSCConnection::DetachedTag{}, "test-reader");
    g_reply = {0x90, 0x00};

    // Dummy bytes shaped like a PIN, not a real one.
    const std::vector<std::uint8_t> dummyPin = {0xA1, 0xB2, 0xC3, 0xD4};
    (void)conn.transmit(LibreSCRS::SmartCard::Internal::verifyPIN(0x01, dummyPin));

    ASSERT_FALSE(lines.empty());
    EXPECT_TRUE(anyLineContains("<redacted 4 bytes>"));
    EXPECT_FALSE(anyLineContains("A1B2C3D4"));
    EXPECT_FALSE(anyLineContains("a1b2c3d4"));
}
