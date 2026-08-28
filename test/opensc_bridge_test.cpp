// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <gtest/gtest.h>

#include <stdexcept>
#include <vector>

#include "opensc_reader_bridge.h"
#include <LibreSCRS/CancelToken.h>
#include <fake_channel.h>
#include <pcsc_connection.h>

using namespace LibreSCRS::OpenSc::Bridge;
using LibreSCRS::CancelSource;
using LibreSCRS::SecureChannel::ChannelState;
using LibreSCRS::SecureChannel::TestSupport::FakeChannel;
using LibreSCRS::SmartCard::AppletAid;
using LibreSCRS::SmartCard::Internal::APDUResponse;
using LibreSCRS::SmartCard::Internal::CardTransaction;
using LibreSCRS::SmartCard::Internal::PCSCConnection;

// The reader ops are wired into reader.ops by initBridgeReader; we drive them
// directly. A DetachedTag connection performs no PC/SC I/O: beginTransaction/
// endTransaction are no-ops, isTransactionHeld reflects CardTransaction
// ownership, and transmitRaw raises a PCSCError — enough to prove the bridge's
// lock-nesting decision and exception-safety without hardware. The actual wire
// round-trip (sc_apdu_get_octets/set_resp <-> conn.transmitRaw) is exercised by
// the HW integration test (opensc_fallback_integration_test.cpp).

TEST(OpenScBridgeLock, AcquiresOwnTransactionWhenNoneHeld)
{
    PCSCConnection conn(PCSCConnection::DetachedTag{}, "FakeReader0");
    OpenScBridge bridge;
    bridge.data.conn = &conn;
    bridge.readerName = "FakeReader0";

    sc_context_t* ctx = nullptr;
    ASSERT_EQ(sc_establish_context(&ctx, "librescrs-bridge-test"), 0);
    const std::vector<uint8_t> atr{0x3B, 0x00};
    initBridgeReader(ctx, bridge, atr);

    EXPECT_FALSE(conn.isTransactionHeld());
    ASSERT_EQ(bridge.reader.ops->lock(&bridge.reader), SC_SUCCESS);
    EXPECT_TRUE(bridge.data.ownsTransaction); // began its own
    ASSERT_EQ(bridge.reader.ops->unlock(&bridge.reader), SC_SUCCESS);
    EXPECT_FALSE(bridge.data.ownsTransaction);

    sc_release_context(ctx);
}

TEST(OpenScBridgeLock, DefersToHolderTransaction)
{
    PCSCConnection conn(PCSCConnection::DetachedTag{}, "FakeReader1");
    OpenScBridge bridge;
    bridge.data.conn = &conn;
    bridge.readerName = "FakeReader1";

    sc_context_t* ctx = nullptr;
    ASSERT_EQ(sc_establish_context(&ctx, "librescrs-bridge-test"), 0);
    const std::vector<uint8_t> atr{0x3B, 0x00};
    initBridgeReader(ctx, bridge, atr);

    CardTransaction holderTxn(conn); // the agent's ActiveChannelHolder analogue
    EXPECT_TRUE(conn.isTransactionHeld());

    ASSERT_EQ(bridge.reader.ops->lock(&bridge.reader), SC_SUCCESS);
    EXPECT_FALSE(bridge.data.ownsTransaction); // deferred — no nested begin
    ASSERT_EQ(bridge.reader.ops->unlock(&bridge.reader), SC_SUCCESS);
    EXPECT_TRUE(conn.isTransactionHeld()); // holder's transaction intact

    sc_release_context(ctx);
}

TEST(OpenScBridgeTransmit, ConvertsTransmitFailureToScErrorWithoutThrowing)
{
    // A DetachedTag connection has no card handle: PCSCConnection::transmitRaw
    // raises a PCSCError (SCardTransmit on a null handle). The bridge transmit
    // op MUST catch it and return an SC error code — a C++ exception crossing
    // the libopensc C frames would be undefined behaviour. This is the
    // exception-safety contract; the wire-level round trip is covered by the
    // HW test.
    PCSCConnection conn(PCSCConnection::DetachedTag{}, "FakeReader2");
    OpenScBridge bridge;
    bridge.data.conn = &conn;
    bridge.readerName = "FakeReader2";

    sc_context_t* ctx = nullptr;
    ASSERT_EQ(sc_establish_context(&ctx, "librescrs-bridge-test"), 0);
    const std::vector<uint8_t> atr{0x3B, 0x00};
    initBridgeReader(ctx, bridge, atr);

    sc_apdu_t a{};
    a.cse = SC_APDU_CASE_2_SHORT;
    a.cla = 0x00;
    a.ins = 0xCA;
    a.p1 = 0x00;
    a.p2 = 0x00;
    a.le = 256;
    uint8_t respbuf[256] = {};
    a.resp = respbuf;
    a.resplen = sizeof(respbuf);

    int rc = SC_SUCCESS;
    EXPECT_NO_THROW({ rc = bridge.reader.ops->transmit(&bridge.reader, &a); });
    EXPECT_EQ(rc, SC_ERROR_TRANSMIT_FAILED);

    sc_release_context(ctx);
}

// ── Tunnel branch ──────────────────────────────────────────────────────────
// With BridgeData::channel installed, the transmit op forwards the sc_apdu
// through the live secure channel (field-by-field mapping, short cases only)
// instead of the raw connection. The FakeChannel captures the mapped
// APDUCommand and the forwarded CancelToken, and scripts replies via
// transmitHandler. SW bytes pass through UNCHANGED; fatality is judged by
// channel STATE (sentinel 6F00/6F02 with an empty body while the channel is
// no longer Open), never by SW pattern.

class OpenScBridgeTunnel : public ::testing::Test
{
protected:
    void SetUp() override
    {
        ASSERT_EQ(sc_establish_context(&ctx, "librescrs-bridge-test"), 0);
        bridge.data.conn = &conn;
        bridge.readerName = "FakeReaderTunnel";
        const std::vector<uint8_t> atr{0x3B, 0x00};
        initBridgeReader(ctx, bridge, atr);
        bridge.data.channel = &channel;
    }

    void TearDown() override
    {
        sc_release_context(ctx);
    }

    int transmit(sc_apdu_t* apdu)
    {
        return bridge.reader.ops->transmit(&bridge.reader, apdu);
    }

    PCSCConnection conn{PCSCConnection::DetachedTag{}, "FakeReaderTunnel"};
    OpenScBridge bridge;
    FakeChannel channel{AppletAid{0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01}, ChannelState::Open, /*carriesSm=*/true};
    sc_context_t* ctx = nullptr;
};

TEST_F(OpenScBridgeTunnel, MapsCase1WithoutLe)
{
    sc_apdu_t a{};
    a.cse = SC_APDU_CASE_1;
    a.cla = 0x00;
    a.ins = 0xA4;
    a.p1 = 0x04;
    a.p2 = 0x0C;

    ASSERT_EQ(transmit(&a), SC_SUCCESS);
    const auto& cmd = channel.lastWrappedCommand();
    EXPECT_EQ(cmd.cla, 0x00);
    EXPECT_EQ(cmd.ins, 0xA4);
    EXPECT_EQ(cmd.p1, 0x04);
    EXPECT_EQ(cmd.p2, 0x0C);
    EXPECT_TRUE(cmd.data.empty());
    EXPECT_FALSE(cmd.hasLe);
    EXPECT_EQ(a.sw1, 0x90u);
    EXPECT_EQ(a.sw2, 0x00u);
}

TEST_F(OpenScBridgeTunnel, MapsCase2ShortWithLe)
{
    sc_apdu_t a{};
    a.cse = SC_APDU_CASE_2_SHORT;
    a.cla = 0x00;
    a.ins = 0xB0;
    a.p1 = 0x00;
    a.p2 = 0x00;
    a.le = 4;
    uint8_t respbuf[4] = {};
    a.resp = respbuf;
    a.resplen = sizeof(respbuf);

    ASSERT_EQ(transmit(&a), SC_SUCCESS);
    const auto& cmd = channel.lastWrappedCommand();
    EXPECT_TRUE(cmd.data.empty());
    EXPECT_TRUE(cmd.hasLe);
    EXPECT_EQ(cmd.le, 4);
}

TEST_F(OpenScBridgeTunnel, MapsLe256ToZero)
{
    sc_apdu_t a{};
    a.cse = SC_APDU_CASE_2_SHORT;
    a.cla = 0x00;
    a.ins = 0xB0;
    a.p1 = 0x00;
    a.p2 = 0x00;
    a.le = 256;
    uint8_t respbuf[256] = {};
    a.resp = respbuf;
    a.resplen = sizeof(respbuf);

    ASSERT_EQ(transmit(&a), SC_SUCCESS);
    const auto& cmd = channel.lastWrappedCommand();
    EXPECT_TRUE(cmd.hasLe);
    EXPECT_EQ(cmd.le, 0);
}

TEST_F(OpenScBridgeTunnel, MapsCase3ShortDataWithoutLe)
{
    const uint8_t path[] = {0x3F, 0x00};
    sc_apdu_t a{};
    a.cse = SC_APDU_CASE_3_SHORT;
    a.cla = 0x00;
    a.ins = 0xA4;
    a.p1 = 0x00;
    a.p2 = 0x0C;
    a.data = path;
    a.datalen = sizeof(path);
    a.lc = sizeof(path);

    ASSERT_EQ(transmit(&a), SC_SUCCESS);
    const auto& cmd = channel.lastWrappedCommand();
    EXPECT_EQ(cmd.data, (std::vector<uint8_t>{0x3F, 0x00}));
    EXPECT_FALSE(cmd.hasLe);
}

TEST_F(OpenScBridgeTunnel, MapsCase4ShortDataAndLe)
{
    const uint8_t aid[] = {0xA0, 0x00, 0x00, 0x02, 0x47};
    sc_apdu_t a{};
    a.cse = SC_APDU_CASE_4_SHORT;
    a.cla = 0x00;
    a.ins = 0xA4;
    a.p1 = 0x04;
    a.p2 = 0x00;
    a.data = aid;
    a.datalen = sizeof(aid);
    a.lc = sizeof(aid);
    a.le = 256;
    uint8_t respbuf[256] = {};
    a.resp = respbuf;
    a.resplen = sizeof(respbuf);

    ASSERT_EQ(transmit(&a), SC_SUCCESS);
    const auto& cmd = channel.lastWrappedCommand();
    EXPECT_EQ(cmd.data, (std::vector<uint8_t>{0xA0, 0x00, 0x00, 0x02, 0x47}));
    EXPECT_TRUE(cmd.hasLe);
    EXPECT_EQ(cmd.le, 0);
}

TEST_F(OpenScBridgeTunnel, RejectsExtendedApduWithoutTouchingChannel)
{
    sc_apdu_t a{};
    a.cse = SC_APDU_CASE_2_EXT;
    a.cla = 0x00;
    a.ins = 0xB0;
    a.p1 = 0x00;
    a.p2 = 0x00;
    a.le = 65536;

    EXPECT_EQ(transmit(&a), SC_ERROR_NOT_SUPPORTED);
    EXPECT_EQ(channel.transmits(), 0);
}

TEST_F(OpenScBridgeTunnel, PassesSwThroughUnchanged)
{
    // 6988 (SM data object incorrect) is the measured SM-fatal SW: the card
    // driver above the bridge must see it EXACTLY as the card returned it.
    channel.transmitHandler = [](const auto&) {
        APDUResponse r;
        r.sw1 = 0x69;
        r.sw2 = 0x88;
        return r;
    };

    sc_apdu_t a{};
    a.cse = SC_APDU_CASE_1;
    a.cla = 0x00;
    a.ins = 0xA4;
    a.p1 = 0x04;
    a.p2 = 0x0C;

    ASSERT_EQ(transmit(&a), SC_SUCCESS);
    EXPECT_EQ(a.sw1, 0x69u);
    EXPECT_EQ(a.sw2, 0x88u);
}

TEST_F(OpenScBridgeTunnel, PassesRealCard6F00ThroughWhileChannelOpen)
{
    // A REAL card 6F00 with the channel still Open is NOT a sentinel:
    // fatality is judged by channel state, never by SW pattern.
    channel.transmitHandler = [](const auto&) {
        APDUResponse r;
        r.sw1 = 0x6F;
        r.sw2 = 0x00;
        return r;
    };

    sc_apdu_t a{};
    a.cse = SC_APDU_CASE_1;
    a.cla = 0x00;
    a.ins = 0x00;
    a.p1 = 0x00;
    a.p2 = 0x00;

    ASSERT_EQ(transmit(&a), SC_SUCCESS);
    EXPECT_EQ(a.sw1, 0x6Fu);
    EXPECT_EQ(a.sw2, 0x00u);
}

TEST_F(OpenScBridgeTunnel, CancelSentinel6F01IsNotHandledHere)
{
    // 6F01 (cancel) leaves the channel Open; cancellation is detected via
    // the operation token by the caller, never by the bridge.
    channel.transmitHandler = [](const auto&) {
        APDUResponse r;
        r.sw1 = 0x6F;
        r.sw2 = 0x01;
        return r;
    };

    sc_apdu_t a{};
    a.cse = SC_APDU_CASE_1;
    a.cla = 0x00;
    a.ins = 0xA4;
    a.p1 = 0x04;
    a.p2 = 0x0C;

    ASSERT_EQ(transmit(&a), SC_SUCCESS);
    EXPECT_EQ(a.sw1, 0x6Fu);
    EXPECT_EQ(a.sw2, 0x01u);
}

TEST_F(OpenScBridgeTunnel, FailsOnFailedSentinelWhenChannelNotOpen)
{
    channel.setState(ChannelState::Failed);
    channel.transmitHandler = [](const auto&) {
        APDUResponse r;
        r.sw1 = 0x6F;
        r.sw2 = 0x02;
        return r;
    };

    sc_apdu_t a{};
    a.cse = SC_APDU_CASE_1;
    a.cla = 0x00;
    a.ins = 0xA4;
    a.p1 = 0x04;
    a.p2 = 0x0C;

    EXPECT_EQ(transmit(&a), SC_ERROR_TRANSMIT_FAILED);
}

TEST_F(OpenScBridgeTunnel, FailsOnClosedSentinelWhenChannelNotOpen)
{
    channel.setState(ChannelState::Closed);
    channel.transmitHandler = [](const auto&) {
        APDUResponse r;
        r.sw1 = 0x6F;
        r.sw2 = 0x00;
        return r;
    };

    sc_apdu_t a{};
    a.cse = SC_APDU_CASE_1;
    a.cla = 0x00;
    a.ins = 0xA4;
    a.p1 = 0x04;
    a.p2 = 0x0C;

    EXPECT_EQ(transmit(&a), SC_ERROR_TRANSMIT_FAILED);
}

TEST_F(OpenScBridgeTunnel, ClampsResponseBodyToResplen)
{
    channel.transmitHandler = [](const auto&) {
        APDUResponse r;
        r.data = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
        r.sw1 = 0x90;
        r.sw2 = 0x00;
        return r;
    };

    sc_apdu_t a{};
    a.cse = SC_APDU_CASE_2_SHORT;
    a.cla = 0x00;
    a.ins = 0xB0;
    a.p1 = 0x00;
    a.p2 = 0x00;
    a.le = 4;
    uint8_t respbuf[4] = {};
    a.resp = respbuf;
    a.resplen = sizeof(respbuf);

    ASSERT_EQ(transmit(&a), SC_SUCCESS);
    EXPECT_EQ(a.resplen, 4u);
    EXPECT_EQ(respbuf[0], 0x01);
    EXPECT_EQ(respbuf[3], 0x04);
    EXPECT_EQ(a.sw1, 0x90u);
    EXPECT_EQ(a.sw2, 0x00u);
}

TEST_F(OpenScBridgeTunnel, HandlesNullResponseBuffer)
{
    channel.transmitHandler = [](const auto&) {
        APDUResponse r;
        r.data = {0xAA, 0xBB};
        r.sw1 = 0x90;
        r.sw2 = 0x00;
        return r;
    };

    sc_apdu_t a{};
    a.cse = SC_APDU_CASE_3_SHORT;
    a.cla = 0x00;
    a.ins = 0xA4;
    const uint8_t path[] = {0x3F, 0x00};
    a.data = path;
    a.datalen = sizeof(path);
    a.lc = sizeof(path);

    ASSERT_EQ(transmit(&a), SC_SUCCESS);
    EXPECT_EQ(a.resplen, 0u);
    EXPECT_EQ(a.sw1, 0x90u);
}

TEST_F(OpenScBridgeTunnel, ExceptionFromChannelBecomesTransmitFailed)
{
    // Card removal mid-operation: the PCSCError from transmitRaw propagates
    // through the channel; the bridge must catch it at the C boundary.
    channel.transmitHandler = [](const auto&) -> APDUResponse { throw std::runtime_error("card removed"); };

    sc_apdu_t a{};
    a.cse = SC_APDU_CASE_1;
    a.cla = 0x00;
    a.ins = 0xA4;
    a.p1 = 0x04;
    a.p2 = 0x0C;

    int rc = SC_SUCCESS;
    EXPECT_NO_THROW({ rc = transmit(&a); });
    EXPECT_EQ(rc, SC_ERROR_TRANSMIT_FAILED);
}

TEST_F(OpenScBridgeTunnel, ForwardsOperationTokenToChannel)
{
    CancelSource src;
    bridge.data.token = src.token();

    sc_apdu_t a{};
    a.cse = SC_APDU_CASE_1;
    a.cla = 0x00;
    a.ins = 0xA4;
    a.p1 = 0x04;
    a.p2 = 0x0C;

    ASSERT_EQ(transmit(&a), SC_SUCCESS);
    // A default-constructed token is never cancellable — cancellability
    // proves the OPERATION token reached the channel, and the shared state
    // proves a later cancellation is visible through it.
    EXPECT_TRUE(channel.lastToken().isCancellable());
    EXPECT_FALSE(channel.lastToken().isCancelled());
    src.requestCancel();
    EXPECT_TRUE(channel.lastToken().isCancelled());
}

TEST_F(OpenScBridgeTunnel, LeavesReaderSizesUntouched)
{
    sc_apdu_t a{};
    a.cse = SC_APDU_CASE_1;
    a.cla = 0x00;
    a.ins = 0xA4;
    a.p1 = 0x04;
    a.p2 = 0x0C;

    ASSERT_EQ(transmit(&a), SC_SUCCESS);
    EXPECT_EQ(bridge.reader.max_send_size, static_cast<size_t>(SC_READER_SHORT_APDU_MAX_SEND_SIZE));
    EXPECT_EQ(bridge.reader.max_recv_size, static_cast<size_t>(SC_READER_SHORT_APDU_MAX_RECV_SIZE));
}
