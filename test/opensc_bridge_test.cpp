// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <gtest/gtest.h>

#include <vector>

#include "opensc_reader_bridge.h"
#include <pcsc_connection.h>

using namespace LibreSCRS::OpenSc::Bridge;
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
