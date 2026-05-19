// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <LibreSCRS/CancelToken.h>
#include <LibreSCRS_internal/SecureChannel/PlainChannel.h>
#include <LibreSCRS/SmartCard/AppletAid.h>

#include "apdu.h"
#include "fake_pcsc_connection.h"

#include <gtest/gtest.h>

namespace {

using LibreSCRS::CancelSource;
using LibreSCRS::CancelToken;
using LibreSCRS::SecureChannel::ChannelState;
using LibreSCRS::SecureChannel::PlainChannel;
using LibreSCRS::SecureChannel::TestSupport::FakePCSCConnection;
using LibreSCRS::SmartCard::AppletAid;
using LibreSCRS::SmartCard::Internal::APDUCommand;
using LibreSCRS::SmartCard::Internal::APDUResponse;

AppletAid makeTestAid()
{
    // Representative AID (NAM eMRTD applet, RID + PIX).
    return AppletAid{0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01};
}

APDUCommand makeSelectMf()
{
    APDUCommand cmd;
    cmd.cla = 0x00;
    cmd.ins = 0xA4;
    cmd.p1 = 0x00;
    cmd.p2 = 0x0C;
    cmd.le = 0;
    cmd.hasLe = false;
    return cmd;
}

APDUResponse makeOkResponse()
{
    APDUResponse r;
    r.sw1 = 0x90;
    r.sw2 = 0x00;
    return r;
}

} // namespace

TEST(PlainChannelTests, ForwardsApduToConnectionUnchanged)
{
    auto aid = makeTestAid();
    FakePCSCConnection fakeConn;
    fakeConn.setResponder([](const auto&) { return makeOkResponse(); });

    PlainChannel channel(fakeConn, aid);

    auto cmd = makeSelectMf();
    auto response = channel.transmit(cmd, CancelToken{});

    ASSERT_EQ(fakeConn.history().size(), 1u);
    EXPECT_EQ(fakeConn.history()[0].toBytes(), cmd.toBytes());
    EXPECT_EQ(response.statusWord(), 0x9000);
}

TEST(PlainChannelTests, ReportsAppletAidAndOpenStateAtConstruction)
{
    auto aid = makeTestAid();
    FakePCSCConnection fakeConn;
    PlainChannel channel(fakeConn, aid);

    EXPECT_EQ(channel.currentApplet(), aid);
    EXPECT_EQ(channel.state(), ChannelState::Open);
}

TEST(PlainChannelTests, CloseTransitionsToClosedAndSuppressesTransmit)
{
    auto aid = makeTestAid();
    FakePCSCConnection fakeConn;
    PlainChannel channel(fakeConn, aid);

    channel.close();
    EXPECT_EQ(channel.state(), ChannelState::Closed);

    auto response = channel.transmit(makeSelectMf(), CancelToken{});
    EXPECT_TRUE(fakeConn.history().empty());
    EXPECT_EQ(response.statusWord(), 0x6F00); // sentinel for closed
}

TEST(PlainChannelTests, CloseIsIdempotent)
{
    auto aid = makeTestAid();
    FakePCSCConnection fakeConn;
    PlainChannel channel(fakeConn, aid);

    channel.close();
    channel.close();
    channel.close();

    EXPECT_EQ(channel.state(), ChannelState::Closed);
    EXPECT_TRUE(fakeConn.history().empty());
}

TEST(PlainChannelTests, RespectsCancelToken)
{
    auto aid = makeTestAid();
    FakePCSCConnection fakeConn;
    PlainChannel channel(fakeConn, aid);

    CancelSource source;
    auto token = source.token();
    source.requestCancel();

    auto response = channel.transmit(makeSelectMf(), token);
    EXPECT_TRUE(fakeConn.history().empty());
    EXPECT_EQ(response.statusWord(), 0x6F01); // sentinel for cancelled
}

TEST(PlainChannelTests, DefaultCancelTokenDoesNotInterfere)
{
    // Default-constructed CancelToken is never-cancellable; transmit
    // must reach the connection.
    auto aid = makeTestAid();
    FakePCSCConnection fakeConn;
    fakeConn.setResponder([](const auto&) { return makeOkResponse(); });
    PlainChannel channel(fakeConn, aid);

    auto response = channel.transmit(makeSelectMf(), CancelToken{});
    EXPECT_EQ(fakeConn.history().size(), 1u);
    EXPECT_EQ(response.statusWord(), 0x9000);
}
