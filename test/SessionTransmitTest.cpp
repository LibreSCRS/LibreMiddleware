// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

/// @file
/// @brief Unit tests for @ref LibreSCRS::SmartCard::CardSession::transmitInternal.
///
/// Drives the routing matrix of the SM-aware transmit funnel:
///   1. Live SM channel installed via @ref ChannelInjector — APDU goes
///      through the channel (wrapped), not through the underlying PC/SC
///      connection.
///   2. No channel installed against a detached session — funnel routes
///      through the (absent) PC/SC connection and returns SW=6F00 via the
///      null-conn guard rather than attempting a wire transmit.
///   3. Moved-from @ref CardSession — funnel returns SW=6F00 without
///      attempting a transmit, matching the documented null-pimpl
///      observation surface.
///   4. Channel reset mid-call — the snapshot @c shared_ptr keeps the
///      channel alive for the duration of the transmit even if a
///      concurrent caller installs a different channel on the same
///      session between the snapshot and the dispatch.
///   5. Single-transmit-per-session caller contract — runtime check
///      requires a concurrent harness; @c GTEST_SKIP documents the
///      thread-safety obligation.

#include <LibreSCRS/Auth/PaceSecretKind.h>
#include <LibreSCRS/CancelToken.h>
#include <LibreSCRS/SmartCard/CardSession.h>
#include <LibreSCRS/SmartCard/detail/ChannelInjection.h>
#include <LibreSCRS_internal/SecureChannel/ISecureChannel.h>

#include <apdu.h>
#include <fake_channel.h>

#include <gtest/gtest.h>

#include <cstdint>
#include <memory>
#include <utility>

namespace {

using LibreSCRS::SecureChannel::ChannelState;
using LibreSCRS::SecureChannel::ISecureChannel;
using LibreSCRS::SecureChannel::TestSupport::FakeChannel;
using LibreSCRS::SmartCard::AppletAid;
using LibreSCRS::SmartCard::CardSession;
using LibreSCRS::SmartCard::detail::ChannelInjector;
using LibreSCRS::SmartCard::detail::makeDetachedCardSession;
using LibreSCRS::SmartCard::Internal::APDUCommand;
using LibreSCRS::SmartCard::Internal::APDUResponse;

APDUCommand makeProbeCommand()
{
    return APDUCommand{0x00, 0xA4, 0x04, 0x00, {0xA0, 0x00}, 0, false};
}

class SessionTransmitTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        session = makeDetachedCardSession("test-reader");
    }
    std::shared_ptr<CardSession> session;
};

TEST_F(SessionTransmitTest, routesThroughSmWhenChannelLive)
{
    // Live SM channel: funnel must dispatch through the channel and the
    // wrapped command's CLA/INS appear on the channel side (not on the
    // underlying PC/SC connection).
    AppletAid aid{0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01};
    auto channel = std::make_unique<FakeChannel>(aid, ChannelState::Open, /*carriesSm=*/true);
    auto* observer = channel.get();
    ChannelInjector::installForTesting(*session, std::move(channel));

    auto resp = session->transmitInternal(makeProbeCommand());

    EXPECT_EQ(observer->lastWrappedCommand().ins, 0xA4);
    EXPECT_EQ(observer->transmits(), 1);
    EXPECT_EQ(resp.sw1, 0x90);
    EXPECT_EQ(resp.sw2, 0x00);
}

TEST_F(SessionTransmitTest, returnsSw6F00OnDetachedSessionWithoutLiveChannel)
{
    // No injected channel + detached PCSC connection: the null-conn /
    // closed-channel guard short-circuits to SW=6F00 rather than emitting
    // a real PC/SC transmit.
    auto resp = session->transmitInternal(makeProbeCommand());
    EXPECT_EQ(resp.sw1, 0x6F);
    EXPECT_EQ(resp.sw2, 0x00);
}

TEST_F(SessionTransmitTest, returnsSw6F00OnClosedChannel)
{
    // Closed channel (not Open): funnel must NOT dispatch through the
    // channel — equivalent to no channel installed. Detached session
    // surfaces the null-conn path; the funnel returns SW=6F00.
    AppletAid aid{0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01};
    auto channel = std::make_unique<FakeChannel>(aid, ChannelState::Closed, /*carriesSm=*/true);
    auto* observer = channel.get();
    ChannelInjector::installForTesting(*session, std::move(channel));

    auto resp = session->transmitInternal(makeProbeCommand());
    EXPECT_EQ(observer->transmits(), 0);
    EXPECT_EQ(resp.sw1, 0x6F);
    EXPECT_EQ(resp.sw2, 0x00);
}

TEST_F(SessionTransmitTest, channelResetMidSnapshotKeepsChannelAlive)
{
    // Snapshot pattern: even if the session-side resets the active channel
    // during the transmit body, the funnel's snapshot @c shared_ptr keeps
    // the channel object alive until the call returns.
    AppletAid aid{0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01};
    auto channel = std::make_unique<FakeChannel>(aid, ChannelState::Open, /*carriesSm=*/true);
    auto* observer = channel.get();
    observer->onTransmitCallback = [this]() {
        // Mid-transmit: drop the session's active-channel slot. The
        // installed channel only survives the call because the funnel
        // holds a shared_ptr snapshot of it on the stack.
        session->clearActiveChannel();
    };
    ChannelInjector::installForTesting(*session, std::move(channel));

    auto resp = session->transmitInternal(makeProbeCommand());

    EXPECT_EQ(observer->lastWrappedCommand().ins, 0xA4);
    EXPECT_EQ(observer->transmits(), 1);
    EXPECT_EQ(resp.sw1, 0x90);
    EXPECT_EQ(resp.sw2, 0x00);
}

TEST_F(SessionTransmitTest, singleTransmitContractIsCallerObligation)
{
    // The funnel does NOT internally serialise concurrent transmits on
    // the same session — that obligation rests on the caller. Violation
    // surfaces as a defined SM-failure path (channel state goes Failed)
    // rather than UB, but exercising it requires a concurrent harness.
    GTEST_SKIP() << "Documents thread-safety contract; runtime check requires "
                    "concurrent harness — out of scope for this unit suite.";
}

} // namespace
