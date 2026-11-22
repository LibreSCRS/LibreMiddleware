// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

/// @file
/// @brief Unit tests for @ref LibreSCRS::SmartCard::CardSession::transmit.
///
/// Drives the routing matrix of the SM-aware transmit funnel:
///   1. Live SM channel installed via @ref ChannelInjector — APDU goes
///      through the channel (wrapped), not through the underlying PC/SC
///      connection.
///   2. No channel installed against a detached session — funnel routes
///      through the (absent) PC/SC connection and returns a TransportError
///      rather than attempting a wire transmit.
///   3. Moved-from @ref CardSession — funnel returns a TransportError without
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
#include <session_access.h>
#include <smartcard/session_connection.h>
#include <LibreSCRS/SmartCard/testing/CardSessionTesting.h>
#include <LibreSCRS_internal/SecureChannel/ISecureChannel.h>

#include <apdu.h>
#include <fake_channel.h>
#include <pcsc_connection.h>

#include <gtest/gtest.h>

#include <expected>
#include <span>
#include <thread>
#include <vector>
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
using LibreSCRS::SmartCard::Internal::APDUCommand;
using LibreSCRS::SmartCard::Internal::APDUResponse;
using LibreSCRS::SmartCard::Testing::makeDetachedCardSession;

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

    auto resp = LibreSCRS::SmartCard::SessionConnection::toResponse(session->transmit(makeProbeCommand().toBytes()));
    ASSERT_TRUE(resp);

    EXPECT_EQ(observer->lastWrappedCommand().ins, 0xA4);
    EXPECT_EQ(observer->transmits(), 1);
    EXPECT_EQ(resp->sw1, 0x90);
    EXPECT_EQ(resp->sw2, 0x00);
}

// A secure-messaging channel that is no longer open -- closed by a reset,
// failed on a bad MAC -- is never bypassed by the operation running over it:
// that operation meant its commands to be protected. The funnel answers the
// channel-unusable error and sends nothing.
TEST_F(SessionTransmitTest, smChannelThatIsNotOpenIsNeverBypassed)
{
    AppletAid aid{0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01};
    for (const auto state : {ChannelState::Closed, ChannelState::Failed}) {
        // An operation runs over the channel: this thread holds the holder,
        // taken while the channel was open, and the channel dies under it.
        const LibreSCRS::SmartCard::SmProtocolRequest pace = LibreSCRS::SmartCard::PaceRequest{};
        auto channel = std::make_unique<FakeChannel>(aid, ChannelState::Open, /*carriesSm=*/true);
        auto* observer = channel.get();
        ChannelInjector::installForTesting(*session, std::move(channel), pace);
        auto holder = session->activateChannelWithSm(aid, pace, LibreSCRS::CancelToken{});
        ASSERT_TRUE(holder.has_value());
        observer->setState(state);
        std::size_t wireCommands = 0;
        LibreSCRS::SmartCard::Internal::connectionOf(*session).setTransmitFilter([&](const APDUCommand&) {
            ++wireCommands;
            return APDUResponse{{}, 0x90, 0x00};
        });

        auto resp =
            LibreSCRS::SmartCard::SessionConnection::toResponse(session->transmit(makeProbeCommand().toBytes()));
        ASSERT_FALSE(resp);
        EXPECT_EQ(observer->transmits(), 0);
        EXPECT_EQ(wireCommands, 0U) << "no plain command reaches the card";
        EXPECT_EQ(resp.error().kind, LibreSCRS::SmartCard::TransportError::Kind::ChannelUnusable);
    }
}

// A plain channel that is not open refuses the command like any installed
// channel: it never falls back to the connection.
TEST_F(SessionTransmitTest, aPlainChannelThatIsNotOpenIsUnusable)
{
    AppletAid aid{0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01};
    auto channel = std::make_unique<FakeChannel>(aid, ChannelState::Closed, /*carriesSm=*/false);
    auto* observer = channel.get();
    ChannelInjector::installForTesting(*session, std::move(channel));
    std::size_t wireCommands = 0;
    LibreSCRS::SmartCard::Internal::connectionOf(*session).setTransmitFilter([&](const APDUCommand&) {
        ++wireCommands;
        return APDUResponse{{}, 0x6F, 0x00};
    });

    auto resp = LibreSCRS::SmartCard::SessionConnection::toResponse(session->transmit(makeProbeCommand().toBytes()));
    ASSERT_FALSE(resp);
    EXPECT_EQ(observer->transmits(), 0);
    EXPECT_EQ(wireCommands, 0U) << "nothing is sent";
    EXPECT_EQ(resp.error().kind, LibreSCRS::SmartCard::TransportError::Kind::ChannelUnusable);
}

// The token is checked before the first command on every path: with no
// channel, under a plain one and under secure messaging, a fired token is
// Cancelled and nothing reaches the channel or the wire.
TEST_F(SessionTransmitTest, aCancelledTokenSendsNothingOnEveryPath)
{
    AppletAid aid{0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01};
    LibreSCRS::CancelSource source;
    source.requestCancel();
    for (const auto path : {0, 1, 2}) {
        SCOPED_TRACE(path);
        FakeChannel* observer = nullptr;
        if (path != 0) {
            auto channel = std::make_unique<FakeChannel>(aid, ChannelState::Open, /*carriesSm=*/path == 2);
            observer = channel.get();
            ChannelInjector::installForTesting(*session, std::move(channel));
        }
        std::size_t wireCommands = 0;
        LibreSCRS::SmartCard::Internal::connectionOf(*session).setTransmitFilter([&](const APDUCommand&) {
            ++wireCommands;
            return APDUResponse{{}, 0x90, 0x00};
        });

        auto resp = session->transmit(makeProbeCommand().toBytes(), source.token());
        ASSERT_FALSE(resp);
        EXPECT_EQ(resp.error().kind, LibreSCRS::SmartCard::TransportError::Kind::Cancelled);
        EXPECT_EQ(wireCommands, 0U);
        if (observer != nullptr) {
            EXPECT_EQ(observer->transmits(), 0);
        }
        session->clearActiveChannel();
    }
}

TEST_F(SessionTransmitTest, channelResetMidSnapshotKeepsChannelAlive)
{
    // A teardown on another thread while a command is on the wire waits for
    // the command: a caller that does not hold the holder sends under the
    // session lock, so the channel cannot be pulled out from under the
    // exchange. Judged by the lock itself, not by timing.
    AppletAid aid{0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01};
    auto channel = std::make_unique<FakeChannel>(aid, ChannelState::Open, /*carriesSm=*/true);
    auto* observer = channel.get();
    std::uint8_t observedIns = 0;
    bool lockedOnTheWire = false;
    std::thread teardown;
    observer->onTransmitCallback = [&, this]() {
        observedIns = observer->lastWrappedCommand().ins;
        lockedOnTheWire = LibreSCRS::SmartCard::Testing::SessionAccess::lockIsHeld(*session);
        teardown = std::thread([this] { session->clearActiveChannel(); });
    };
    ChannelInjector::installForTesting(*session, std::move(channel));

    auto resp = LibreSCRS::SmartCard::SessionConnection::toResponse(session->transmit(makeProbeCommand().toBytes()));
    ASSERT_TRUE(resp);
    teardown.join();

    EXPECT_EQ(observedIns, 0xA4);
    EXPECT_TRUE(lockedOnTheWire) << "the command went out without the session lock";
    EXPECT_FALSE(session->channelState().has_value()) << "the teardown ran after the command";
    EXPECT_EQ(resp->sw1, 0x90);
    EXPECT_EQ(resp->sw2, 0x00);
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

// A command the byte interface does not accept is an InvalidCommand error and
// nothing reaches the wire.
TEST_F(SessionTransmitTest, AMalformedApduIsInvalidCommandAndSendsNothing)
{
    std::size_t wireCommands = 0;
    LibreSCRS::SmartCard::Internal::connectionOf(*session).setDetachedRawResponder([&](std::span<const std::uint8_t>) {
        ++wireCommands;
        return APDUResponse{{}, 0x90, 0x00};
    });
    const std::vector<std::uint8_t> malformed{0x00, 0xA4, 0x04};

    const auto r = session->transmit(malformed);

    ASSERT_FALSE(r);
    EXPECT_EQ(r.error().kind, LibreSCRS::SmartCard::TransportError::Kind::InvalidCommand);
    EXPECT_EQ(wireCommands, 0U);
}

// The reader's failure reaches the caller as the error it classified to.
TEST_F(SessionTransmitTest, AReaderFailureOnThePlainPathIsTheError)
{
    LibreSCRS::SmartCard::Internal::connectionOf(*session).setDetachedRawResponder(
        [](std::span<const std::uint8_t>) -> std::expected<APDUResponse, LibreSCRS::SmartCard::TransportError> {
            return std::unexpected(LibreSCRS::SmartCard::TransportError{
                LibreSCRS::SmartCard::TransportError::Kind::NoCardPresent, "card removed"});
        });

    const auto r = session->transmit(makeProbeCommand().toBytes());

    ASSERT_FALSE(r);
    EXPECT_EQ(r.error().kind, LibreSCRS::SmartCard::TransportError::Kind::NoCardPresent);
}
