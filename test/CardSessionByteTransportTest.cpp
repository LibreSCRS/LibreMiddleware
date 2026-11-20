// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

/// @file
/// @brief The byte-level transport of @ref LibreSCRS::SmartCard::CardSession:
///        @c transmit, @c transmitRaw, the transaction and reconnect calls, the
///        channel accessors and @c generation.
///
/// A detached session stands in for the card. Its connection counts the two
/// ways a command can reach the wire: the typed transmit (the plain path,
/// which completes a chained answer) and the raw single exchange. A fake
/// channel counts what the secure-messaging path carries.

#include <LibreSCRS/CancelToken.h>
#include <LibreSCRS/Plugin/SessionKey.h>
#include <LibreSCRS/SmartCard/CardSession.h>
#include <LibreSCRS/SmartCard/detail/ChannelInjection.h>
#include <LibreSCRS/SmartCard/testing/CardSessionTesting.h>

#include <apdu.h>
#include <fake_channel.h>
#include <pcsc_connection.h>
#include <session_access.h>
#include <smartcard/session_connection.h>
#include <LibreSCRS_internal/SecureChannel/SessionChannel.h>

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <span>
#include <stdexcept>
#include <thread>
#include <utility>
#include <vector>

namespace {

using LibreSCRS::SecureChannel::ChannelState;
using LibreSCRS::SecureChannel::TestSupport::FakeChannel;
using LibreSCRS::SmartCard::ActiveChannelHolder;
using LibreSCRS::SmartCard::AppletAid;
using LibreSCRS::SmartCard::CardSession;
using LibreSCRS::SmartCard::PaceRequest;
using LibreSCRS::SmartCard::SmProtocolRequest;
using LibreSCRS::SmartCard::detail::ChannelInjector;
using LibreSCRS::SmartCard::Internal::APDUCommand;
using LibreSCRS::SmartCard::Internal::APDUResponse;
using LibreSCRS::SmartCard::Testing::SessionAccess;
using Bytes = std::vector<std::uint8_t>;

const AppletAid kAid{0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01};

// SELECT by AID with an Le: a case 4 command.
const Bytes kSelect{0x00, 0xA4, 0x04, 0x00, 0x02, 0x3F, 0x00, 0x00};

// Aborts the process if the body does not finish in time: a call that took
// the session mutex on the thread holding the holder would hang forever.
class Watchdog
{
public:
    explicit Watchdog(std::chrono::milliseconds deadline)
    {
        thread = std::thread([this, deadline] {
            const auto start = std::chrono::steady_clock::now();
            while (!done.load(std::memory_order_acquire)) {
                if (std::chrono::steady_clock::now() - start > deadline) {
                    std::fputs("byte transport test watchdog tripped: a call deadlocked on the session mutex\n",
                               stderr);
                    std::abort();
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(25));
            }
        });
    }
    ~Watchdog()
    {
        done.store(true, std::memory_order_release);
        thread.join();
    }
    Watchdog(const Watchdog&) = delete;
    Watchdog& operator=(const Watchdog&) = delete;

private:
    std::atomic<bool> done{false};
    std::thread thread;
};

class CardSessionByteTransportTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        session = SessionAccess::detached("byte-transport-reader");
        auto& conn = LibreSCRS::SmartCard::Internal::connectionOf(*session);
        conn.setTransmitFilter([this](const APDUCommand& cmd) {
            plainCommands.push_back(cmd.toBytes());
            return plainAnswer;
        });
        conn.setDetachedRawResponder([this](std::span<const std::uint8_t> bytes) {
            rawCommands.emplace_back(bytes.begin(), bytes.end());
            return rawAnswer;
        });
    }

    FakeChannel* install(ChannelState state, bool carriesSm, std::optional<SmProtocolRequest> recorded = std::nullopt)
    {
        auto channel = std::make_unique<FakeChannel>(kAid, state, carriesSm);
        auto* observer = channel.get();
        ChannelInjector::installForTesting(*session, std::move(channel), std::move(recorded));
        return observer;
    }

    std::shared_ptr<CardSession> session;
    std::vector<Bytes> plainCommands;
    std::vector<Bytes> rawCommands;
    APDUResponse plainAnswer{{0x01, 0x02}, 0x90, 0x00};
    APDUResponse rawAnswer{{0x0A}, 0x90, 0x00};
};

TEST_F(CardSessionByteTransportTest, ACommandGoesThroughTheLiveTunnel)
{
    auto* channel = install(ChannelState::Open, /*carriesSm=*/true);
    channel->transmitHandler = [](const APDUCommand&) { return APDUResponse{{0xC0, 0xDE}, 0x90, 0x00}; };

    const auto answer = session->transmit(kSelect);

    EXPECT_EQ(answer, (Bytes{0xC0, 0xDE, 0x90, 0x00}));
    EXPECT_EQ(channel->transmits(), 1);
    EXPECT_EQ(channel->lastWrappedCommand().toBytes(), kSelect) << "the channel wraps the very command given";
    EXPECT_TRUE(plainCommands.empty());
    EXPECT_TRUE(rawCommands.empty());
}

TEST_F(CardSessionByteTransportTest, ACommandGoesPlainWhenNoTunnelIsLive)
{
    const auto answer = session->transmit(kSelect);

    EXPECT_EQ(answer, (Bytes{0x01, 0x02, 0x90, 0x00}));
    ASSERT_EQ(plainCommands.size(), 1U);
    EXPECT_EQ(plainCommands.front(), kSelect);
    EXPECT_TRUE(rawCommands.empty());
}

TEST_F(CardSessionByteTransportTest, AnOpenPlainChannelCarriesTheCommand)
{
    auto* channel = install(ChannelState::Open, /*carriesSm=*/false);

    (void)session->transmit(kSelect);

    EXPECT_EQ(channel->transmits(), 1);
    EXPECT_TRUE(plainCommands.empty());
}

TEST_F(CardSessionByteTransportTest, AClosedTunnelRefusesWithoutSending)
{
    // An operation runs over the tunnel -- this thread holds the session's
    // holder -- and the tunnel dies under it: its commands meant to be
    // protected are refused, never sent plain, raw or not.
    const SmProtocolRequest pace = PaceRequest{};
    for (const auto state : {ChannelState::Failed, ChannelState::Closed}) {
        plainCommands.clear();
        auto* channel = install(ChannelState::Open, /*carriesSm=*/true, pace);
        auto holder = session->activateChannelWithSm(kAid, pace, LibreSCRS::CancelToken{});
        ASSERT_TRUE(holder.has_value());
        channel->setState(state);

        EXPECT_EQ(session->transmit(kSelect), (Bytes{0x6F, 0x02}));
        EXPECT_EQ(session->transmitRaw(kSelect), (Bytes{0x6F, 0x02}));
        EXPECT_EQ(channel->transmits(), 0);
        EXPECT_TRUE(plainCommands.empty()) << "no plain command reaches the card";
        EXPECT_TRUE(rawCommands.empty());
        EXPECT_EQ(session->channelState(), state) << "the operation's channel stays installed";
    }
}

TEST_F(CardSessionByteTransportTest, ADeadTunnelNoOperationRunsOverIsDropped)
{
    // No holder: nothing runs over the dead tunnel, the card has ended its
    // secure-messaging session (or will on the next answer). Plain traffic
    // goes through again, and the dead channel is gone.
    for (const auto state : {ChannelState::Failed, ChannelState::Closed}) {
        plainCommands.clear();
        rawCommands.clear();
        auto* channel = install(state, /*carriesSm=*/true, SmProtocolRequest{PaceRequest{}});
        (void)channel;

        EXPECT_EQ(session->transmit(kSelect), (Bytes{0x01, 0x02, 0x90, 0x00}));
        EXPECT_EQ(plainCommands.size(), 1U);
        EXPECT_FALSE(session->channelState().has_value());
        EXPECT_FALSE(session->activatedProtocol().has_value());

        install(state, /*carriesSm=*/true);
        EXPECT_EQ(session->transmitRaw(kSelect), (Bytes{0x0A, 0x90, 0x00}));
        EXPECT_EQ(rawCommands.size(), 1U);
        EXPECT_FALSE(session->channelState().has_value());
    }
}

TEST_F(CardSessionByteTransportTest, APlainActivationReplacesAFailedTunnel)
{
    install(ChannelState::Failed, /*carriesSm=*/true, SmProtocolRequest{PaceRequest{}});

    auto holder = session->activateChannelFor(kAid, LibreSCRS::CancelToken{});

    ASSERT_TRUE(holder.has_value()) << "the dead tunnel must not refuse the plain SELECT";
    ASSERT_EQ(plainCommands.size(), 1U);
    EXPECT_EQ(plainCommands.front()[1], 0xA4) << "the SELECT went out plain";
    EXPECT_EQ(session->channelState(), ChannelState::Open);
    EXPECT_FALSE(session->carriesSecureMessaging());
}

TEST_F(CardSessionByteTransportTest, ACommandCollectsAChainedAnswer)
{
    // The plain path completes a 61xx answer with GET RESPONSE, as the reader
    // layer does for every typed command.
    LibreSCRS::SmartCard::Internal::connectionOf(*session).clearTransmitFilter();
    int exchanges = 0;
    LibreSCRS::SmartCard::Internal::connectionOf(*session).setDetachedRawResponder(
        [&](std::span<const std::uint8_t> bytes) {
            rawCommands.emplace_back(bytes.begin(), bytes.end());
            return ++exchanges == 1 ? APDUResponse{{0xAA}, 0x61, 0x01} : APDUResponse{{0xBB}, 0x90, 0x00};
        });

    const auto answer = session->transmit(kSelect);

    EXPECT_EQ(answer, (Bytes{0xAA, 0xBB, 0x90, 0x00}));
    ASSERT_EQ(rawCommands.size(), 2U);
    EXPECT_EQ(rawCommands[1], (Bytes{0x00, 0xC0, 0x00, 0x00, 0x01}));
}

TEST_F(CardSessionByteTransportTest, ASessionWithoutAConnectionAnswers6F00)
{
    SessionAccess::dropConnection(*session);

    EXPECT_EQ(session->transmit(kSelect), (Bytes{0x6F, 0x00}));
    EXPECT_EQ(session->transmitRaw(kSelect), (Bytes{0x6F, 0x00}));
}

TEST_F(CardSessionByteTransportTest, AFailingReaderThrows)
{
    // An unrigged detached connection has no card to reach: the reader error
    // surfaces, it is not turned into a status word the card never sent.
    auto bare = LibreSCRS::SmartCard::Testing::makeDetachedCardSession("bare-reader");

    EXPECT_THROW((void)bare->transmit(kSelect), std::runtime_error);
    EXPECT_THROW((void)bare->transmitRaw(kSelect), std::runtime_error);
}

TEST_F(CardSessionByteTransportTest, AMalformedCommandIsRejectedUnsent)
{
    const std::vector<Bytes> malformed{
        {0x00, 0xA4, 0x04},                         // shorter than a header
        {0x00, 0xA4, 0x04, 0x00, 0x05, 0x01},       // Lc 5, one data byte
        {0x00, 0xB0, 0x00, 0x00, 0x00, 0x00},       // 00 with one byte after it
        {0x00, 0xB0, 0x00, 0x00, 0x00, 0x00, 0x00}, // extended Le 65536: no command encodes to it
    };
    for (const auto& bytes : malformed) {
        EXPECT_THROW((void)session->transmit(bytes), std::invalid_argument);
    }
    EXPECT_TRUE(plainCommands.empty());
    EXPECT_TRUE(rawCommands.empty());
}

TEST_F(CardSessionByteTransportTest, ARawCommandUnderLiveSecureMessagingSendsNothing)
{
    auto* channel = install(ChannelState::Open, /*carriesSm=*/true);

    EXPECT_EQ(session->transmitRaw(kSelect), (Bytes{0x6F, 0x02}));
    EXPECT_TRUE(rawCommands.empty());
    EXPECT_TRUE(plainCommands.empty());
    EXPECT_EQ(channel->transmits(), 0);

    // The tunnel was not touched: the next command still rides it.
    EXPECT_EQ(channel->state(), ChannelState::Open);
    (void)session->transmit(kSelect);
    EXPECT_EQ(channel->transmits(), 1);
}

TEST_F(CardSessionByteTransportTest, ARawCommandGoesOutWhenNoTunnelIsLive)
{
    // No channel, an open plain channel, and a secure-messaging channel that
    // already failed: none is live, so the bytes go out unchanged, once.
    const Bytes unusual{0x80, 0xCA, 0x9F, 0x7F, 0x00};
    const auto send = [&] {
        rawCommands.clear();
        const auto answer = session->transmitRaw(unusual);
        EXPECT_EQ(answer, (Bytes{0x0A, 0x90, 0x00}));
        ASSERT_EQ(rawCommands.size(), 1U);
        EXPECT_EQ(rawCommands.front(), unusual);
    };
    send();
    install(ChannelState::Open, /*carriesSm=*/false);
    send();
    install(ChannelState::Failed, /*carriesSm=*/true);
    send();
    EXPECT_TRUE(plainCommands.empty());
}

TEST_F(CardSessionByteTransportTest, ARawCommandIsOneExchange)
{
    // A 61xx answer comes back as is: the caller does its own GET RESPONSE.
    rawAnswer = APDUResponse{{}, 0x61, 0x10};

    EXPECT_EQ(session->transmitRaw(kSelect), (Bytes{0x61, 0x10}));
    EXPECT_EQ(rawCommands.size(), 1U);
}

TEST_F(CardSessionByteTransportTest, GenerationMatchesTheSessionKey)
{
    const auto key = LibreSCRS::Plugin::makeSessionKey(*session);
    EXPECT_EQ(key.generation, session->generation());
    EXPECT_NE(session->generation(), 0U);

    auto other = SessionAccess::detached("byte-transport-reader");
    EXPECT_NE(other->generation(), session->generation()) << "a new session over the same reader is another";
}

TEST_F(CardSessionByteTransportTest, TheChannelStateIsTheInstalledChannels)
{
    EXPECT_FALSE(session->channelState().has_value());
    EXPECT_FALSE(session->carriesSecureMessaging());

    auto* tunnel = install(ChannelState::Open, /*carriesSm=*/true);
    EXPECT_EQ(session->channelState(), ChannelState::Open);
    EXPECT_TRUE(session->carriesSecureMessaging());

    tunnel->setState(ChannelState::Failed);
    EXPECT_EQ(session->channelState(), ChannelState::Failed);
    EXPECT_TRUE(session->carriesSecureMessaging()) << "a failed tunnel still carries secure messaging";
    EXPECT_FALSE(session->hasLiveSecureChannel());

    install(ChannelState::Open, /*carriesSm=*/false);
    EXPECT_EQ(session->channelState(), ChannelState::Open);
    EXPECT_FALSE(session->carriesSecureMessaging());
}

TEST_F(CardSessionByteTransportTest, TheSessionForgetsTheCurrentApplet)
{
    auto* channel = install(ChannelState::Open, /*carriesSm=*/true);
    ASSERT_EQ(channel->currentApplet(), kAid);

    session->forgetCurrentApplet();

    EXPECT_TRUE(channel->currentApplet().empty());
}

TEST_F(CardSessionByteTransportTest, ATransactionIsHeldUntilItEnds)
{
    EXPECT_FALSE(session->isTransactionHeld());
    session->beginTransaction();
    EXPECT_TRUE(session->isTransactionHeld());
    session->endTransaction();
    EXPECT_FALSE(session->isTransactionHeld());
    session->endTransaction(); // none held: nothing happens
    EXPECT_FALSE(session->isTransactionHeld());
}

TEST_F(CardSessionByteTransportTest, ARefusedTransactionIsNotHeld)
{
    LibreSCRS::SmartCard::Internal::connectionOf(*session).setDetachedTransactionFailure(
        0x8010000BL); // SCARD_E_SHARING_VIOLATION

    EXPECT_THROW(session->beginTransaction(), std::runtime_error);
    EXPECT_FALSE(session->isTransactionHeld());
}

TEST_F(CardSessionByteTransportTest, AReconnectWithoutACardThrows)
{
    EXPECT_THROW(session->reconnect(), std::runtime_error);
}

TEST_F(CardSessionByteTransportTest, TheHolderThreadReachesTheChannelWithoutDeadlock)
{
    Watchdog watchdog(std::chrono::seconds(5));
    const SmProtocolRequest pace = PaceRequest{};
    auto* channel = install(ChannelState::Open, /*carriesSm=*/true, pace);
    auto holder = session->activateChannelWithSm(kAid, pace, LibreSCRS::CancelToken{});
    ASSERT_TRUE(holder.has_value());

    // This thread holds the session mutex through the holder: every call below
    // must read the session without taking it again.
    (void)session->transmit(kSelect);
    EXPECT_EQ(channel->transmits(), 1);
    EXPECT_EQ(session->transmitRaw(kSelect), (Bytes{0x6F, 0x02}));
    EXPECT_EQ(session->channelState(), ChannelState::Open);
    EXPECT_TRUE(session->carriesSecureMessaging());
    EXPECT_TRUE(session->hasLiveSecureChannel());
    EXPECT_EQ(session->activatedProtocol(), pace);
    session->forgetCurrentApplet();
    EXPECT_TRUE(channel->currentApplet().empty());
}

TEST_F(CardSessionByteTransportTest, AnotherThreadWaitsForTheHolder)
{
    Watchdog watchdog(std::chrono::seconds(5));
    auto* channel = install(ChannelState::Open, /*carriesSm=*/true, SmProtocolRequest{PaceRequest{}});
    std::atomic<bool> sent{false};
    std::thread other;
    {
        auto holder = session->activateChannelWithSm(kAid, PaceRequest{}, LibreSCRS::CancelToken{});
        ASSERT_TRUE(holder.has_value());
        other = std::thread([&] {
            (void)session->transmit(kSelect);
            sent.store(true);
        });
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        EXPECT_FALSE(sent.load()) << "the other thread must not use the channel while the holder is held";
    }
    other.join();
    EXPECT_TRUE(sent.load());
    EXPECT_EQ(channel->transmits(), 1);
}

// Every command this library builds goes through the byte interface as the
// same bytes and as the same command: the parser is the exact inverse of
// APDUCommand::toBytes(), Le included.
TEST(ApduParseCommand, EveryEncodedCommandRoundTrips)
{
    using LibreSCRS::SmartCard::Internal::parseCommand;
    const std::vector<std::size_t> dataSizes{0, 1, 2, 254, 255, 256, 257, 1000};
    const std::vector<std::uint16_t> les{0, 1, 2, 0xFF, 0x100, 0x101, 0x1FF, 0x200, 0x1000, 0xFFFF};
    // Le 0 means "as much as there is": 256 in the short form, written as
    // 0100 in the extended one.
    const auto effectiveLe = [](const APDUCommand& c) { return c.le == 0 ? 256 : c.le; };
    int checked = 0;
    for (const auto size : dataSizes) {
        for (const bool hasLe : {false, true}) {
            for (const auto le : les) {
                if (!hasLe && le != 0) {
                    continue;
                }
                APDUCommand cmd{0x0C, 0xB0, 0x81, 0x7F, Bytes(size, 0x5A), le, hasLe};
                const auto bytes = cmd.toBytes();
                const auto parsed = parseCommand(bytes);
                ASSERT_TRUE(parsed.has_value()) << "size " << size << " le " << le << " hasLe " << hasLe;
                EXPECT_EQ(parsed->toBytes(), bytes);
                EXPECT_EQ(parsed->cla, cmd.cla);
                EXPECT_EQ(parsed->ins, cmd.ins);
                EXPECT_EQ(parsed->p1, cmd.p1);
                EXPECT_EQ(parsed->p2, cmd.p2);
                EXPECT_EQ(parsed->data, cmd.data);
                EXPECT_EQ(parsed->hasLe, cmd.hasLe);
                if (hasLe) {
                    EXPECT_EQ(effectiveLe(*parsed), effectiveLe(cmd)) << "size " << size << " le " << le;
                }
                ++checked;
            }
        }
    }
    EXPECT_GT(checked, 80);
}

// A data-less command expecting more than 256 bytes is case 2 extended:
// 00 marker, then the two Le bytes (ISO/IEC 7816-4, 5.1).
TEST(ApduParseCommand, ADataLessExtendedLeCarriesItsMarker)
{
    const APDUCommand read{0x00, 0xB0, 0x00, 0x00, {}, 0x0300, true};
    EXPECT_EQ(read.toBytes(), (Bytes{0x00, 0xB0, 0x00, 0x00, 0x00, 0x03, 0x00}));
}

// A command the byte interface cannot take is a failure of the call, which a
// card library catches as a std::runtime_error like any other: it must not
// leave the adapter as a logic error.
TEST_F(CardSessionByteTransportTest, AnUnencodableCommandFailsAsARuntimeError)
{
    // More data than an extended Lc can count: the serialization cannot
    // carry it, so the session refuses the bytes.
    const APDUCommand huge{0x00, 0xD6, 0x00, 0x00, Bytes(70000, 0x11), 0, false};
    LibreSCRS::SmartCard::SessionConnection conn(*session);
    EXPECT_THROW((void)conn.transmit(huge), std::runtime_error);
    LibreSCRS::SecureChannel::SessionChannel channel(*session);
    EXPECT_THROW((void)channel.transmit(huge, LibreSCRS::CancelToken{}), std::runtime_error);
    EXPECT_TRUE(plainCommands.empty());
    EXPECT_TRUE(rawCommands.empty());
}

} // namespace
