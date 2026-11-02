// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

/// @file
/// @brief Behavioural tests for PaceChannel and BacChannel. The tests
///        do not exercise full PACE/BAC handshakes (those require BSI
///        TR-03110 / ICAO Doc 9303 test vectors, deferred to a session
///        with the canonical documents). They do verify:
///
///        - Channel construction with provided session keys succeeds.
///        - Default state is Open.
///        - Closing the channel zeroises keys and transitions to Closed;
///          transmit returns the 6F00 sentinel without touching the wire.
///        - CancelToken is honoured (6F01 sentinel, no transmit).
///        - SW 6987 and SW 6988 from the card transition the channel to
///          Failed and surface the raw status word to the caller.
///        - A MAC-failure path (malformed response) transitions to Failed
///          and returns SW 6988.

#include <LibreSCRS/CancelToken.h>
#include <LibreSCRS/Secure/Buffer.h>
#include <LibreSCRS_internal/SecureChannel/BacChannel.h>
#include <LibreSCRS_internal/SecureChannel/PaceChannel.h>
#include <LibreSCRS_internal/SecureChannel/SessionKeys.h>
#include <LibreSCRS_internal/SecureChannel/detail/ChannelStateMutator.h>
#include <LibreSCRS/SmartCard/AppletAid.h>

#include "apdu.h"
#include "fake_pcsc_connection.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <ios>
#include <vector>

namespace {

using LibreSCRS::CancelSource;
using LibreSCRS::CancelToken;
using LibreSCRS::SecureChannel::BacChannel;
using LibreSCRS::SecureChannel::ChannelState;
using LibreSCRS::SecureChannel::PaceChannel;
using LibreSCRS::SecureChannel::SessionKeys;
using LibreSCRS::SecureChannel::SmCipher;
using LibreSCRS::SecureChannel::TestSupport::FakePCSCConnection;
using LibreSCRS::SmartCard::AppletAid;
using LibreSCRS::SmartCard::Internal::APDUCommand;
using LibreSCRS::SmartCard::Internal::APDUResponse;

AppletAid makeNamEmrtdAid()
{
    return AppletAid{0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01};
}

SessionKeys makeFakeAesKeys()
{
    SessionKeys k;
    k.encKey = LibreSCRS::Secure::Buffer{std::vector<std::uint8_t>(16, 0x11)};
    k.macKey = LibreSCRS::Secure::Buffer{std::vector<std::uint8_t>(16, 0x22)};
    k.ssc = LibreSCRS::Secure::Buffer{std::vector<std::uint8_t>(16, 0x00)};
    k.cipher = SmCipher::Aes;
    return k;
}

SessionKeys makeFakeDes3Keys()
{
    SessionKeys k;
    k.encKey = LibreSCRS::Secure::Buffer{std::vector<std::uint8_t>(16, 0x33)};
    k.macKey = LibreSCRS::Secure::Buffer{std::vector<std::uint8_t>(16, 0x44)};
    k.ssc = LibreSCRS::Secure::Buffer{std::vector<std::uint8_t>(8, 0x00)};
    k.cipher = SmCipher::Des3;
    return k;
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

APDUResponse makeRaw(std::uint8_t sw1, std::uint8_t sw2)
{
    APDUResponse r;
    r.sw1 = sw1;
    r.sw2 = sw2;
    return r;
}

} // namespace

TEST(PaceChannelTests, ReportsAppletAidAndOpenStateAtConstruction)
{
    FakePCSCConnection fakeConn;
    PaceChannel channel(fakeConn, makeNamEmrtdAid(), makeFakeAesKeys());
    EXPECT_EQ(channel.currentApplet(), makeNamEmrtdAid());
    EXPECT_EQ(channel.state(), ChannelState::Open);
}

TEST(PaceChannelTests, CloseTransitionsToClosedAndSuppressesTransmit)
{
    FakePCSCConnection fakeConn;
    PaceChannel channel(fakeConn, makeNamEmrtdAid(), makeFakeAesKeys());
    channel.close();
    EXPECT_EQ(channel.state(), ChannelState::Closed);
    auto resp = channel.transmit(makeSelectMf(), CancelToken{});
    EXPECT_TRUE(fakeConn.history().empty());
    EXPECT_EQ(resp.statusWord(), 0x6F00);
}

TEST(PaceChannelTests, CloseIsIdempotent)
{
    FakePCSCConnection fakeConn;
    PaceChannel channel(fakeConn, makeNamEmrtdAid(), makeFakeAesKeys());
    channel.close();
    channel.close();
    EXPECT_EQ(channel.state(), ChannelState::Closed);
}

TEST(PaceChannelTests, CancelTokenHonoured)
{
    FakePCSCConnection fakeConn;
    PaceChannel channel(fakeConn, makeNamEmrtdAid(), makeFakeAesKeys());
    CancelSource src;
    auto token = src.token();
    src.requestCancel();
    auto resp = channel.transmit(makeSelectMf(), token);
    EXPECT_TRUE(fakeConn.history().empty());
    EXPECT_EQ(resp.statusWord(), 0x6F01);
}

TEST(PaceChannelTests, Sw6987FromCardTransitionsToFailed)
{
    FakePCSCConnection fakeConn;
    fakeConn.setResponder([](const auto&) { return makeRaw(0x69, 0x87); });
    PaceChannel channel(fakeConn, makeNamEmrtdAid(), makeFakeAesKeys());

    auto resp = channel.transmit(makeSelectMf(), CancelToken{});
    EXPECT_EQ(resp.statusWord(), 0x6987);
    EXPECT_EQ(channel.state(), ChannelState::Failed);
}

TEST(PaceChannelTests, Sw6988FromCardTransitionsToFailed)
{
    FakePCSCConnection fakeConn;
    fakeConn.setResponder([](const auto&) { return makeRaw(0x69, 0x88); });
    PaceChannel channel(fakeConn, makeNamEmrtdAid(), makeFakeAesKeys());

    auto resp = channel.transmit(makeSelectMf(), CancelToken{});
    EXPECT_EQ(resp.statusWord(), 0x6988);
    EXPECT_EQ(channel.state(), ChannelState::Failed);
}

TEST(PaceChannelTests, MalformedResponseTransitionsToFailed)
{
    // Card replies SW 9000 with no SM TLVs — MAC unwrap will fail.
    FakePCSCConnection fakeConn;
    fakeConn.setResponder([](const auto&) { return makeRaw(0x90, 0x00); });
    PaceChannel channel(fakeConn, makeNamEmrtdAid(), makeFakeAesKeys());

    auto resp = channel.transmit(makeSelectMf(), CancelToken{});
    EXPECT_EQ(channel.state(), ChannelState::Failed);
    EXPECT_EQ(resp.statusWord(), 0x6988);
}

TEST(PaceChannelTests, Sw6883ChainingResponseTransitionsToFailed)
{
    // ISO 7816-4 SW 6883 ("last command of the chain expected") is not one
    // of the two SM-invalidation status words short-circuited before MAC
    // unwrap (6987/6988), so a bare 6883 with no SM TLVs is treated like any
    // other unprotected reply: MAC unwrap fails and the channel maps it to
    // the same 6988 sentinel as MalformedResponseTransitionsToFailed, not
    // to the raw 6883 the card sent.
    FakePCSCConnection fakeConn;
    fakeConn.setResponder([](const auto&) { return makeRaw(0x68, 0x83); });
    PaceChannel channel(fakeConn, makeNamEmrtdAid(), makeFakeAesKeys());

    auto resp = channel.transmit(makeSelectMf(), CancelToken{});
    EXPECT_EQ(channel.state(), ChannelState::Failed);
    EXPECT_EQ(resp.statusWord(), 0x6988);
}

TEST(PaceChannelTests, TransmitAfterFailedReturnsFailedSentinel)
{
    FakePCSCConnection fakeConn;
    fakeConn.setResponder([](const auto&) { return makeRaw(0x69, 0x87); });
    PaceChannel channel(fakeConn, makeNamEmrtdAid(), makeFakeAesKeys());
    (void)channel.transmit(makeSelectMf(), CancelToken{});
    ASSERT_EQ(channel.state(), ChannelState::Failed);

    fakeConn.clearHistory();
    auto resp = channel.transmit(makeSelectMf(), CancelToken{});
    EXPECT_TRUE(fakeConn.history().empty());
    EXPECT_EQ(resp.statusWord(), 0x6F02);
}

TEST(BacChannelTests, ReportsAppletAidAndOpenStateAtConstruction)
{
    FakePCSCConnection fakeConn;
    BacChannel channel(fakeConn, makeNamEmrtdAid(), makeFakeDes3Keys());
    EXPECT_EQ(channel.currentApplet(), makeNamEmrtdAid());
    EXPECT_EQ(channel.state(), ChannelState::Open);
}

TEST(BacChannelTests, CloseTransitionsToClosed)
{
    FakePCSCConnection fakeConn;
    BacChannel channel(fakeConn, makeNamEmrtdAid(), makeFakeDes3Keys());
    channel.close();
    EXPECT_EQ(channel.state(), ChannelState::Closed);
    auto resp = channel.transmit(makeSelectMf(), CancelToken{});
    EXPECT_TRUE(fakeConn.history().empty());
    EXPECT_EQ(resp.statusWord(), 0x6F00);
}

TEST(BacChannelTests, Sw6988TransitionsToFailed)
{
    FakePCSCConnection fakeConn;
    fakeConn.setResponder([](const auto&) { return makeRaw(0x69, 0x88); });
    BacChannel channel(fakeConn, makeNamEmrtdAid(), makeFakeDes3Keys());
    auto resp = channel.transmit(makeSelectMf(), CancelToken{});
    EXPECT_EQ(resp.statusWord(), 0x6988);
    EXPECT_EQ(channel.state(), ChannelState::Failed);
}

// -----------------------------------------------------------------------------
// PaceChannel::establish / BacChannel::establish — error-mapping tests.
//
// These do not validate handshake correctness against canonical BSI TR-03110
// / ICAO Doc 9303 vectors; they validate the wrapper's responsibility:
// translating emrtd-crypto failure modes (and pre-handshake validation) into
// the ChannelActivationError taxonomy. Real-card matrix validation is a
// separate effort.
// -----------------------------------------------------------------------------

namespace {

LibreSCRS::SecureChannel::PaceParams canParams()
{
    LibreSCRS::SecureChannel::PaceParams params;
    params.oid = "0.4.0.127.0.7.2.2.4.2.4";
    params.passwordType = LibreSCRS::Auth::PaceSecretKind::Can;
    params.password = LibreSCRS::Secure::String{"123456"};
    params.paramId = LibreSCRS::SecureChannel::PaceStandardisedDomainParam::BrainpoolP256r1;
    return params;
}

// The card answers MSE:Set AT with @p mseSw and General Authenticate with
// @p gaSw.
FakePCSCConnection::ResponseFn paceCard(std::uint16_t mseSw, std::uint16_t gaSw)
{
    return [mseSw, gaSw](const LibreSCRS::SmartCard::Internal::APDUCommand& cmd) {
        const auto sw = cmd.ins == 0x22 ? mseSw : gaSw;
        return LibreSCRS::SmartCard::Internal::APDUResponse{
            {}, static_cast<std::uint8_t>(sw >> 8), static_cast<std::uint8_t>(sw & 0xFF)};
    };
}

} // namespace

// MSE:Set AT carries the OID and the password type, nothing derived from the
// secret: a card refusing it does not support this OID, and the caller may try
// another one.
TEST(PaceEstablishTests, CardRefusingMseSetAtIsAnUnsupportedOid)
{
    using LibreSCRS::SecureChannel::ChannelActivationError;

    FakePCSCConnection fakeConn;
    fakeConn.setResponder(paceCard(0x6A80, 0x9000));

    auto outcome = PaceChannel::establish(fakeConn, canParams(), CancelToken{});
    ASSERT_FALSE(outcome.has_value());
    EXPECT_EQ(outcome.error(), ChannelActivationError::PaceUnsupported);
    ASSERT_EQ(fakeConn.history().size(), 1u);
    EXPECT_EQ(fakeConn.history()[0].ins, 0x22);
    EXPECT_EQ(fakeConn.history()[0].p1, 0xC1);
    EXPECT_EQ(fakeConn.history()[0].p2, 0xA4);
}

// A card may report on the password itself at MSE:Set AT (tries left,
// blocked): that is about the secret, not the OID.
TEST(PaceEstablishTests, CardReportingThePasswordAtMseSetAtIsAWrongSecret)
{
    using LibreSCRS::SecureChannel::ChannelActivationError;

    for (const std::uint16_t sw : {std::uint16_t{0x63C2}, std::uint16_t{0x6983}, std::uint16_t{0x6984}}) {
        FakePCSCConnection fakeConn;
        fakeConn.setResponder(paceCard(sw, 0x9000));

        auto outcome = PaceChannel::establish(fakeConn, canParams(), CancelToken{});
        ASSERT_FALSE(outcome.has_value());
        EXPECT_EQ(outcome.error(), ChannelActivationError::PaceWrongSecret) << std::hex << sw;
        EXPECT_EQ(fakeConn.history().size(), 1u) << std::hex << sw;
    }
}

// Once the card took the OID, a refused General Authenticate is a failed
// attempt with this secret.
TEST(PaceEstablishTests, CardRefusingGeneralAuthenticateIsAWrongSecret)
{
    using LibreSCRS::SecureChannel::ChannelActivationError;

    FakePCSCConnection fakeConn;
    fakeConn.setResponder(paceCard(0x9000, 0x63C2));

    auto outcome = PaceChannel::establish(fakeConn, canParams(), CancelToken{});
    ASSERT_FALSE(outcome.has_value());
    EXPECT_EQ(outcome.error(), ChannelActivationError::PaceWrongSecret);
    ASSERT_EQ(fakeConn.history().size(), 2u);
    EXPECT_EQ(fakeConn.history()[1].ins, 0x86);
}

TEST(PaceEstablishTests, AlreadyCancelledTokenSkipsHandshake)
{
    using LibreSCRS::Auth::PaceSecretKind;
    using LibreSCRS::SecureChannel::ChannelActivationError;
    using LibreSCRS::SecureChannel::PaceParams;

    FakePCSCConnection fakeConn;
    PaceParams params;
    params.oid = "0.4.0.127.0.7.2.2.4.2.4";
    params.passwordType = PaceSecretKind::Can;
    params.password = LibreSCRS::Secure::String{"123456"};

    CancelSource src;
    auto token = src.token();
    src.requestCancel();

    auto outcome = PaceChannel::establish(fakeConn, params, token);
    ASSERT_FALSE(outcome.has_value());
    EXPECT_EQ(outcome.error(), ChannelActivationError::Cancelled);
    EXPECT_TRUE(fakeConn.history().empty());
}

TEST(PaceChannelTests, SetCurrentAppletUpdatesReportedAid)
{
    // Channels emerge from establish() with an empty currentApplet because
    // PACE binds session keys at MF, not to any particular applet. The
    // wrapped-SELECT applet-switch path updates the tracked AID through
    // setCurrentApplet.
    FakePCSCConnection fakeConn;
    PaceChannel channel(fakeConn, AppletAid{}, makeFakeAesKeys());
    EXPECT_TRUE(channel.currentApplet().empty());

    using LibreSCRS::SecureChannel::detail::ChannelStateMutator;
    ChannelStateMutator::setCurrentApplet(channel, makeNamEmrtdAid());
    EXPECT_EQ(channel.currentApplet(), makeNamEmrtdAid());

    AppletAid otherAid{0xA0, 0x00, 0x00, 0x00, 0x63, 0x50, 0x4B, 0x43, 0x53, 0x2D, 0x31, 0x35};
    ChannelStateMutator::setCurrentApplet(channel, otherAid);
    EXPECT_EQ(channel.currentApplet(), otherAid);
}

TEST(BacEstablishTests, CardRefusingGetChallengeIsAWrongSecret)
{
    using LibreSCRS::SecureChannel::BacInput;
    using LibreSCRS::SecureChannel::ChannelActivationError;

    FakePCSCConnection fakeConn;
    BacInput input;
    input.documentNumber = LibreSCRS::Secure::String{"L898902C"};
    input.dateOfBirth = LibreSCRS::Secure::String{"690806"};
    input.dateOfExpiry = LibreSCRS::Secure::String{"940623"};

    fakeConn.setResponder([](const LibreSCRS::SmartCard::Internal::APDUCommand&) {
        return LibreSCRS::SmartCard::Internal::APDUResponse{{}, 0x6A, 0x80};
    });

    auto outcome = BacChannel::establish(fakeConn, makeNamEmrtdAid(), input, CancelToken{});
    ASSERT_FALSE(outcome.has_value());
    EXPECT_EQ(outcome.error(), ChannelActivationError::PaceWrongSecret);
    ASSERT_EQ(fakeConn.history().size(), 1u);
    EXPECT_EQ(fakeConn.history()[0].ins, 0x84);
}

TEST(BacEstablishTests, AlreadyCancelledTokenSkipsHandshake)
{
    using LibreSCRS::SecureChannel::BacInput;
    using LibreSCRS::SecureChannel::ChannelActivationError;

    FakePCSCConnection fakeConn;
    BacInput input;
    input.documentNumber = LibreSCRS::Secure::String{"L898902C"};
    input.dateOfBirth = LibreSCRS::Secure::String{"690806"};
    input.dateOfExpiry = LibreSCRS::Secure::String{"940623"};

    CancelSource src;
    auto token = src.token();
    src.requestCancel();

    auto outcome = BacChannel::establish(fakeConn, makeNamEmrtdAid(), input, token);
    ASSERT_FALSE(outcome.has_value());
    EXPECT_EQ(outcome.error(), ChannelActivationError::Cancelled);
    EXPECT_TRUE(fakeConn.history().empty());
}

TEST(SecureChannelParsePaceOids, EmptyInputYieldsEmptyList)
{
    auto pairs = LibreSCRS::SecureChannel::parsePaceOidsFromCardAccess({});
    EXPECT_TRUE(pairs.empty());
}
