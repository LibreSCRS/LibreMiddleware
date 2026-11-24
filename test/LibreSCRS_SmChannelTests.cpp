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
///          transmit is ChannelUnusable without touching the wire.
///        - CancelToken is honoured (Cancelled, no transmit, state kept).
///        - SW 6987 and SW 6988 from the card transition the channel to
///          Failed and are the answer, as the card sent them.
///        - A MAC-failure path (malformed response) transitions to Failed
///          and is an IntegrityFailure.
///        - A reader error mid-exchange is returned and fails the channel.

#include <LibreSCRS/CancelToken.h>
#include <LibreSCRS/Secure/Buffer.h>
#include <LibreSCRS_internal/SecureChannel/BacChannel.h>
#include <LibreSCRS_internal/SecureChannel/PaceChannel.h>
#include <LibreSCRS_internal/SecureChannel/SessionKeys.h>
#include <LibreSCRS_internal/SecureChannel/detail/ChannelStateMutator.h>
#include <LibreSCRS/SmartCard/AppletAid.h>

#include "apdu.h"
#include "chip_auth_card_oracle.h"
#include "fake_pcsc_connection.h"
#include <LibreSCRS/Logging.h>
#include <smartcard/read_length_policy.h>

#include <gtest/gtest.h>

#include <cstdint>
#include <cstdlib>
#include <ios>
#include <memory>
#include <optional>
#include <string>
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
using LibreSCRS::SmartCard::TransportError;
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

TEST(PaceChannelTests, AClosedChannelIsUnusableAndSendsNothing)
{
    FakePCSCConnection fakeConn;
    PaceChannel channel(fakeConn, makeNamEmrtdAid(), makeFakeAesKeys());
    channel.close();
    EXPECT_EQ(channel.state(), ChannelState::Closed);
    auto resp = channel.transmit(makeSelectMf(), CancelToken{});
    EXPECT_TRUE(fakeConn.history().empty());
    ASSERT_FALSE(resp.has_value());
    EXPECT_EQ(resp.error().kind, TransportError::Kind::ChannelUnusable);
}

TEST(PaceChannelTests, CloseIsIdempotent)
{
    FakePCSCConnection fakeConn;
    PaceChannel channel(fakeConn, makeNamEmrtdAid(), makeFakeAesKeys());
    channel.close();
    channel.close();
    EXPECT_EQ(channel.state(), ChannelState::Closed);
}

TEST(PaceChannelTests, ACancelledTokenSendsNothingAndKeepsTheChannelOpen)
{
    FakePCSCConnection fakeConn;
    PaceChannel channel(fakeConn, makeNamEmrtdAid(), makeFakeAesKeys());
    CancelSource src;
    auto token = src.token();
    src.requestCancel();
    auto resp = channel.transmit(makeSelectMf(), token);
    EXPECT_TRUE(fakeConn.history().empty());
    ASSERT_FALSE(resp.has_value());
    EXPECT_EQ(resp.error().kind, TransportError::Kind::Cancelled);
    EXPECT_EQ(channel.state(), ChannelState::Open);
}

TEST(PaceChannelTests, ACardSent6987IsTheAnswerAndFailsTheChannel)
{
    FakePCSCConnection fakeConn;
    fakeConn.setResponder([](const auto&) { return makeRaw(0x69, 0x87); });
    PaceChannel channel(fakeConn, makeNamEmrtdAid(), makeFakeAesKeys());

    auto resp = channel.transmit(makeSelectMf(), CancelToken{});
    ASSERT_TRUE(resp.has_value());
    EXPECT_EQ(resp->statusWord(), 0x6987);
    EXPECT_EQ(channel.state(), ChannelState::Failed);
}

TEST(PaceChannelTests, ACardSent6988IsTheAnswerAndFailsTheChannel)
{
    FakePCSCConnection fakeConn;
    fakeConn.setResponder([](const auto&) { return makeRaw(0x69, 0x88); });
    PaceChannel channel(fakeConn, makeNamEmrtdAid(), makeFakeAesKeys());

    auto resp = channel.transmit(makeSelectMf(), CancelToken{});
    ASSERT_TRUE(resp.has_value());
    EXPECT_EQ(resp->statusWord(), 0x6988);
    EXPECT_EQ(channel.state(), ChannelState::Failed);
}

TEST(PaceChannelTests, AMalformedResponseIsAnIntegrityFailureAndFailsTheChannel)
{
    // Card replies SW 9000 with no SM TLVs — MAC unwrap will fail.
    FakePCSCConnection fakeConn;
    fakeConn.setResponder([](const auto&) { return makeRaw(0x90, 0x00); });
    PaceChannel channel(fakeConn, makeNamEmrtdAid(), makeFakeAesKeys());

    auto resp = channel.transmit(makeSelectMf(), CancelToken{});
    EXPECT_EQ(channel.state(), ChannelState::Failed);
    ASSERT_FALSE(resp.has_value());
    EXPECT_EQ(resp.error().kind, TransportError::Kind::IntegrityFailure);
}

TEST(PaceChannelTests, AnUnprotected6883IsAnIntegrityFailure)
{
    // ISO 7816-4 SW 6883 ("last command of the chain expected") is not one
    // of the two SM-invalidation status words short-circuited before MAC
    // unwrap (6987/6988), so a bare 6883 with no SM TLVs is treated like any
    // other unprotected reply: MAC unwrap fails, which is an integrity
    // failure, not the raw 6883 the card sent.
    FakePCSCConnection fakeConn;
    fakeConn.setResponder([](const auto&) { return makeRaw(0x68, 0x83); });
    PaceChannel channel(fakeConn, makeNamEmrtdAid(), makeFakeAesKeys());

    auto resp = channel.transmit(makeSelectMf(), CancelToken{});
    EXPECT_EQ(channel.state(), ChannelState::Failed);
    ASSERT_FALSE(resp.has_value());
    EXPECT_EQ(resp.error().kind, TransportError::Kind::IntegrityFailure);
}

TEST(PaceChannelTests, AFailedChannelIsUnusableAndSendsNothing)
{
    FakePCSCConnection fakeConn;
    fakeConn.setResponder([](const auto&) { return makeRaw(0x69, 0x87); });
    PaceChannel channel(fakeConn, makeNamEmrtdAid(), makeFakeAesKeys());
    (void)channel.transmit(makeSelectMf(), CancelToken{});
    ASSERT_EQ(channel.state(), ChannelState::Failed);

    fakeConn.clearHistory();
    auto resp = channel.transmit(makeSelectMf(), CancelToken{});
    EXPECT_TRUE(fakeConn.history().empty());
    ASSERT_FALSE(resp.has_value());
    EXPECT_EQ(resp.error().kind, TransportError::Kind::ChannelUnusable);
}

TEST(PaceChannelTests, AReaderErrorMidExchangeFailsTheChannel)
{
    FakePCSCConnection fakeConn;
    fakeConn.setResponder([](const auto&) {
        return std::unexpected(TransportError{TransportError::Kind::ProtocolError, "reader lost the card"});
    });
    PaceChannel channel(fakeConn, makeNamEmrtdAid(), makeFakeAesKeys());

    auto resp = channel.transmit(makeSelectMf(), CancelToken{});
    ASSERT_FALSE(resp.has_value());
    EXPECT_EQ(resp.error().kind, TransportError::Kind::ProtocolError);
    EXPECT_EQ(channel.state(), ChannelState::Failed);

    auto next = channel.transmit(makeSelectMf(), CancelToken{});
    ASSERT_FALSE(next.has_value());
    EXPECT_EQ(next.error().kind, TransportError::Kind::ChannelUnusable);
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
    ASSERT_FALSE(resp.has_value());
    EXPECT_EQ(resp.error().kind, TransportError::Kind::ChannelUnusable);
}

TEST(BacChannelTests, ACardSent6988IsTheAnswerAndFailsTheChannel)
{
    FakePCSCConnection fakeConn;
    fakeConn.setResponder([](const auto&) { return makeRaw(0x69, 0x88); });
    BacChannel channel(fakeConn, makeNamEmrtdAid(), makeFakeDes3Keys());
    auto resp = channel.transmit(makeSelectMf(), CancelToken{});
    ASSERT_TRUE(resp.has_value());
    EXPECT_EQ(resp->statusWord(), 0x6988);
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

// ---- READ BINARY length under secure messaging ----------------------------

namespace {

using LibreSCRS::SmartCard::Internal::ReadLengthPolicy;
using LibreSCRS::SmartCard::Internal::ReadLengthState;
using LibreSCRS::Test::AesSmCardOracle;

APDUCommand readBinary(std::uint16_t le)
{
    return APDUCommand{0x00, 0xB0, 0x00, 0x00, {}, le, true};
}

// The Le in DO'97 of a wrapped command frame: what the card is asked for
// inside the protection. Empty when the frame carries no DO'97.
std::optional<std::size_t> innerLe(const std::vector<std::uint8_t>& frame)
{
    std::size_t pos = 4;
    if (pos >= frame.size()) {
        return std::nullopt;
    }
    pos += frame[pos] == 0x00 ? 3 : 1;
    while (pos + 2 <= frame.size()) {
        const std::uint8_t tag = frame[pos];
        const std::size_t len = frame[pos + 1];
        if (tag == 0x97) {
            std::size_t value = 0;
            for (std::size_t i = 0; i < len; ++i) {
                value = (value << 8) | frame[pos + 2 + i];
            }
            return len == 1 && value == 0 ? 256 : value;
        }
        if (len >= 0x80) {
            return std::nullopt; // not a frame this helper reads
        }
        pos += 2 + len;
    }
    return std::nullopt;
}

std::vector<std::uint8_t> bytesOf(std::uint8_t v, std::size_t n)
{
    return std::vector<std::uint8_t>(n, v);
}

std::shared_ptr<AesSmCardOracle> makeOracle()
{
    return std::make_shared<AesSmCardOracle>(bytesOf(0x11, 16), bytesOf(0x22, 16), bytesOf(0x00, 16));
}

void answerFrom(FakePCSCConnection& conn, std::shared_ptr<AesSmCardOracle> oracle,
                AesSmCardOracle::CommandHandler handler = {})
{
    conn.setResponder(
        [&conn, oracle, handler](const APDUCommand&) { return oracle->respond(conn.rawHistory().back(), handler); });
}

class SmReadLengthTests : public ::testing::Test
{
protected:
    void TearDown() override
    {
        ::unsetenv("LIBRESCRS_PCSC_TRACE");
        LibreSCRS::log::resetForTest();
    }

    FakePCSCConnection conn;
    ReadLengthPolicy policy;
};

} // namespace

TEST_F(SmReadLengthTests, AnUntestedCardIsAskedForNoMoreThanTheShortLength)
{
    conn.setReadLengthPolicy(&policy);
    answerFrom(conn, makeOracle());
    PaceChannel channel(conn, makeNamEmrtdAid(), makeFakeAesKeys());
    ASSERT_TRUE(channel.transmit(readBinary(20000), CancelToken{}).has_value());
    EXPECT_EQ(innerLe(conn.rawHistory().back()), 256u);
    EXPECT_EQ(policy.state(), ReadLengthState::Untested) << "the channel never probes";
}

TEST_F(SmReadLengthTests, AnAcceptedCardIsStillAskedForNoMoreThanTheShortLength)
{
    conn.setReadLengthPolicy(&policy);
    policy.learn(ReadLengthState::Untested);
    policy.markAccepted();
    answerFrom(conn, makeOracle());
    PaceChannel channel(conn, makeNamEmrtdAid(), makeFakeAesKeys());
    ASSERT_TRUE(channel.transmit(readBinary(20000), CancelToken{}).has_value());
    EXPECT_EQ(innerLe(conn.rawHistory().back()), 256u);
    EXPECT_EQ(policy.state(), ReadLengthState::Accepted);
}

TEST_F(SmReadLengthTests, ADeclaredCardOnAesIsAskedForWhatFitsItsResponse)
{
    conn.setReadLengthPolicy(&policy);
    policy.learn(ReadLengthState::Declared, 960);
    answerFrom(conn, makeOracle());
    PaceChannel channel(conn, makeNamEmrtdAid(), makeFakeAesKeys());
    ASSERT_TRUE(channel.transmit(readBinary(20000), CancelToken{}).has_value());
    EXPECT_EQ(innerLe(conn.rawHistory().back()), 927u);
}

TEST_F(SmReadLengthTests, ADeclaredCardOnDes3IsAskedForWhatFitsItsResponse)
{
    conn.setReadLengthPolicy(&policy);
    policy.learn(ReadLengthState::Declared, 960);
    BacChannel channel(conn, makeNamEmrtdAid(), makeFakeDes3Keys());
    // The answer is irrelevant (the fake card sends no valid frame): only the inner Le asked for is checked.
    (void)channel.transmit(readBinary(20000), CancelToken{});
    EXPECT_EQ(innerLe(conn.rawHistory().back()), 935u);
}

TEST_F(SmReadLengthTests, ReplacingDes3KeysWithAesKeysChangesTheBlockSize)
{
    conn.setReadLengthPolicy(&policy);
    policy.learn(ReadLengthState::Declared, 960);
    answerFrom(conn, makeOracle());
    PaceChannel channel(conn, makeNamEmrtdAid(), makeFakeDes3Keys());
    LibreSCRS::SecureChannel::detail::ChannelStateMutator::replaceKeys(channel, makeFakeAesKeys());
    ASSERT_TRUE(channel.transmit(readBinary(20000), CancelToken{}).has_value());
    EXPECT_EQ(innerLe(conn.rawHistory().back()), 927u);
}

TEST_F(SmReadLengthTests, ARequestBelowTheLimitIsNotRaised)
{
    conn.setReadLengthPolicy(&policy);
    policy.learn(ReadLengthState::Declared, 960);
    answerFrom(conn, makeOracle());
    PaceChannel channel(conn, makeNamEmrtdAid(), makeFakeAesKeys());
    ASSERT_TRUE(channel.transmit(readBinary(100), CancelToken{}).has_value());
    EXPECT_EQ(innerLe(conn.rawHistory().back()), 100u);
}

TEST_F(SmReadLengthTests, AConnectionWithoutAPolicyIsAskedForNoMoreThanTheShortLength)
{
    answerFrom(conn, makeOracle());
    PaceChannel channel(conn, makeNamEmrtdAid(), makeFakeAesKeys());
    ASSERT_TRUE(channel.transmit(readBinary(20000), CancelToken{}).has_value());
    EXPECT_EQ(innerLe(conn.rawHistory().back()), 256u);
}

TEST_F(SmReadLengthTests, ACommandThatIsNotAReadBinaryIsNotShortened)
{
    conn.setReadLengthPolicy(&policy);
    answerFrom(conn, makeOracle());
    PaceChannel channel(conn, makeNamEmrtdAid(), makeFakeAesKeys());
    APDUCommand getData{0x00, 0xCA, 0x00, 0x00, {}, 20000, true};
    ASSERT_TRUE(channel.transmit(getData, CancelToken{}).has_value());
    EXPECT_EQ(innerLe(conn.rawHistory().back()), 20000u);
}

TEST_F(SmReadLengthTests, AReaderErrorOnALongCommandDemotesTheConnection)
{
    conn.setReadLengthPolicy(&policy);
    policy.learn(ReadLengthState::Declared, 960);
    conn.setResponder([](const APDUCommand&) {
        return std::unexpected(TransportError{TransportError::Kind::ProtocolError, "reader lost the card"});
    });
    PaceChannel channel(conn, makeNamEmrtdAid(), makeFakeAesKeys());
    auto answer = channel.transmit(readBinary(20000), CancelToken{});
    ASSERT_FALSE(answer.has_value());
    EXPECT_EQ(answer.error().kind, TransportError::Kind::ProtocolError);
    EXPECT_EQ(channel.state(), ChannelState::Failed);
    EXPECT_EQ(conn.rawHistory().size(), 1u) << "no retry";
    EXPECT_EQ(policy.state(), ReadLengthState::Short);

    conn.setResponder({});
    PaceChannel next(conn, makeNamEmrtdAid(), makeFakeAesKeys());
    (void)next.transmit(readBinary(20000), CancelToken{});
    EXPECT_LE(innerLe(conn.rawHistory().back()).value_or(0), 256u);
}

TEST_F(SmReadLengthTests, AnUnprotected6700OnALongCommandDemotesTheConnection)
{
    conn.setReadLengthPolicy(&policy);
    policy.learn(ReadLengthState::Declared, 960);
    conn.setResponder([](const APDUCommand&) { return makeRaw(0x67, 0x00); });
    PaceChannel channel(conn, makeNamEmrtdAid(), makeFakeAesKeys());
    auto answer = channel.transmit(readBinary(20000), CancelToken{});
    ASSERT_FALSE(answer.has_value());
    EXPECT_EQ(answer.error().kind, TransportError::Kind::IntegrityFailure);
    EXPECT_EQ(channel.state(), ChannelState::Failed);
    EXPECT_EQ(conn.rawHistory().size(), 1u) << "no retry";
    EXPECT_EQ(policy.state(), ReadLengthState::Short);

    PaceChannel next(conn, makeNamEmrtdAid(), makeFakeAesKeys());
    (void)next.transmit(readBinary(20000), CancelToken{});
    EXPECT_LE(innerLe(conn.rawHistory().back()).value_or(0), 256u);
}

TEST_F(SmReadLengthTests, AFailureOnAShortCommandLeavesTheStateAlone)
{
    conn.setReadLengthPolicy(&policy);
    policy.learn(ReadLengthState::Declared, 960);
    conn.setResponder([](const APDUCommand&) { return makeRaw(0x67, 0x00); });
    PaceChannel channel(conn, makeNamEmrtdAid(), makeFakeAesKeys());
    ASSERT_FALSE(channel.transmit(readBinary(100), CancelToken{}).has_value());
    EXPECT_EQ(policy.state(), ReadLengthState::Declared);
}

TEST_F(SmReadLengthTests, AProtected6700IsRetriedShortAndTheStateStays)
{
    conn.setReadLengthPolicy(&policy);
    policy.learn(ReadLengthState::Declared, 960);
    int calls = 0;
    answerFrom(conn, makeOracle(),
               [&calls](std::uint8_t, std::uint8_t, std::uint8_t, const std::vector<std::uint8_t>&) {
                   APDUResponse a;
                   if (++calls == 1) {
                       a.sw1 = 0x67;
                       a.sw2 = 0x00;
                   } else {
                       a.data = {0xDE, 0xAD};
                       a.sw1 = 0x90;
                       a.sw2 = 0x00;
                   }
                   return a;
               });
    PaceChannel channel(conn, makeNamEmrtdAid(), makeFakeAesKeys());

    auto answer = channel.transmit(readBinary(20000), CancelToken{});
    ASSERT_TRUE(answer.has_value());
    EXPECT_EQ(answer->statusWord(), 0x9000) << "the caller sees the second answer";
    EXPECT_EQ(answer->data, (std::vector<std::uint8_t>{0xDE, 0xAD}));
    ASSERT_EQ(conn.rawHistory().size(), 2u);
    EXPECT_EQ(innerLe(conn.rawHistory()[0]), 927u);
    EXPECT_EQ(innerLe(conn.rawHistory()[1]), 256u);
    EXPECT_EQ(channel.state(), ChannelState::Open);
    EXPECT_EQ(policy.state(), ReadLengthState::Declared);

    ASSERT_TRUE(channel.transmit(readBinary(20000), CancelToken{}).has_value());
    EXPECT_EQ(innerLe(conn.rawHistory().back()), 927u) << "the next command asks for the full length again";
}

TEST_F(SmReadLengthTests, AShortCommandThatGets67xxIsNotRetried)
{
    conn.setReadLengthPolicy(&policy);
    policy.learn(ReadLengthState::Declared, 960);
    answerFrom(conn, makeOracle(), [](std::uint8_t, std::uint8_t, std::uint8_t, const std::vector<std::uint8_t>&) {
        APDUResponse a;
        a.sw1 = 0x67;
        a.sw2 = 0x00;
        return a;
    });
    PaceChannel channel(conn, makeNamEmrtdAid(), makeFakeAesKeys());
    auto answer = channel.transmit(readBinary(100), CancelToken{});
    ASSERT_TRUE(answer.has_value());
    EXPECT_EQ(answer->statusWord(), 0x6700);
    EXPECT_EQ(conn.rawHistory().size(), 1u);
}

TEST_F(SmReadLengthTests, TheTraceNamesTheInnerLe)
{
    ::setenv("LIBRESCRS_PCSC_TRACE", "1", 1);
    LibreSCRS::log::resetForTest();
    std::vector<std::string> lines;
    LibreSCRS::log::init([&lines](LibreSCRS::log::Level level, std::string_view line) {
        if (level == LibreSCRS::log::Level::Trace) {
            lines.emplace_back(line);
        }
    });
    conn.setReadLengthPolicy(&policy);
    policy.learn(ReadLengthState::Declared, 960);
    answerFrom(conn, makeOracle());
    PaceChannel channel(conn, makeNamEmrtdAid(), makeFakeAesKeys());
    ASSERT_TRUE(channel.transmit(readBinary(20000), CancelToken{}).has_value());

    bool found = false;
    for (const auto& line : lines) {
        found = found || (line.find("[PCSC_TRACE]") != std::string::npos && line.find("927") != std::string::npos);
    }
    EXPECT_TRUE(found);
}
