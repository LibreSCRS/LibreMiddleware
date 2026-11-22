// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

/// @file
/// @brief CardSession control-flow tests for Chip Authentication: the
///        performChipAuthentication operation (plain upgrade and in-tunnel key
///        rotation, with every verdict it can give), the reuse-only
///        ChipAuthRequest guard on activateChannelWithSm, and the cross-applet
///        wrapped-SELECT reuse activateChannelFor gained for session-scoped SM
///        tunnels.
///
/// A detached CardSession's connection exposes setDetachedRawResponder, so a
/// real ChipAuthChannel's wrapped SELECT round-trips against an AES SM oracle
/// with matching keys — the Case-2 / reuse success paths are exercised on the
/// wire, not stubbed.

#include <LibreSCRS/CancelToken.h>
#include <LibreSCRS/Secure/Buffer.h>
#include <LibreSCRS/SecureChannel/ChannelErrors.h>
#include <LibreSCRS/SmartCard/ActiveChannelHolder.h>
#include <LibreSCRS/SmartCard/AppletAid.h>
#include <LibreSCRS/SmartCard/CardSession.h>
#include <LibreSCRS/SmartCard/testing/CardSessionTesting.h>
#include <LibreSCRS/SmartCard/detail/ChannelInjection.h>
#include <session_access.h>
#include <LibreSCRS_internal/SecureChannel/BacChannel.h>
#include <LibreSCRS_internal/SecureChannel/ChipAuthChannel.h>
#include <LibreSCRS_internal/SecureChannel/PlainChannel.h>
#include <LibreSCRS_internal/SecureChannel/SessionKeys.h>

#include <LibreSCRS_internal/SecureChannel/PaceChannel.h>
#include <pcsc_connection.h>
#include <smartcard/i_connection.h>
#include <smartcard/or_throw.h>

#include "apdu.h"
#include "chip_auth_card_oracle.h"
#include "chip_auth_fake_chip.h"

#include <gtest/gtest.h>

#include <memory>
#include <new>
#include <optional>
#include <stdexcept>
#include <span>
#include <string>
#include <vector>

namespace {

using LibreSCRS::SecureChannel::BacChannel;
using LibreSCRS::SecureChannel::ChannelActivationError;
using LibreSCRS::SecureChannel::ChipAuthChannel;
using LibreSCRS::SecureChannel::PaceChannel;
using LibreSCRS::SecureChannel::PlainChannel;
using LibreSCRS::SecureChannel::SessionKeys;
using LibreSCRS::SecureChannel::SmCipher;
using LibreSCRS::SmartCard::ActiveChannelHolder;
using LibreSCRS::SmartCard::AppletAid;
using LibreSCRS::SmartCard::BacRequest;
using LibreSCRS::SmartCard::CardSession;
using LibreSCRS::SmartCard::ChipAuthOutcome;
using LibreSCRS::SmartCard::ChipAuthReason;
using LibreSCRS::SmartCard::ChipAuthReport;
using LibreSCRS::SmartCard::ChipAuthRequest;
using LibreSCRS::SmartCard::PaceRequest;
using LibreSCRS::SmartCard::SmProtocolRequest;
using LibreSCRS::SmartCard::detail::ChannelInjector;
using LibreSCRS::SmartCard::Testing::makeDetachedCardSession;
using LibreSCRS::SmartCard::Testing::SessionAccess;
using LibreSCRS::Test::AesSmCardOracle;
using LibreSCRS::Test::buildDg14;
using LibreSCRS::Test::CaCardOnTheWire;
using LibreSCRS::Test::EcCardKey;

AppletAid aidA()
{
    return AppletAid{0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01};
}
AppletAid aidB()
{
    return AppletAid{0xB0, 0x01, 0x02, 0x03, 0x04, 0x05};
}

constexpr std::uint8_t kEncByte = 0x33;
constexpr std::uint8_t kMacByte = 0x44;

SessionKeys aesKeys()
{
    SessionKeys k;
    k.encKey = LibreSCRS::Secure::Buffer{std::vector<std::uint8_t>(16, kEncByte)};
    k.macKey = LibreSCRS::Secure::Buffer{std::vector<std::uint8_t>(16, kMacByte)};
    k.ssc = LibreSCRS::Secure::Buffer{std::vector<std::uint8_t>(16, 0x00)};
    k.cipher = SmCipher::Aes;
    return k;
}

std::vector<std::uint8_t> vec(std::uint8_t v, std::size_t n)
{
    return std::vector<std::uint8_t>(n, v);
}

// Point the detached connection's raw responder at an SM oracle with keys
// matching the channel installed on the session, so wrapped SELECTs succeed.
void wireOracle(CardSession& session, std::shared_ptr<AesSmCardOracle> oracle)
{
    auto& conn = LibreSCRS::SmartCard::Internal::connectionOf(session);
    conn.setDetachedRawResponder([oracle](std::span<const std::uint8_t> wrapped) { return oracle->respond(wrapped); });
}

std::shared_ptr<AesSmCardOracle> matchingOracle()
{
    return std::make_shared<AesSmCardOracle>(vec(kEncByte, 16), vec(kMacByte, 16), vec(0x00, 16));
}

// id-CA-ECDH-AES-CBC-CMAC-128, the protocol buildDg14 advertises.
const std::string kCaAes128Oid = "0.4.0.127.0.7.2.2.3.2.2";

// A plain channel that remembers being closed after it is gone.
class CloseRecordingPlainChannel final : public LibreSCRS::SecureChannel::ISecureChannel
{
public:
    CloseRecordingPlainChannel(LibreSCRS::SmartCard::IConnection& connection, AppletAid aid,
                               std::shared_ptr<bool> closedFlag)
        : conn(connection), appletAid(std::move(aid)), closed(std::move(closedFlag))
    {}
    [[nodiscard]] const AppletAid& currentApplet() const noexcept override
    {
        return appletAid;
    }
    [[nodiscard]] LibreSCRS::SecureChannel::ChannelState state() const noexcept override
    {
        return *closed ? LibreSCRS::SecureChannel::ChannelState::Closed : LibreSCRS::SecureChannel::ChannelState::Open;
    }
    [[nodiscard]] std::expected<LibreSCRS::SmartCard::Internal::APDUResponse, LibreSCRS::SmartCard::TransportError>
    transmit(const LibreSCRS::SmartCard::Internal::APDUCommand& cmd, LibreSCRS::CancelToken /*token*/) override
    {
        return conn.transmit(cmd);
    }
    void close() override
    {
        *closed = true;
    }

protected:
    void setCurrentApplet(AppletAid aid) noexcept override
    {
        appletAid = std::move(aid);
    }
    void replaceKeys(SessionKeys /*keys*/) noexcept override {}

private:
    LibreSCRS::SmartCard::IConnection& conn;
    AppletAid appletAid;
    std::shared_ptr<bool> closed;
};

// A detached session whose connection is answered by @p card, with a channel
// installed and held the way a plugin read holds it. @c inTunnel starts the
// card and the session inside a PACE tunnel keyed by aesKeys(); otherwise
// the session sits on a plain channel.
struct CaRig
{
    std::shared_ptr<CardSession> session;
    std::shared_ptr<CaCardOnTheWire> card;
    std::optional<ActiveChannelHolder> holder;
};

CaRig makeCaRig(const EcCardKey& key, bool inTunnel, bool takeHolder = true)
{
    CaRig rig;
    rig.session = makeDetachedCardSession(inTunnel ? "reader-ca-tunnel" : "reader-ca-plain");
    rig.card = std::make_shared<CaCardOnTheWire>(key);
    auto& conn = LibreSCRS::SmartCard::Internal::connectionOf(*rig.session);
    conn.setDetachedRawResponder(
        [card = rig.card](std::span<const std::uint8_t> frame) { return card->respond(frame); });
    if (inTunnel) {
        rig.card->startInTunnel(vec(kEncByte, 16), vec(kMacByte, 16), vec(0x00, 16));
        ChannelInjector::installForTesting(*rig.session, std::make_unique<PaceChannel>(conn, aidA(), aesKeys()),
                                           SmProtocolRequest{PaceRequest{}});
        if (takeHolder) {
            auto h = rig.session->activateChannelWithSm(aidA(), PaceRequest{}, LibreSCRS::CancelToken{});
            if (h) {
                rig.holder.emplace(std::move(*h));
            }
        }
    } else {
        ChannelInjector::installForTesting(*rig.session, std::make_unique<PlainChannel>(conn, aidA()));
        if (takeHolder) {
            auto h = rig.session->activateChannelFor(aidA(), LibreSCRS::CancelToken{});
            if (h) {
                rig.holder.emplace(std::move(*h));
            }
        }
    }
    return rig;
}

bool sawIns(const CaCardOnTheWire& card, std::uint8_t ins)
{
    for (auto i : card.insLog()) {
        if (i == ins) {
            return true;
        }
    }
    return false;
}

LibreSCRS::SmartCard::Internal::APDUCommand readBinary()
{
    return LibreSCRS::SmartCard::Internal::APDUCommand{0x00, 0xB0, 0x00, 0x00, {}, 0x00, true};
}

} // namespace

// --- performChipAuthentication -------------------------------------------

TEST(ChipAuthSessionTest, APlainUpgradeRecordsTheProtocolAndClosesThePlainChannel)
{
    // A successful upgrade replaces the plain channel the read started on: the
    // session records ChipAuthRequest and closes the channel it replaced.
    const auto key = EcCardKey::generate();
    auto rig = makeCaRig(key, /*inTunnel=*/false, /*takeHolder=*/false);
    auto closed = std::make_shared<bool>(false);
    auto& conn = LibreSCRS::SmartCard::Internal::connectionOf(*rig.session);
    ChannelInjector::installForTesting(*rig.session,
                                       std::make_unique<CloseRecordingPlainChannel>(conn, aidA(), closed));
    auto holder = rig.session->activateChannelFor(aidA(), LibreSCRS::CancelToken{});
    ASSERT_TRUE(holder.has_value());
    ASSERT_FALSE(*closed);

    const auto report =
        rig.session->performChipAuthentication(buildDg14(key.spkiDer), aidA(), LibreSCRS::CancelToken{});
    ASSERT_EQ(report.outcome, ChipAuthOutcome::Passed);
    EXPECT_TRUE(*closed) << "the replaced plain channel must be closed";

    // Lock-free accessor (the public one would self-deadlock under the holder).
    auto proto = rig.session->activatedProtocol();
    ASSERT_TRUE(proto.has_value());
    EXPECT_TRUE(std::holds_alternative<ChipAuthRequest>(*proto));
    auto* active = SessionAccess::activeChannel(*rig.session);
    ASSERT_NE(active, nullptr);
    EXPECT_TRUE(active->carriesSm());
}

TEST(ChipAuthSessionTest, OverAPlainChannelASuccessfulRunInstallsTheTunnel)
{
    const auto key = EcCardKey::generate();
    auto rig = makeCaRig(key, /*inTunnel=*/false);
    ASSERT_TRUE(rig.holder.has_value());

    const ChipAuthReport report =
        rig.session->performChipAuthentication(buildDg14(key.spkiDer), aidA(), LibreSCRS::CancelToken{});
    EXPECT_EQ(report.outcome, ChipAuthOutcome::Passed);
    EXPECT_EQ(report.reason, ChipAuthReason::None);
    EXPECT_EQ(report.protocolOid, kCaAes128Oid);
    EXPECT_TRUE(report.detail.empty()) << report.detail;
    // Passed rests on a wrapped exchange the card verified under the new keys.
    EXPECT_EQ(rig.card->keyAgreements(), 1);
    ASSERT_NE(rig.card->smOracle(), nullptr);
    EXPECT_EQ(rig.card->smOracle()->verifiedCommands(), 1);

    rig.holder.reset();
    EXPECT_TRUE(rig.session->hasLiveSecureChannel());
    const auto proto = rig.session->activatedProtocol();
    ASSERT_TRUE(proto.has_value());
    EXPECT_TRUE(std::holds_alternative<ChipAuthRequest>(*proto));
}

TEST(ChipAuthSessionTest, OverAPlainChannelARefusedProtocolIsNotPerformedAndTheReadStaysPlain)
{
    const auto key = EcCardKey::generate();
    auto rig = makeCaRig(key, /*inTunnel=*/false);
    ASSERT_TRUE(rig.holder.has_value());
    rig.card->refuseIns(0x86, 0x69, 0x82);

    const auto report =
        rig.session->performChipAuthentication(buildDg14(key.spkiDer), aidA(), LibreSCRS::CancelToken{});
    EXPECT_EQ(report.outcome, ChipAuthOutcome::NotPerformed);
    EXPECT_EQ(report.reason, ChipAuthReason::NotOffered);
    EXPECT_EQ(report.protocolOid, kCaAes128Oid);
    EXPECT_EQ(report.detail, "chip refused Chip Authentication on plain channel");

    // The read goes on over the same plain channel.
    auto* active = SessionAccess::activeChannel(*rig.session);
    ASSERT_NE(active, nullptr);
    EXPECT_FALSE(active->carriesSm());
    const auto next = active->transmit(LibreSCRS::SmartCard::Internal::selectByAID(aidA().asVector(), 0x0C),
                                       LibreSCRS::CancelToken{});
    ASSERT_TRUE(next.has_value());
    EXPECT_TRUE(next->isSuccess());

    rig.holder.reset();
    EXPECT_FALSE(rig.session->hasLiveSecureChannel());
    EXPECT_FALSE(rig.session->activatedProtocol().has_value());
}

TEST(ChipAuthSessionTest, OverAPlainChannelAFailedProofIsAFailure)
{
    const auto key = EcCardKey::generate();
    auto rig = makeCaRig(key, /*inTunnel=*/false);
    ASSERT_TRUE(rig.holder.has_value());
    rig.card->makeClone();

    const auto report =
        rig.session->performChipAuthentication(buildDg14(key.spkiDer), aidA(), LibreSCRS::CancelToken{});
    EXPECT_EQ(report.outcome, ChipAuthOutcome::Failed);
    EXPECT_EQ(report.reason, ChipAuthReason::None);
    EXPECT_EQ(report.protocolOid, kCaAes128Oid);
    EXPECT_EQ(report.detail, "secure-messaging proof exchange failed");
    EXPECT_EQ(rig.card->keyAgreements(), 1) << "the clone must be caught on the wire, after the key agreement";

    rig.holder.reset();
    EXPECT_FALSE(rig.session->hasLiveSecureChannel());
}

TEST(ChipAuthSessionTest, ADg14WithoutKeyMaterialIsNotSupported)
{
    const auto key = EcCardKey::generate();
    auto rig = makeCaRig(key, /*inTunnel=*/false);
    ASSERT_TRUE(rig.holder.has_value());

    const std::vector<std::uint8_t> noCaMaterial = {0x6E, 0x02, 0x31, 0x00};
    const auto report = rig.session->performChipAuthentication(noCaMaterial, aidA(), LibreSCRS::CancelToken{});
    EXPECT_EQ(report.outcome, ChipAuthOutcome::NotSupported);
    EXPECT_EQ(report.reason, ChipAuthReason::NotOffered);
    EXPECT_TRUE(report.protocolOid.empty());
    EXPECT_TRUE(report.detail.empty()) << report.detail;
    EXPECT_FALSE(sawIns(*rig.card, 0x22));
    EXPECT_FALSE(sawIns(*rig.card, 0x86));
}

TEST(ChipAuthSessionTest, ACancelledRunEarnsNoVerdict)
{
    // A cancel before the run, during the key agreement, or while the proof
    // exchange is on the wire yields no verdict on either path. In the last
    // case the exchange is aborted (the card's answer is lost), which without
    // the cancel would read as a proof that did not verify.
    enum class When { Before, AtKeyAgreement, AtProof };
    struct Case
    {
        bool inTunnel;
        When when;
        const char* name;
    };
    const Case cases[] = {
        {false, When::Before, "plain, before"},
        {true, When::Before, "tunnel, before"},
        {false, When::AtKeyAgreement, "plain, at the key agreement"},
        {false, When::AtProof, "plain, at the proof exchange"},
        {true, When::AtProof, "tunnel, at the proof exchange"},
    };
    const auto key = EcCardKey::generate();
    for (const auto& c : cases) {
        SCOPED_TRACE(c.name);
        auto rig = makeCaRig(key, c.inTunnel);
        ASSERT_TRUE(rig.holder.has_value());

        LibreSCRS::CancelSource src;
        if (c.when == When::Before) {
            src.requestCancel();
        } else if (c.when == When::AtKeyAgreement) {
            rig.card->onIns(0x86, [&src]() -> std::optional<LibreSCRS::SmartCard::Internal::APDUResponse> {
                src.requestCancel();
                return std::nullopt;
            });
        } else {
            rig.card->onIns(0xA4, [&src]() -> std::optional<LibreSCRS::SmartCard::Internal::APDUResponse> {
                src.requestCancel();
                return LibreSCRS::SmartCard::Internal::APDUResponse{
                    {}, 0x6F, 0x00}; // not under the keys: the channel rejects it
            });
        }
        const auto report = rig.session->performChipAuthentication(buildDg14(key.spkiDer), aidA(), src.token());
        EXPECT_EQ(report.outcome, ChipAuthOutcome::NotPerformed);
        EXPECT_EQ(report.reason, ChipAuthReason::Cancelled);
        if (c.when == When::Before) {
            EXPECT_TRUE(rig.card->insLog().empty()) << "a cancelled run must not reach the card";
        } else {
            EXPECT_EQ(rig.card->keyAgreements(), 1);
        }
    }
}

TEST(ChipAuthSessionTest, InsideATunnelASuccessfulRunRotatesTheKeys)
{
    const auto key = EcCardKey::generate();
    auto rig = makeCaRig(key, /*inTunnel=*/true);
    ASSERT_TRUE(rig.holder.has_value());
    ASSERT_TRUE(rig.card->insLog().empty()) << "taking the holder must not touch the wire";

    const auto report =
        rig.session->performChipAuthentication(buildDg14(key.spkiDer), aidA(), LibreSCRS::CancelToken{});
    EXPECT_EQ(report.outcome, ChipAuthOutcome::Passed);
    EXPECT_EQ(report.reason, ChipAuthReason::None);
    EXPECT_EQ(report.protocolOid, kCaAes128Oid);
    EXPECT_TRUE(report.detail.empty()) << report.detail;
    ASSERT_EQ(rig.card->keyAgreements(), 1);

    // The card now answers only under the CA keys. The proof exchange was
    // one wrapped command under them; the next APDU of the read must be too.
    auto rotated = rig.card->smOracle();
    ASSERT_NE(rotated, nullptr);
    EXPECT_EQ(rotated->verifiedCommands(), 1);
    rotated->setNextResponseData({0xAA, 0xBB});
    auto* active = SessionAccess::activeChannel(*rig.session);
    ASSERT_NE(active, nullptr);
    const auto next = active->transmit(readBinary(), LibreSCRS::CancelToken{});
    ASSERT_TRUE(next.has_value());
    EXPECT_TRUE(next->isSuccess());
    EXPECT_EQ(next->data, (std::vector<std::uint8_t>{0xAA, 0xBB}));
    EXPECT_EQ(rotated->verifiedCommands(), 2);

    // The tunnel keeps the protocol it was opened with.
    const auto proto = rig.session->activatedProtocol();
    ASSERT_TRUE(proto.has_value());
    EXPECT_TRUE(std::holds_alternative<PaceRequest>(*proto));
}

TEST(ChipAuthSessionTest, ARotationThatDoesNotVerifyIsAFailure)
{
    const auto key = EcCardKey::generate();
    auto rig = makeCaRig(key, /*inTunnel=*/true);
    ASSERT_TRUE(rig.holder.has_value());
    rig.card->makeClone();

    const auto report =
        rig.session->performChipAuthentication(buildDg14(key.spkiDer), aidA(), LibreSCRS::CancelToken{});
    EXPECT_EQ(report.outcome, ChipAuthOutcome::Failed);
    EXPECT_EQ(report.reason, ChipAuthReason::None);
    EXPECT_EQ(report.protocolOid, kCaAes128Oid);
    EXPECT_EQ(report.detail, "chip authentication key agreement did not verify");
    EXPECT_EQ(rig.card->keyAgreements(), 1);
}

TEST(ChipAuthSessionTest, InsideATunnelACancelDuringTheRotationEarnsNoVerdict)
{
    const auto key = EcCardKey::generate();
    auto rig = makeCaRig(key, /*inTunnel=*/true);
    ASSERT_TRUE(rig.holder.has_value());

    // The cancel lands after the key agreement went out, so the proof
    // exchange is never sent: aborted, not answered wrongly.
    LibreSCRS::CancelSource src;
    rig.card->onIns(0x86, [&src]() -> std::optional<LibreSCRS::SmartCard::Internal::APDUResponse> {
        src.requestCancel();
        return std::nullopt;
    });
    const auto report = rig.session->performChipAuthentication(buildDg14(key.spkiDer), aidA(), src.token());
    EXPECT_EQ(report.outcome, ChipAuthOutcome::NotPerformed);
    EXPECT_EQ(report.reason, ChipAuthReason::Cancelled);
    ASSERT_EQ(rig.card->keyAgreements(), 1);

    // Both sides hold the CA keys: nothing went out under them yet, and the
    // next command of the read goes through under them.
    auto rotated = rig.card->smOracle();
    ASSERT_NE(rotated, nullptr);
    EXPECT_EQ(rotated->verifiedCommands(), 0);
    auto* active = SessionAccess::activeChannel(*rig.session);
    ASSERT_NE(active, nullptr);
    rotated->setNextResponseData({0x01, 0x02});
    const auto next = active->transmit(readBinary(), LibreSCRS::CancelToken{});
    ASSERT_TRUE(next.has_value());
    EXPECT_TRUE(next->isSuccess());
    EXPECT_EQ(next->data, (std::vector<std::uint8_t>{0x01, 0x02}));
    EXPECT_EQ(rotated->verifiedCommands(), 1);
}

TEST(ChipAuthSessionTest, WithoutTheChannelHeldNothingIsSent)
{
    const auto key = EcCardKey::generate();
    auto rig = makeCaRig(key, /*inTunnel=*/false, /*takeHolder=*/false);

    const auto report =
        rig.session->performChipAuthentication(buildDg14(key.spkiDer), aidA(), LibreSCRS::CancelToken{});
    EXPECT_EQ(report.outcome, ChipAuthOutcome::NotPerformed);
    EXPECT_EQ(report.reason, ChipAuthReason::NoUsableChannel);
    EXPECT_TRUE(rig.card->insLog().empty());
}

TEST(ChipAuthSessionTest, AReaderErrorDuringTheProofIsNotACloneVerdict)
{
    // The reader loses the card on the proof SELECT: the card gave no answer,
    // which is no evidence against it, on either path.
    const auto key = EcCardKey::generate();
    for (const bool inTunnel : {false, true}) {
        SCOPED_TRACE(inTunnel ? "inside a tunnel" : "over a plain channel");
        auto rig = makeCaRig(key, inTunnel);
        ASSERT_TRUE(rig.holder.has_value());
        rig.card->failIns(0xA4, LibreSCRS::SmartCard::TransportError{
                                    LibreSCRS::SmartCard::TransportError::Kind::NoCardPresent, "SCardTransmit failed"});

        const auto report =
            rig.session->performChipAuthentication(buildDg14(key.spkiDer), aidA(), LibreSCRS::CancelToken{});
        EXPECT_EQ(report.outcome, ChipAuthOutcome::NotPerformed);
        EXPECT_EQ(report.reason, ChipAuthReason::ReaderError);
        EXPECT_EQ(report.protocolOid, kCaAes128Oid);
        EXPECT_EQ(rig.card->keyAgreements(), 1);
    }
}

TEST(ChipAuthSessionTest, AReaderErrorDuringGeneralAuthenticateIsReaderError)
{
    const auto key = EcCardKey::generate();
    for (const bool inTunnel : {false, true}) {
        SCOPED_TRACE(inTunnel ? "inside a tunnel" : "over a plain channel");
        auto rig = makeCaRig(key, inTunnel);
        ASSERT_TRUE(rig.holder.has_value());
        rig.card->failIns(0x86, LibreSCRS::SmartCard::TransportError{
                                    LibreSCRS::SmartCard::TransportError::Kind::NoCardPresent, "SCardTransmit failed"});

        const auto report =
            rig.session->performChipAuthentication(buildDg14(key.spkiDer), aidA(), LibreSCRS::CancelToken{});
        EXPECT_EQ(report.outcome, ChipAuthOutcome::NotPerformed);
        EXPECT_EQ(report.reason, ChipAuthReason::ReaderError);
        EXPECT_EQ(rig.card->keyAgreements(), 0);
    }
}

TEST(ChipAuthSessionTest, ACardSent6988OnTheProofIsFailed)
{
    // A card-side secure-messaging abort on the proof SELECT is the card's own
    // answer: it does not hold the keys.
    const auto key = EcCardKey::generate();
    for (const bool inTunnel : {false, true}) {
        SCOPED_TRACE(inTunnel ? "inside a tunnel" : "over a plain channel");
        auto rig = makeCaRig(key, inTunnel);
        ASSERT_TRUE(rig.holder.has_value());
        rig.card->breakSmOn(0xA4);

        const auto report =
            rig.session->performChipAuthentication(buildDg14(key.spkiDer), aidA(), LibreSCRS::CancelToken{});
        EXPECT_EQ(report.outcome, ChipAuthOutcome::Failed);
        EXPECT_EQ(report.reason, ChipAuthReason::None);
    }
}

TEST(ChipAuthSessionTest, AnIntegrityFailureOnPlainIsFailed)
{
    // The proof answer does not verify under the derived keys: the chip did
    // not prove the key, and that is a verdict.
    const auto key = EcCardKey::generate();
    auto rig = makeCaRig(key, /*inTunnel=*/false);
    ASSERT_TRUE(rig.holder.has_value());
    rig.card->onIns(0xA4, []() -> std::optional<LibreSCRS::SmartCard::Internal::APDUResponse> {
        return LibreSCRS::SmartCard::Internal::APDUResponse{{}, 0x6F, 0x00};
    });

    const auto report =
        rig.session->performChipAuthentication(buildDg14(key.spkiDer), aidA(), LibreSCRS::CancelToken{});
    EXPECT_EQ(report.outcome, ChipAuthOutcome::Failed);
    EXPECT_EQ(report.reason, ChipAuthReason::None);
}

TEST(ChipAuthSessionTest, AnAllocationFailureDuringTheRunPropagates)
{
    const auto key = EcCardKey::generate();
    for (const bool inTunnel : {false, true}) {
        SCOPED_TRACE(inTunnel ? "inside a tunnel" : "over a plain channel");
        auto rig = makeCaRig(key, inTunnel);
        ASSERT_TRUE(rig.holder.has_value());
        rig.card->onIns(
            0x86, []() -> std::optional<LibreSCRS::SmartCard::Internal::APDUResponse> { throw std::bad_alloc(); });
        EXPECT_THROW(
            (void)rig.session->performChipAuthentication(buildDg14(key.spkiDer), aidA(), LibreSCRS::CancelToken{}),
            std::bad_alloc);
    }
}

TEST(ChipAuthSessionTest, ALocalCryptoFailureIsNoVerdict)
{
    // DG14 advertises a key this side cannot use (not a SubjectPublicKeyInfo):
    // the run fails here, before the chip is asked anything.
    const auto key = EcCardKey::generate();
    const auto unusableKey = buildDg14({0x30, 0x03, 0x02, 0x01, 0x00});
    for (const bool inTunnel : {false, true}) {
        SCOPED_TRACE(inTunnel ? "inside a tunnel" : "over a plain channel");
        auto rig = makeCaRig(key, inTunnel);
        ASSERT_TRUE(rig.holder.has_value());
        const auto report = rig.session->performChipAuthentication(unusableKey, aidA(), LibreSCRS::CancelToken{});
        EXPECT_EQ(report.outcome, ChipAuthOutcome::NotPerformed);
        EXPECT_EQ(report.reason, ChipAuthReason::LocalCryptoFailure);
        EXPECT_EQ(report.protocolOid, kCaAes128Oid);
        EXPECT_FALSE(sawIns(*rig.card, 0x86));
    }
}

TEST(ChipAuthSessionTest, InsideATunnelTheProofSelectBecomesTheCurrentApplet)
{
    // The proof exchange selects the applet the caller names; the channel must
    // know it, or a later activation for the holder's applet would take the
    // no-SELECT fast path and talk to the wrong one.
    const auto key = EcCardKey::generate();
    auto rig = makeCaRig(key, /*inTunnel=*/true);
    ASSERT_TRUE(rig.holder.has_value());

    const auto report =
        rig.session->performChipAuthentication(buildDg14(key.spkiDer), aidB(), LibreSCRS::CancelToken{});
    ASSERT_EQ(report.outcome, ChipAuthOutcome::Passed);
    auto* active = SessionAccess::activeChannel(*rig.session);
    ASSERT_NE(active, nullptr);
    EXPECT_EQ(active->currentApplet(), aidB());

    // Activating the holder's original applet now re-selects it through the
    // tunnel instead of assuming it is current.
    rig.holder.reset();
    const auto proofsBefore = rig.card->smOracle()->verifiedCommands();
    auto again = rig.session->activateChannelWithSm(aidA(), PaceRequest{}, LibreSCRS::CancelToken{});
    ASSERT_TRUE(again.has_value());
    EXPECT_EQ(rig.card->smOracle()->verifiedCommands(), proofsBefore + 1);
}

TEST(ChipAuthSessionTest, InsideATunnelARefusalOfTheProtocolIsAFailure)
{
    // Inside the tunnel a chip whose signed DG14 offers Chip Authentication
    // must complete it; a protected refusal is an answer, and a verdict.
    const auto key = EcCardKey::generate();
    auto rig = makeCaRig(key, /*inTunnel=*/true);
    ASSERT_TRUE(rig.holder.has_value());
    rig.card->refuseIns(0x86, 0x69, 0x82);

    const auto report =
        rig.session->performChipAuthentication(buildDg14(key.spkiDer), aidA(), LibreSCRS::CancelToken{});
    EXPECT_EQ(report.outcome, ChipAuthOutcome::Failed);
    EXPECT_EQ(report.reason, ChipAuthReason::None);
    EXPECT_EQ(report.protocolOid, kCaAes128Oid);
    EXPECT_EQ(rig.card->keyAgreements(), 0);
}

TEST(ChipAuthSessionTest, InsideATunnelAnIntegrityFailureIsAFailure)
{
    // A card-side secure-messaging abort during the key agreement is an answer
    // from the card, not a reader error: inside the tunnel it is a verdict.
    const auto key = EcCardKey::generate();
    auto rig = makeCaRig(key, /*inTunnel=*/true);
    ASSERT_TRUE(rig.holder.has_value());
    rig.card->breakSmOn(0x86);

    const auto report =
        rig.session->performChipAuthentication(buildDg14(key.spkiDer), aidA(), LibreSCRS::CancelToken{});
    EXPECT_EQ(report.outcome, ChipAuthOutcome::Failed);
    EXPECT_EQ(report.reason, ChipAuthReason::None);
    EXPECT_EQ(rig.card->keyAgreements(), 0);
}

TEST(ChipAuthSessionTest, AProofAnsweredWithAnErrorStatusUnderTheNewKeysPasses)
{
    // The proof SELECT names an applet the card does not have; the card says
    // so (6A82) in a response protected under the new keys. Only a card that
    // holds the keys can produce that response, so the keys are proven -- but
    // the applet is not selected, and the channel does not claim it is.
    const auto key = EcCardKey::generate();
    for (const bool inTunnel : {false, true}) {
        SCOPED_TRACE(inTunnel ? "inside a tunnel" : "over a plain channel");
        auto rig = makeCaRig(key, inTunnel);
        ASSERT_TRUE(rig.holder.has_value());
        rig.card->refuseIns(0xA4, 0x6A, 0x82);

        const auto report =
            rig.session->performChipAuthentication(buildDg14(key.spkiDer), aidB(), LibreSCRS::CancelToken{});
        EXPECT_EQ(report.outcome, ChipAuthOutcome::Passed);
        ASSERT_NE(rig.card->smOracle(), nullptr);
        EXPECT_EQ(rig.card->smOracle()->verifiedCommands(), 1);
        auto* active = SessionAccess::activeChannel(*rig.session);
        ASSERT_NE(active, nullptr);
        EXPECT_TRUE(active->carriesSm());
        EXPECT_EQ(active->currentApplet(), aidA());
    }
}

// --- activateChannelWithSm(ChipAuthRequest) --------------------------------

TEST(ChipAuthSessionTest, ChipAuthRequestReusesSameAppletChannelWithoutWire)
{
    auto session = makeDetachedCardSession("reader-case1");
    auto& conn = LibreSCRS::SmartCard::Internal::connectionOf(*session);

    auto ca = std::make_unique<ChipAuthChannel>(conn, aidA(), aesKeys());
    ChannelInjector::installForTesting(*session, std::move(ca), SmProtocolRequest{ChipAuthRequest{}});

    // Same applet: Case 1 fast path returns a holder without touching the wire.
    auto result = session->activateChannelWithSm(aidA(), ChipAuthRequest{}, LibreSCRS::CancelToken{});
    ASSERT_TRUE(result.has_value());
}

TEST(ChipAuthSessionTest, ChipAuthRequestReusesAcrossAppletsViaWrappedSelect)
{
    auto session = makeDetachedCardSession("reader-case2");
    auto& conn = LibreSCRS::SmartCard::Internal::connectionOf(*session);
    wireOracle(*session, matchingOracle());

    auto ca = std::make_unique<ChipAuthChannel>(conn, aidA(), aesKeys());
    ChannelInjector::installForTesting(*session, std::move(ca), SmProtocolRequest{ChipAuthRequest{}});

    // Different applet: Case 2 wraps a SELECT through the live tunnel.
    auto result = session->activateChannelWithSm(aidB(), ChipAuthRequest{}, LibreSCRS::CancelToken{});
    ASSERT_TRUE(result.has_value());
}

TEST(ChipAuthSessionTest, ChipAuthRequestWithNoChannelRefusesWithoutPrompting)
{
    auto session = makeDetachedCardSession("reader-nochan");
    // No channel installed, no credential provider: ChipAuthRequest must refuse
    // as Internal and NEVER fall into the PACE establish loop / provider prompt.
    auto result = session->activateChannelWithSm(aidA(), ChipAuthRequest{}, LibreSCRS::CancelToken{});
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), ChannelActivationError::Internal);
}

TEST(ChipAuthSessionTest, ChipAuthRequestAgainstPaceChannelRefuses)
{
    auto session = makeDetachedCardSession("reader-mismatch");
    auto& conn = LibreSCRS::SmartCard::Internal::connectionOf(*session);

    // A live BAC channel does not match a ChipAuthRequest.
    SessionKeys bacKeys = aesKeys();
    bacKeys.cipher = SmCipher::Des3;
    auto bac = std::make_unique<BacChannel>(conn, aidA(),
                                            SessionKeys{LibreSCRS::Secure::Buffer{std::vector<std::uint8_t>(16, 0x01)},
                                                        LibreSCRS::Secure::Buffer{std::vector<std::uint8_t>(16, 0x02)},
                                                        LibreSCRS::Secure::Buffer{std::vector<std::uint8_t>(8, 0x00)},
                                                        SmCipher::Des3});
    ChannelInjector::installForTesting(*session, std::move(bac), SmProtocolRequest{BacRequest{}});

    auto result = session->activateChannelWithSm(aidA(), ChipAuthRequest{}, LibreSCRS::CancelToken{});
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), ChannelActivationError::Internal);
}

// A channel matches a request by the protocol the session recorded when it
// installed the channel. The public stand-in records none, so a live stand-in
// is never reused for any protocol: an Open SM channel that serves no request
// is refused rather than replaced.
TEST(ChipAuthSessionTest, LiveStandInChannelIsNeverReusedForAProtocol)
{
    const SmProtocolRequest requests[] = {PaceRequest{}, BacRequest{}, ChipAuthRequest{}};
    for (const auto& request : requests) {
        SCOPED_TRACE(request.index());
        auto session = makeDetachedCardSession("reader-standin");
        LibreSCRS::SmartCard::Testing::installStandInChannel(
            *session, LibreSCRS::SmartCard::Testing::StandInChannel::LiveSecureMessaging);
        ASSERT_TRUE(session->hasLiveSecureChannel());
        ASSERT_FALSE(session->activatedProtocol().has_value());

        auto result = session->activateChannelWithSm(aidA(), request, LibreSCRS::CancelToken{});
        ASSERT_FALSE(result.has_value());
        EXPECT_EQ(result.error(), ChannelActivationError::Internal);
        // Refused, not torn down: the live tunnel is still there.
        EXPECT_TRUE(session->hasLiveSecureChannel());
    }
}

// --- activateChannelFor cross-applet reuse ---------------------------------

TEST(ChipAuthSessionTest, ActivateChannelForReusesChipAuthTunnelAcrossApplets)
{
    auto session = makeDetachedCardSession("reader-reuse");
    auto& conn = LibreSCRS::SmartCard::Internal::connectionOf(*session);
    wireOracle(*session, matchingOracle());

    auto ca = std::make_unique<ChipAuthChannel>(conn, aidA(), aesKeys());
    ChannelInjector::installForTesting(*session, std::move(ca), SmProtocolRequest{ChipAuthRequest{}});

    // A plain-profile plugin (e.g. PKCS#15) switching applets rides the live CA
    // tunnel via a wrapped SELECT instead of being refused Internal.
    auto result = session->activateChannelFor(aidB(), LibreSCRS::CancelToken{});
    ASSERT_TRUE(result.has_value());

    // The tunnel survived: protocol still ChipAuthRequest, channel still SM.
    auto proto = session->activatedProtocol();
    ASSERT_TRUE(proto.has_value());
    EXPECT_TRUE(std::holds_alternative<ChipAuthRequest>(*proto));
}

TEST(ChipAuthSessionTest, ActivateChannelForStillRefusesNonReusableBacTunnel)
{
    auto session = makeDetachedCardSession("reader-bac");
    auto& conn = LibreSCRS::SmartCard::Internal::connectionOf(*session);

    auto bac = std::make_unique<BacChannel>(conn, aidA(),
                                            SessionKeys{LibreSCRS::Secure::Buffer{std::vector<std::uint8_t>(16, 0x01)},
                                                        LibreSCRS::Secure::Buffer{std::vector<std::uint8_t>(16, 0x02)},
                                                        LibreSCRS::Secure::Buffer{std::vector<std::uint8_t>(8, 0x00)},
                                                        SmCipher::Des3});
    ChannelInjector::installForTesting(*session, std::move(bac), SmProtocolRequest{BacRequest{}});

    // BAC is single-applet: no cross-applet reuse, so a plain activation for a
    // different applet is still refused rather than corrupting the tunnel.
    auto result = session->activateChannelFor(aidB(), LibreSCRS::CancelToken{});
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), ChannelActivationError::Internal);
}

TEST(ChipAuthSessionTest, ActivateChannelForReuseWrappedSelectFailureKeepsTunnel)
{
    auto session = makeDetachedCardSession("reader-reuse-fail");
    auto& conn = LibreSCRS::SmartCard::Internal::connectionOf(*session);
    // Oracle with the WRONG mac key: the wrapped SELECT's response MAC will not
    // verify, so the SELECT "fails" — the tunnel must NOT be torn down.
    conn.setDetachedRawResponder(
        [oracle = std::make_shared<AesSmCardOracle>(vec(kEncByte, 16), vec(kMacByte ^ 0xFF, 16), vec(0x00, 16))](
            std::span<const std::uint8_t> w) { return oracle->respond(w); });

    auto ca = std::make_unique<ChipAuthChannel>(conn, aidA(), aesKeys());
    ChannelInjector::installForTesting(*session, std::move(ca), SmProtocolRequest{ChipAuthRequest{}});

    auto result = session->activateChannelFor(aidB(), LibreSCRS::CancelToken{});
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), ChannelActivationError::SelectAppletFailed);
}
