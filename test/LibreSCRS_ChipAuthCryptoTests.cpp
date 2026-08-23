// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

/// @file
/// @brief Tests for the CA/AA crypto verdicts and, later, the full
///        ChipAuthChannel::establish handshake. This file pins the
///        refuse-vs-fail distinction (chipRefusedProtocol) that lets the
///        plugin report NOT_PERFORMED on a plain channel a card SM-gates,
///        instead of accusing the card.

#include "chip_auth.h"
#include "active_auth.h"
#include "chip_auth_fake_chip.h"

#include <LibreSCRS_internal/SecureChannel/ChipAuthChannel.h>

#include "fake_pcsc_connection.h"

#include <gtest/gtest.h>

#include <vector>

namespace {

using LibreSCRS::SecureChannel::ChipAuthChannel;
using LibreSCRS::SecureChannel::ChipAuthEstablishError;
using LibreSCRS::SecureChannel::TestSupport::FakePCSCConnection;
using LibreSCRS::SmartCard::AppletAid;
using LibreSCRS::Test::buildDg14;
using LibreSCRS::Test::buildDg15;
using LibreSCRS::Test::EcCardKey;
using LibreSCRS::Test::EcdhCaCardChannel;

AppletAid emrtdAid()
{
    return AppletAid{0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01};
}

// Route the SM leg (over the wire connection) to the card's SM oracle, which
// only exists after GENERAL AUTHENTICATE — so read it lazily at call time.
void wireSmLeg(FakePCSCConnection& conn, EcdhCaCardChannel& card)
{
    conn.setResponder([&conn, &card](const LibreSCRS::SmartCard::Internal::APDUCommand&) {
        auto sm = card.smOracle();
        if (!sm) {
            return LibreSCRS::SmartCard::Internal::APDUResponse{{}, 0x6F, 0x00};
        }
        return sm->respond(conn.rawHistory().back());
    });
}

} // namespace

TEST(ChipAuthCryptoTest, GeneralAuthenticateRefusalIsNotPerformedNotFailure)
{
    auto key = EcCardKey::generate();
    const auto dg14 = buildDg14(key.spkiDer);

    EcdhCaCardChannel card{key, emrtdAid()};
    card.refuseIns(0x86, 0x69, 0x82); // GENERAL AUTHENTICATE refused

    auto result = emrtd::crypto::performChipAuth(card, dg14, LibreSCRS::CancelToken{});
    EXPECT_EQ(result.chipAuthentication, emrtd::crypto::ChipAuthResult::FAILED);
    EXPECT_TRUE(result.chipRefusedProtocol);
}

TEST(ChipAuthCryptoTest, MseRefusalIsMarkedAsProtocolRefusal)
{
    auto key = EcCardKey::generate();
    const auto dg14 = buildDg14(key.spkiDer);

    EcdhCaCardChannel card{key, emrtdAid()};
    card.refuseIns(0x22, 0x69, 0x82); // MSE:Set AT refused

    auto result = emrtd::crypto::performChipAuth(card, dg14, LibreSCRS::CancelToken{});
    EXPECT_EQ(result.chipAuthentication, emrtd::crypto::ChipAuthResult::FAILED);
    EXPECT_TRUE(result.chipRefusedProtocol);
}

TEST(ChipAuthCryptoTest, ActiveAuthInternalAuthRefusalSetsFlag)
{
    auto key = EcCardKey::generate();
    const auto dg15 = buildDg15(key.spkiDer);

    EcdhCaCardChannel card{key, emrtdAid()};
    card.refuseIns(0x88, 0x69, 0x82); // INTERNAL AUTHENTICATE refused

    auto result = emrtd::crypto::performActiveAuth(card, dg15, LibreSCRS::CancelToken{});
    EXPECT_EQ(result.activeAuthentication, emrtd::crypto::ChipAuthResult::FAILED);
    EXPECT_TRUE(result.chipRefusedProtocol);
}

TEST(ChipAuthCryptoTest, ActiveAuthEmptyResponseIsFailureNotRefusal)
{
    // The card answers INTERNAL AUTHENTICATE with a success SW but no signature
    // bytes: a genuine failure, but NOT a protocol refusal — the flag must stay
    // clear so the plugin does not mislabel it as "not performed".
    auto key = EcCardKey::generate();
    const auto dg15 = buildDg15(key.spkiDer);

    // Default EcdhCaCardChannel returns 6D00 for INS 0x88 (unhandled) which is a
    // bad SW; to get "9000 + empty" drive AA through a tiny inline channel.
    struct EmptyOkChannel final : LibreSCRS::SecureChannel::ISecureChannel
    {
        AppletAid aid{emrtdAid()};
        const AppletAid& currentApplet() const noexcept override
        {
            return aid;
        }
        LibreSCRS::SecureChannel::ChannelState state() const noexcept override
        {
            return LibreSCRS::SecureChannel::ChannelState::Open;
        }
        LibreSCRS::SmartCard::Internal::APDUResponse
        transmit(const LibreSCRS::SmartCard::Internal::APDUCommand& /*cmd*/, LibreSCRS::CancelToken) override
        {
            return {{}, 0x90, 0x00}; // success SW, empty data
        }
        void close() override {}
        void setCurrentApplet(AppletAid a) noexcept override
        {
            aid = std::move(a);
        }
        void replaceKeys(LibreSCRS::SecureChannel::SessionKeys) noexcept override {}
    } card;

    auto result = emrtd::crypto::performActiveAuth(card, dg15, LibreSCRS::CancelToken{});
    EXPECT_EQ(result.activeAuthentication, emrtd::crypto::ChipAuthResult::FAILED);
    EXPECT_FALSE(result.chipRefusedProtocol);
}

TEST(ChipAuthEstablishTest, SucceedsAndProofExchangePassesWithHonestChip)
{
    auto key = EcCardKey::generate();
    const auto dg14 = buildDg14(key.spkiDer);

    FakePCSCConnection conn;
    EcdhCaCardChannel card{key, emrtdAid()};
    wireSmLeg(conn, card);

    auto result = ChipAuthChannel::establish(conn, card, dg14, emrtdAid(), LibreSCRS::CancelToken{});
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE((*result)->carriesSm());
    EXPECT_FALSE((*result)->protocolOid().empty()); // CA OID recorded for the check detail

    // The returned channel really speaks SM to the same card: a further wrapped
    // command round-trips (the card set up its SM oracle during GA).
    card.smOracle()->setNextResponseData({0xAA, 0xBB});
    LibreSCRS::SmartCard::Internal::APDUCommand read{0x00, 0xB0, 0x00, 0x00, {}, 0x00, true};
    auto resp = (*result)->transmit(read, LibreSCRS::CancelToken{});
    EXPECT_TRUE(resp.isSuccess());
    EXPECT_EQ(resp.data, (std::vector<std::uint8_t>{0xAA, 0xBB}));
}

TEST(ChipAuthEstablishTest, CloneChipFailsTheProofExchange)
{
    auto key = EcCardKey::generate();
    const auto dg14 = buildDg14(key.spkiDer);

    FakePCSCConnection conn;
    EcdhCaCardChannel card{key, emrtdAid()};
    card.makeClone(); // derives a wrong MAC key card-side
    wireSmLeg(conn, card);

    auto result = ChipAuthChannel::establish(conn, card, dg14, emrtdAid(), LibreSCRS::CancelToken{});
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().kind, ChipAuthEstablishError::Kind::SmProofFailed);
}

TEST(ChipAuthEstablishTest, ProtocolRefusalMapsToProtocolRefused)
{
    auto key = EcCardKey::generate();
    const auto dg14 = buildDg14(key.spkiDer);

    FakePCSCConnection conn;
    EcdhCaCardChannel card{key, emrtdAid()};
    card.refuseIns(0x86, 0x69, 0x82); // GA refused on the plain channel
    wireSmLeg(conn, card);

    auto result = ChipAuthChannel::establish(conn, card, dg14, emrtdAid(), LibreSCRS::CancelToken{});
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().kind, ChipAuthEstablishError::Kind::ProtocolRefused);
}

TEST(ChipAuthEstablishTest, CancelledTokenMapsToCancelledNotFailure)
{
    // A caller-side cancel earns no genuineness verdict: it must surface as
    // its own kind (the plugin maps it to NOT_PERFORMED), never as the
    // LocalCryptoFailure/SmProofFailed kinds that read as a clone signal.
    auto key = EcCardKey::generate();
    const auto dg14 = buildDg14(key.spkiDer);

    FakePCSCConnection conn;
    EcdhCaCardChannel card{key, emrtdAid()};
    wireSmLeg(conn, card);

    LibreSCRS::CancelSource src;
    src.requestCancel();
    auto result = ChipAuthChannel::establish(conn, card, dg14, emrtdAid(), src.token());
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().kind, ChipAuthEstablishError::Kind::Cancelled);
}

TEST(ChipAuthEstablishTest, UnparsableDg14MapsToNotSupported)
{
    auto key = EcCardKey::generate();
    const std::vector<std::uint8_t> garbage = {0x00, 0x01, 0x02, 0x03};

    FakePCSCConnection conn;
    EcdhCaCardChannel card{key, emrtdAid()};
    wireSmLeg(conn, card);

    auto result = ChipAuthChannel::establish(conn, card, garbage, emrtdAid(), LibreSCRS::CancelToken{});
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().kind, ChipAuthEstablishError::Kind::NotSupported);
}
