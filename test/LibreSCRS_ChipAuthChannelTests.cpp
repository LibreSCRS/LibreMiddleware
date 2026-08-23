// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

/// @file
/// @brief ChipAuthChannel behavioural tests: SM flags, an AES secure-messaging
///        round-trip against a faithful card-side oracle, and the
///        confirmSmAfterKeyChange proof exchange (both the key-match and the
///        key-mismatch clone signal).

#include <LibreSCRS/CancelToken.h>
#include <LibreSCRS/Secure/Buffer.h>
#include <LibreSCRS_internal/SecureChannel/ChipAuthChannel.h>
#include <LibreSCRS_internal/SecureChannel/SessionKeys.h>
#include <LibreSCRS/SmartCard/AppletAid.h>

#include "apdu.h"
#include "chip_auth_card_oracle.h"
#include "fake_pcsc_connection.h"

#include <gtest/gtest.h>

#include <vector>

namespace {

using LibreSCRS::CancelToken;
using LibreSCRS::SecureChannel::ChannelState;
using LibreSCRS::SecureChannel::ChipAuthChannel;
using LibreSCRS::SecureChannel::confirmSmAfterKeyChange;
using LibreSCRS::SecureChannel::SessionKeys;
using LibreSCRS::SecureChannel::SmCipher;
using LibreSCRS::SecureChannel::TestSupport::FakePCSCConnection;
using LibreSCRS::SmartCard::AppletAid;
using LibreSCRS::Test::AesSmCardOracle;

AppletAid makeEmrtdAid()
{
    return AppletAid{0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01};
}

constexpr std::uint8_t kEncByte = 0x11;
constexpr std::uint8_t kMacByte = 0x22;

SessionKeys makeAesKeys()
{
    SessionKeys k;
    k.encKey = LibreSCRS::Secure::Buffer{16, kEncByte};
    k.macKey = LibreSCRS::Secure::Buffer{16, kMacByte};
    k.ssc = LibreSCRS::Secure::Buffer{16, 0x00};
    k.cipher = SmCipher::Aes;
    return k;
}

// Wire a card-side oracle behind a FakePCSCConnection: SM commands arrive via
// transmitRaw, so the responder replays the full wire frame (rawHistory) into
// the oracle rather than the header-only APDUCommand the fake reconstructs.
void installOracle(FakePCSCConnection& conn, std::shared_ptr<AesSmCardOracle> oracle)
{
    conn.setResponder([&conn, oracle](const LibreSCRS::SmartCard::Internal::APDUCommand&) {
        return oracle->respond(conn.rawHistory().back());
    });
}

std::vector<std::uint8_t> bytes(std::uint8_t v, std::size_t n)
{
    return std::vector<std::uint8_t>(n, v);
}

} // namespace

TEST(ChipAuthChannelTest, CarriesSmAndSupportsCrossAppletReuse)
{
    FakePCSCConnection conn;
    ChipAuthChannel ch{conn, makeEmrtdAid(), makeAesKeys()};
    EXPECT_TRUE(ch.carriesSm());
    EXPECT_TRUE(ch.supportsCrossAppletReuse());
    EXPECT_EQ(ch.state(), ChannelState::Open);
    EXPECT_TRUE(ch.protocolOid().empty());
}

TEST(ChipAuthChannelTest, ProofExchangeSucceedsWhenKeysMatch)
{
    FakePCSCConnection conn;
    auto oracle = std::make_shared<AesSmCardOracle>(bytes(kEncByte, 16), bytes(kMacByte, 16), bytes(0x00, 16));
    installOracle(conn, oracle);

    ChipAuthChannel ch{conn, makeEmrtdAid(), makeAesKeys()};
    EXPECT_TRUE(confirmSmAfterKeyChange(ch, makeEmrtdAid(), CancelToken{}));
    EXPECT_EQ(oracle->verifiedCommands(), 1); // the card really verified our MAC
}

TEST(ChipAuthChannelTest, ProofExchangeFailsWhenCardKeysDiffer)
{
    FakePCSCConnection conn;
    // Clone: the card derived a wrong MAC key, so it cannot verify our command
    // and never emits a valid response — the proof exchange must report false.
    auto oracle = std::make_shared<AesSmCardOracle>(bytes(kEncByte, 16), bytes(kMacByte ^ 0xFF, 16), bytes(0x00, 16));
    installOracle(conn, oracle);

    ChipAuthChannel ch{conn, makeEmrtdAid(), makeAesKeys()};
    EXPECT_FALSE(confirmSmAfterKeyChange(ch, makeEmrtdAid(), CancelToken{}));
    EXPECT_EQ(oracle->verifiedCommands(), 0);
    EXPECT_EQ(ch.state(), ChannelState::Failed); // 6988 tore the channel down
}

TEST(ChipAuthChannelTest, DataRoundTripDecryptsCardResponse)
{
    FakePCSCConnection conn;
    auto oracle = std::make_shared<AesSmCardOracle>(bytes(kEncByte, 16), bytes(kMacByte, 16), bytes(0x00, 16));
    const std::vector<std::uint8_t> payload = {0x01, 0x02, 0x03, 0x04, 0x05};
    oracle->setNextResponseData(payload);
    installOracle(conn, oracle);

    ChipAuthChannel ch{conn, makeEmrtdAid(), makeAesKeys()};
    // A READ BINARY (Case 2: Le present) exercises DO'87 decryption on the
    // response leg on top of the command MAC on the way in.
    LibreSCRS::SmartCard::Internal::APDUCommand read{0x00, 0xB0, 0x00, 0x00, {}, 0x00, true};
    auto resp = ch.transmit(read, CancelToken{});
    EXPECT_EQ(resp.sw1, 0x90);
    EXPECT_EQ(resp.sw2, 0x00);
    EXPECT_EQ(resp.data, payload);
}
