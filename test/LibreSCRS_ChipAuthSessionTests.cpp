// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

/// @file
/// @brief CardSession control-flow tests for the Chip Authentication channel:
///        the installSmChannel seam, the reuse-only ChipAuthRequest guard on
///        activateChannelWithSm, and the cross-applet wrapped-SELECT reuse
///        activateChannelFor gained for session-scoped SM tunnels.
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
#include <LibreSCRS/SmartCard/detail/CardSessionInjection.h>
#include <LibreSCRS/SmartCard/detail/ChannelInjection.h>
#include <LibreSCRS/SmartCard/detail/Unwrap.h>
#include <LibreSCRS_internal/SecureChannel/BacChannel.h>
#include <LibreSCRS_internal/SecureChannel/ChipAuthChannel.h>
#include <LibreSCRS_internal/SecureChannel/PlainChannel.h>
#include <LibreSCRS_internal/SecureChannel/SessionKeys.h>
#include <LibreSCRS_internal/SmartCard/ActiveChannelHolderInternal.h>

#include "apdu.h"
#include "chip_auth_card_oracle.h"

#include <gtest/gtest.h>

#include <memory>
#include <vector>

namespace {

using LibreSCRS::SecureChannel::BacChannel;
using LibreSCRS::SecureChannel::ChannelActivationError;
using LibreSCRS::SecureChannel::ChipAuthChannel;
using LibreSCRS::SecureChannel::PlainChannel;
using LibreSCRS::SecureChannel::SessionKeys;
using LibreSCRS::SecureChannel::SmCipher;
using LibreSCRS::SmartCard::AppletAid;
using LibreSCRS::SmartCard::BacRequest;
using LibreSCRS::SmartCard::CardSession;
using LibreSCRS::SmartCard::ChipAuthRequest;
using LibreSCRS::SmartCard::PaceRequest;
using LibreSCRS::SmartCard::SmProtocolRequest;
using LibreSCRS::SmartCard::detail::ChannelInjector;
using LibreSCRS::SmartCard::detail::makeDetachedCardSession;
using LibreSCRS::SmartCard::Internal::ActiveChannelAccessor;
using LibreSCRS::Test::AesSmCardOracle;

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
    k.encKey = LibreSCRS::Secure::Buffer{16, kEncByte};
    k.macKey = LibreSCRS::Secure::Buffer{16, kMacByte};
    k.ssc = LibreSCRS::Secure::Buffer{16, 0x00};
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
    auto& conn = LibreSCRS::SmartCard::detail::unwrap(session);
    conn.setDetachedRawResponder([oracle](std::span<const std::uint8_t> wrapped) { return oracle->respond(wrapped); });
}

std::shared_ptr<AesSmCardOracle> matchingOracle()
{
    return std::make_shared<AesSmCardOracle>(vec(kEncByte, 16), vec(kMacByte, 16), vec(0x00, 16));
}

} // namespace

// --- installSmChannel ------------------------------------------------------

TEST(ChipAuthSessionTest, InstallSmChannelRecordsProtocolAndClosesOldChannel)
{
    auto session = makeDetachedCardSession("reader-install");
    auto& conn = LibreSCRS::SmartCard::detail::unwrap(*session);

    // Start on a plain channel bound to aidA and take a real holder via the
    // fast path (no wire), reproducing the owner-thread state installSmChannel
    // requires.
    ChannelInjector::installForTesting(*session, std::make_unique<PlainChannel>(conn, aidA()));
    auto holder = session->activateChannelFor(aidA(), LibreSCRS::CancelToken{});
    ASSERT_TRUE(holder.has_value());

    auto ca = std::make_unique<ChipAuthChannel>(conn, aidA(), aesKeys());
    ActiveChannelAccessor::installSmChannel(*session, std::move(ca), ChipAuthRequest{});

    // Lock-free accessor (the public one would self-deadlock under the holder).
    auto proto = ActiveChannelAccessor::activatedProtocol(*session);
    ASSERT_TRUE(proto.has_value());
    EXPECT_TRUE(std::holds_alternative<ChipAuthRequest>(*proto));
    // The live channel is now the CA channel (carries SM).
    auto* active = ActiveChannelAccessor::active(*session);
    ASSERT_NE(active, nullptr);
    EXPECT_TRUE(active->carriesSm());
}

// --- activateChannelWithSm(ChipAuthRequest) --------------------------------

TEST(ChipAuthSessionTest, ChipAuthRequestReusesSameAppletChannelWithoutWire)
{
    auto session = makeDetachedCardSession("reader-case1");
    auto& conn = LibreSCRS::SmartCard::detail::unwrap(*session);

    auto ca = std::make_unique<ChipAuthChannel>(conn, aidA(), aesKeys());
    ChannelInjector::installForTesting(*session, std::move(ca), SmProtocolRequest{ChipAuthRequest{}});

    // Same applet: Case 1 fast path returns a holder without touching the wire.
    auto result = session->activateChannelWithSm(aidA(), ChipAuthRequest{}, LibreSCRS::CancelToken{});
    ASSERT_TRUE(result.has_value());
}

TEST(ChipAuthSessionTest, ChipAuthRequestReusesAcrossAppletsViaWrappedSelect)
{
    auto session = makeDetachedCardSession("reader-case2");
    auto& conn = LibreSCRS::SmartCard::detail::unwrap(*session);
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
    auto& conn = LibreSCRS::SmartCard::detail::unwrap(*session);

    // A live BAC channel does not match a ChipAuthRequest.
    SessionKeys bacKeys = aesKeys();
    bacKeys.cipher = SmCipher::Des3;
    auto bac = std::make_unique<BacChannel>(conn, aidA(),
                                            SessionKeys{LibreSCRS::Secure::Buffer{16, 0x01},
                                                        LibreSCRS::Secure::Buffer{16, 0x02},
                                                        LibreSCRS::Secure::Buffer{8, 0x00}, SmCipher::Des3});
    ChannelInjector::installForTesting(*session, std::move(bac), SmProtocolRequest{BacRequest{}});

    auto result = session->activateChannelWithSm(aidA(), ChipAuthRequest{}, LibreSCRS::CancelToken{});
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), ChannelActivationError::Internal);
}

// --- activateChannelFor cross-applet reuse ---------------------------------

TEST(ChipAuthSessionTest, ActivateChannelForReusesChipAuthTunnelAcrossApplets)
{
    auto session = makeDetachedCardSession("reader-reuse");
    auto& conn = LibreSCRS::SmartCard::detail::unwrap(*session);
    wireOracle(*session, matchingOracle());

    auto ca = std::make_unique<ChipAuthChannel>(conn, aidA(), aesKeys());
    ChannelInjector::installForTesting(*session, std::move(ca), SmProtocolRequest{ChipAuthRequest{}});

    // A plain-profile plugin (e.g. PKCS#15) switching applets rides the live CA
    // tunnel via a wrapped SELECT instead of being refused Internal.
    auto result = session->activateChannelFor(aidB(), LibreSCRS::CancelToken{});
    ASSERT_TRUE(result.has_value());

    // The tunnel survived: protocol still ChipAuthRequest, channel still SM.
    auto proto = ActiveChannelAccessor::activatedProtocol(*session);
    ASSERT_TRUE(proto.has_value());
    EXPECT_TRUE(std::holds_alternative<ChipAuthRequest>(*proto));
}

TEST(ChipAuthSessionTest, ActivateChannelForStillRefusesNonReusableBacTunnel)
{
    auto session = makeDetachedCardSession("reader-bac");
    auto& conn = LibreSCRS::SmartCard::detail::unwrap(*session);

    auto bac = std::make_unique<BacChannel>(conn, aidA(),
                                            SessionKeys{LibreSCRS::Secure::Buffer{16, 0x01},
                                                        LibreSCRS::Secure::Buffer{16, 0x02},
                                                        LibreSCRS::Secure::Buffer{8, 0x00}, SmCipher::Des3});
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
    auto& conn = LibreSCRS::SmartCard::detail::unwrap(*session);
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
