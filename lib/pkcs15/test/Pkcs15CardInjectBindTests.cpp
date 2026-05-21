// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "pkcs15_pkcs11_card.h"

#include "apdu.h"

#include <LibreSCRS/SmartCard/CardSession.h>
#include <LibreSCRS/SmartCard/detail/CardSessionInjection.h>
#include <LibreSCRS/SmartCard/detail/ChannelInjection.h>
#include <LibreSCRS_internal/SecureChannel/ISecureChannel.h>

#include <internal/Crv.h>

#include <gtest/gtest.h>

#include <memory>
#include <string>
#include <utility>

namespace LibreSCRS::Pkcs15::Pkcs11 {

// Pkcs15CardInjectBindTests exercises the new bindFromInjectedSession
// surface using detached CardSession fixtures (no PC/SC IO). The detached
// session's PCSCConnection has no live card handle, so any holder
// activation surfaces as a transport-level failure mapped to DeviceError —
// sufficient to assert that the new code path adopts the injected session
// (rather than crashing or trying to open a second handle) and propagates
// the holder's failure mode through the existing mapHolderErrorToCrv
// translator.

TEST(Pkcs15CardInjectBindTest, NullSessionReturnsArgumentsBad)
{
    auto card = std::make_shared<Pkcs15Card>(nullptr);
    auto rc = card->bindFromInjectedSession("Reader 0", nullptr);
    EXPECT_EQ(rc, LibreSCRS::Pkcs11::Internal::Crv::ArgumentsBad);
}

TEST(Pkcs15CardInjectBindTest, DetachedSessionAdoptsAndPropagatesHolderFailure)
{
    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("Reader 0");
    ASSERT_NE(session, nullptr);

    auto card = std::make_shared<Pkcs15Card>(nullptr);
    auto rc = card->bindFromInjectedSession("Reader 0", session);

    // Detached PCSCConnection rejects beginTransaction (no live card
    // handle) — activateChannelFor returns ReaderError, which the holder-
    // error mapper translates to DeviceError. The important invariant is
    // that the card adopted the session and reported a deterministic
    // numeric Crv rather than crashing or opening a new PC/SC handle.
    EXPECT_EQ(rc, LibreSCRS::Pkcs11::Internal::Crv::DeviceError);

    // Adoption: the card holds a shared reference to the same session.
    // Two refs in this test scope (local + card) plus any extra LM-
    // internal refs — assert ≥2 to keep the test robust against future
    // intermediate caches.
    EXPECT_GE(session.use_count(), 2L);
}

namespace {

// Minimal SM-carrying channel for the probe-respect-SM regression. Counts
// transmits so a regression that re-introduces a plain SELECT-AID during
// the bind / probe path can be detected at the test seam — the production
// invariant is "no plain APDU once a carriesSm() channel is Open" (PACE
// SM is session-scoped per BSI TR-03110 §3; a plain APDU resets card-side
// SM context).
class SmRespectingFakeChannel final : public LibreSCRS::SecureChannel::ISecureChannel
{
public:
    SmRespectingFakeChannel() : aid(LibreSCRS::SmartCard::AppletAid::fromBytes({})) {}

    [[nodiscard]] const LibreSCRS::SmartCard::AppletAid& currentApplet() const noexcept override
    {
        return aid;
    }
    [[nodiscard]] LibreSCRS::SecureChannel::ChannelState state() const noexcept override
    {
        return channelState;
    }
    [[nodiscard]] LibreSCRS::SmartCard::Internal::APDUResponse
    transmit(const LibreSCRS::SmartCard::Internal::APDUCommand& /*cmd*/, LibreSCRS::CancelToken /*token*/) override
    {
        ++transmitCount;
        return {};
    }
    void close() override
    {
        channelState = LibreSCRS::SecureChannel::ChannelState::Closed;
    }
    [[nodiscard]] bool carriesSm() const noexcept override
    {
        return true;
    }
    [[nodiscard]] bool supportsCrossAppletReuse() const noexcept override
    {
        return true;
    }
    [[nodiscard]] int transmits() const noexcept
    {
        return transmitCount;
    }

protected:
    void setCurrentApplet(LibreSCRS::SmartCard::AppletAid newAid) noexcept override
    {
        aid = std::move(newAid);
    }
    void replaceKeys(LibreSCRS::SecureChannel::SessionKeys /*keys*/) noexcept override {}

private:
    LibreSCRS::SmartCard::AppletAid aid;
    LibreSCRS::SecureChannel::ChannelState channelState{LibreSCRS::SecureChannel::ChannelState::Open};
    int transmitCount{0};
};

} // namespace

// Pkcs15CardInjectBindTest, RespectsLiveSecureChannel — regression for the
// NAM CL consecutive-sign bug where Pkcs15Card::bind() called a plain
// probeApplet SELECT-AID over the borrowed PC/SC connection even when the
// session already carried a live SM channel, tearing down the card-side
// PACE SM context. The bindFromInjectedSession path exercised here does
// not call probeApplet at all; it routes through CardSession's
// activateChannelWithSm and reuses the live channel via the Case 1 fast
// path (same applet, channel still Open). This test asserts that:
//
//   (a) the live SM channel survives the bind attempt (no plain APDU was
//       routed past the SM tunnel via the host code path), and
//   (b) hasLiveSecureChannel() still reports true after the call.
//
// Pkcs15Card::bind() — the cold-open path — adds the same guard inline:
// when session.hasLiveSecureChannel() is true the probeApplet plain
// transmit is skipped. Direct unit coverage of bind() requires PC/SC
// infrastructure (CardSession::open) and lives in the hardware-gated
// Pkcs11NamFixture suite.
TEST(Pkcs15CardInjectBindTest, RespectsLiveSecureChannel)
{
    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("Reader 0");
    ASSERT_NE(session, nullptr);

    auto channel = std::make_unique<SmRespectingFakeChannel>();
    auto* channelPtr = channel.get();
    LibreSCRS::SmartCard::detail::ChannelInjector::installForTesting(*session, std::move(channel));
    ASSERT_TRUE(session->hasLiveSecureChannel());
    const int transmitsBefore = channelPtr->transmits();

    auto card = std::make_shared<Pkcs15Card>(nullptr);
    // bindFromInjectedSession routes through activateChannelWithSm. With a
    // live SM-carrying channel installed the Case 3 refusal (incompatible
    // protocol — FakeChannel is not a PaceChannel) surfaces as Internal,
    // which mapHolderErrorToCrv translates to DeviceError. The live
    // channel is left intact — that is the invariant under test.
    (void)card->bindFromInjectedSession("Reader 0", session);

    // The live SM channel must NOT have been torn down via plain transmits
    // emitted by the bind path. Zero new transmits is the strongest signal;
    // any incremental count would indicate a plain SELECT slipped past the
    // SM tunnel and reset the card-side context.
    EXPECT_EQ(channelPtr->transmits(), transmitsBefore);
    EXPECT_TRUE(session->hasLiveSecureChannel());
}

} // namespace LibreSCRS::Pkcs15::Pkcs11
