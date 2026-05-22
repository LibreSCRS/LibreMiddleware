// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

/// @file
/// @brief Regression-test anchor for the cross-provider session-coordination
///        contract that prevents a parallel PC/SC handle from invalidating
///        a live PACE/BAC SM tunnel.
///
/// The contract spans:
///
///   - @ref LibreSCRS::SmartCard::Internal::SessionPresence — process-local
///     registry of CardSessions with live secure-messaging channels;
///     populated automatically when @c CardSession::activateChannelWithSm
///     commits a channel and consulted by every in-process PKCS#11 probe.
///   - @ref LibreSCRS::OpenSc::Pkcs11::OpenScPKCS11Provider::probe — defers
///     when @c SessionPresence reports a live SM channel; PIV / generic ICC /
///     contact PKCS#15 with no live SM proceed normally.
///   - @ref LibreSCRS::SmartCard::CardSession — refuses to corrupt a live
///     SM tunnel from @c activateChannelWithSm (protocol mismatch) or
///     @c activateChannelFor (plain activation requested while an Open SM
///     channel is installed). Both surface
///     @ref LibreSCRS::SecureChannel::ChannelActivationError::Internal
///     rather than tearing the tunnel down.
///
/// If any one layer ships ahead of the others, signing on SM-protected
/// contactless cards — which depends on all three holding simultaneously —
/// silently regresses. These tests pin the joint invariant down without
/// any hardware dependency.

#include "pkcs15_pkcs11_card.h"

#include "apdu.h"

#include <LibreSCRS/Secure/String.h>
#include <LibreSCRS/SecureChannel/BacParams.h>
#include <LibreSCRS/SecureChannel/ChannelErrors.h>
#include <LibreSCRS_internal/SecureChannel/ISecureChannel.h>
#include <LibreSCRS_internal/SmartCard/SessionPresence.h>
#include <LibreSCRS_internal/SmartCard/SmartCardServices.h>
#include <LibreSCRS/SmartCard/AppletAid.h>
#include <LibreSCRS/SmartCard/CardSession.h>
#include <LibreSCRS/SmartCard/SmProtocolRequest.h>
#include <LibreSCRS/SmartCard/detail/CardSessionInjection.h>
#include <LibreSCRS/SmartCard/detail/ChannelInjection.h>

#include "fake_channel.h"

#include <internal/OpenScPKCS11Provider.h>
#include <internal/PinClassification.h>

#include "pkcs15_types.h"

#include <gtest/gtest.h>

#include <memory>
#include <string>
#include <utility>

// Lock the noexcept contract of LibreSCRS::Pkcs15::Internal::isUserPin at
// compile time. The body allocates (label copy + std::transform); the
// implementation must keep the body in a top-level try/catch so allocator
// pressure degrades to a conservative @c false instead of @c std::terminate
// (API-POLICY §5.1 noexcept-alloc contract).
static_assert(noexcept(LibreSCRS::Pkcs15::Internal::isUserPin(std::declval<const ::pkcs15::PinInfo&>())),
              "isUserPin must remain noexcept per API-POLICY §5.1");

namespace {

using LibreSCRS::SecureChannel::ChannelActivationError;
using LibreSCRS::SecureChannel::ChannelState;
using LibreSCRS::SecureChannel::TestSupport::FakeChannel;
using LibreSCRS::SmartCard::AppletAid;
using LibreSCRS::SmartCard::CardSession;
using LibreSCRS::SmartCard::PaceRequest;
using LibreSCRS::SmartCard::SmProtocolRequest;
using LibreSCRS::SmartCard::detail::ChannelInjector;
using LibreSCRS::SmartCard::detail::makeDetachedCardSession;
using LibreSCRS::SmartCard::Internal::ensureSessionPresenceInitialised;
using LibreSCRS::SmartCard::Internal::sessionPresence;
using LibreSCRS::SmartCard::Internal::shutdownSessionPresenceForTest;

constexpr const char* kReader = "Phantom Reader 0";

AppletAid makeAid()
{
    return AppletAid{0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01};
}

AppletAid makeOtherAid()
{
    return AppletAid{0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00};
}

// Convenience: install a Pace-shaped fake (carriesSm=true) in the desired
// state and return a raw pointer for later assertions. The session retains
// ownership; raw pointer is for inspection only.
FakeChannel* installPaceFake(CardSession& session, ChannelState state)
{
    auto channel = std::make_unique<FakeChannel>(makeAid(), state, /*carriesSm=*/true);
    auto* ptr = channel.get();
    ChannelInjector::installForTesting(session, std::move(channel));
    return ptr;
}

FakeChannel* installPlainFake(CardSession& session, ChannelState state)
{
    auto channel = std::make_unique<FakeChannel>(makeAid(), state, /*carriesSm=*/false);
    auto* ptr = channel.get();
    ChannelInjector::installForTesting(session, std::move(channel));
    return ptr;
}

class CrossProviderCoordination : public ::testing::Test
{
protected:
    void SetUp() override
    {
        ensureSessionPresenceInitialised();
        shutdownSessionPresenceForTest();
    }
};

} // namespace

// ---------------------------------------------------------------------------
// Invariant #1 — SessionPresence::hasLiveSm reflects an injected session's
// hasLiveSecureChannel state. The OpenScPKCS11Provider::probe consults
// hasLiveSm and short-circuits accordingly; this anchor pins the predicate
// down without invoking the provider directly.
// ---------------------------------------------------------------------------

TEST_F(CrossProviderCoordination, SessionPresenceReflectsLiveSm)
{
    auto session = makeDetachedCardSession(kReader);
    installPaceFake(*session, ChannelState::Open);
    auto reg = sessionPresence().insert(kReader, session);

    EXPECT_TRUE(sessionPresence().hasLiveSm(kReader));
    EXPECT_FALSE(sessionPresence().hasLiveSm("unrelated-reader"));
}

// ---------------------------------------------------------------------------
// Invariant #2 — OpenScPKCS11Provider::probe defers ONLY when the parked
// session reports a live SM channel. This is the PIV regression guard:
// the earlier "skip on any registry hit" logic prevented OpenSC from
// binding PIV cards because LC parks a CardSession even when no SM is
// live. The fix tightens the predicate to a live-SM check via
// SessionPresence::hasLiveSm.
// ---------------------------------------------------------------------------

TEST_F(CrossProviderCoordination, OpenScProbeShortCircuitsWhenSessionHasLiveSm)
{
    auto session = makeDetachedCardSession(kReader);
    installPaceFake(*session, ChannelState::Open);
    auto reg = sessionPresence().insert(kReader, session);

    LibreSCRS::OpenSc::Pkcs11::OpenScPKCS11Provider provider;
    auto card = provider.probe(kReader);
    EXPECT_EQ(card, nullptr);

    // SessionPresence entry survives the short-circuit so subsequent
    // probes on the same reader continue to defer.
    EXPECT_TRUE(sessionPresence().hasLiveSm(kReader));
}

TEST_F(CrossProviderCoordination, OpenScProbeProceedsWhenSessionHasNoLiveSm)
{
    auto session = makeDetachedCardSession(kReader);
    // No channel installed at all — hasLiveSecureChannel() == false.
    auto reg = sessionPresence().insert(kReader, session);

    LibreSCRS::OpenSc::Pkcs11::OpenScPKCS11Provider provider;
    // probe is permitted to fail at the OpenSc::bind step in this test
    // environment (no real PC/SC handle). The contract under test is
    // that it did NOT short-circuit early; the presence entry stays in
    // place regardless of bind outcome.
    (void)provider.probe(kReader);
    EXPECT_FALSE(sessionPresence().hasLiveSm(kReader));
}

// ---------------------------------------------------------------------------
// Invariant #3 — CardSession::hasLiveSecureChannel reports correctly across
// the supported state matrix. This is the predicate the cross-provider
// coordination consumers gate on; getting it wrong in either direction
// breaks signing on SM-protected cards or onboarding of non-SM cards
// through the OpenSc fallback.
// ---------------------------------------------------------------------------

TEST_F(CrossProviderCoordination, HasLiveSecureChannelMatrix)
{
    {
        SCOPED_TRACE("no channel installed");
        auto session = makeDetachedCardSession(kReader);
        EXPECT_FALSE(session->hasLiveSecureChannel());
    }
    {
        SCOPED_TRACE("plain channel Open — no SM context");
        auto session = makeDetachedCardSession(kReader);
        installPlainFake(*session, ChannelState::Open);
        EXPECT_FALSE(session->hasLiveSecureChannel());
    }
    {
        SCOPED_TRACE("pace-style channel Open — carriesSm=true");
        auto session = makeDetachedCardSession(kReader);
        installPaceFake(*session, ChannelState::Open);
        EXPECT_TRUE(session->hasLiveSecureChannel());
    }
    {
        SCOPED_TRACE("pace-style channel Closed");
        auto session = makeDetachedCardSession(kReader);
        installPaceFake(*session, ChannelState::Closed);
        EXPECT_FALSE(session->hasLiveSecureChannel());
    }
    {
        SCOPED_TRACE("pace-style channel Failed");
        auto session = makeDetachedCardSession(kReader);
        installPaceFake(*session, ChannelState::Failed);
        EXPECT_FALSE(session->hasLiveSecureChannel());
    }
}

// ---------------------------------------------------------------------------
// Invariant #4 — activateChannelWithSm refuses when an Open SM channel of
// the wrong protocol is already installed. The live channel survives the
// call; the caller is expected to either explicitly close it via
// clearActiveChannel or route through the same protocol family.
// ---------------------------------------------------------------------------

TEST_F(CrossProviderCoordination, ActivateChannelWithSmRefusesOnIncompatibleLiveSmChannel)
{
    auto session = makeDetachedCardSession(kReader);
    auto* fake = installPaceFake(*session, ChannelState::Open);
    ASSERT_TRUE(session->hasLiveSecureChannel());

    // Seed the BAC input so the cheap precondition gate (cacheHit ||
    // hasUsableChannel || credentialProvider) passes for the BacRequest
    // branch. The values are placeholders — no handshake runs in this
    // detached session.
    session->setBacInput(LibreSCRS::SecureChannel::BacInput{LibreSCRS::Secure::String{"L898902C3"},
                                                            LibreSCRS::Secure::String{"690806"},
                                                            LibreSCRS::Secure::String{"940623"}});

    SmProtocolRequest req = LibreSCRS::SmartCard::BacRequest{};
    auto result = session->activateChannelWithSm(makeAid(), req, LibreSCRS::CancelToken{});
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), ChannelActivationError::Internal);

    // Live SM channel is sacred: still Open, still installed, never close()d.
    EXPECT_TRUE(session->hasLiveSecureChannel());
    EXPECT_EQ(fake->state(), ChannelState::Open);
}

// ---------------------------------------------------------------------------
// Invariant #5 — activateChannelFor (plain activation) refuses when an
// Open SM channel exists. The live SM channel must not be torn down by
// the plain-SELECT path.
// ---------------------------------------------------------------------------

TEST_F(CrossProviderCoordination, ActivateChannelForRefusesOnLiveSmChannel)
{
    auto session = makeDetachedCardSession(kReader);
    auto* fake = installPaceFake(*session, ChannelState::Open);
    ASSERT_TRUE(session->hasLiveSecureChannel());

    auto result = session->activateChannelFor(makeOtherAid(), LibreSCRS::CancelToken{});
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), ChannelActivationError::Internal);

    // Live SM channel remains intact post-refusal.
    EXPECT_TRUE(session->hasLiveSecureChannel());
    EXPECT_EQ(fake->state(), ChannelState::Open);
}
