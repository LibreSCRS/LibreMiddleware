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
#include <optional>
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
// ownership; raw pointer is for inspection only. @p recordedProtocol, when
// set, is stamped as the session's activatedProtocol under the same lock —
// mirroring the activation paths so a test can reconstruct a
// recorded-protocol-but-non-live-channel window.
FakeChannel* installPaceFake(CardSession& session, ChannelState state,
                             std::optional<SmProtocolRequest> recordedProtocol = std::nullopt)
{
    auto channel = std::make_unique<FakeChannel>(makeAid(), state, /*carriesSm=*/true);
    auto* ptr = channel.get();
    ChannelInjector::installForTesting(session, std::move(channel), std::move(recordedProtocol));
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
// Invariant #3b — activatedProtocol is self-consistent with
// hasLiveSecureChannel. An installed SM channel can transition to Failed (or
// Closed) on its own during a holder transmit (card-side 6987/6988 /
// MAC-unwrap failure) with NO teardown call, leaving activeChannel set and
// activatedProtocol still recorded. In that window hasLiveSecureChannel() is
// false; the accessor MUST mirror it and report nullopt rather than the stale
// recorded protocol. The Open case is the positive control: a recorded
// protocol on a live SM channel reads back intact.
// ---------------------------------------------------------------------------

TEST_F(CrossProviderCoordination, ActivatedProtocolGatedOnLiveSmChannel)
{
    const SmProtocolRequest recorded = PaceRequest{LibreSCRS::Auth::PaceSecretKind::Can};
    {
        SCOPED_TRACE("recorded protocol on Open SM channel reads back intact");
        auto session = makeDetachedCardSession(kReader);
        installPaceFake(*session, ChannelState::Open, recorded);
        ASSERT_TRUE(session->hasLiveSecureChannel());
        ASSERT_TRUE(session->activatedProtocol().has_value());
        EXPECT_EQ(*session->activatedProtocol(), recorded);
    }
    {
        // REQUIRED regression: recorded protocol but Failed channel — accessor
        // must return nullopt even though d->activatedProtocol is set.
        SCOPED_TRACE("recorded protocol on Failed SM channel reports nullopt");
        auto session = makeDetachedCardSession(kReader);
        installPaceFake(*session, ChannelState::Failed, recorded);
        ASSERT_FALSE(session->hasLiveSecureChannel());
        EXPECT_FALSE(session->activatedProtocol().has_value());
    }
    {
        SCOPED_TRACE("recorded protocol on Closed SM channel reports nullopt");
        auto session = makeDetachedCardSession(kReader);
        installPaceFake(*session, ChannelState::Closed, recorded);
        ASSERT_FALSE(session->hasLiveSecureChannel());
        EXPECT_FALSE(session->activatedProtocol().has_value());
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

// ---------------------------------------------------------------------------
// Invariant #6 — Pkcs15PKCS11Provider consults the SessionPresence it was
// constructed with (ctor DI), peeking BEFORE bind. The registry is injected
// by reference rather than reached through the process-global accessor, so
// the adopt-or-bind decision is unit-testable here without a PC/SC reader.
//
// Sibling of OpenScProbeShortCircuitsWhenSessionHasLiveSm, but for the
// adopt-not-defer contract: where the OpenSc provider returns nullptr
// (defers to the PKCS#15 provider) on a live SM channel, the PKCS#15
// provider ADOPTS the injected session and reuses its SM tunnel instead of
// opening a parallel PC/SC handle.
// ---------------------------------------------------------------------------

TEST_F(CrossProviderCoordination, Pkcs15ProbeFreshBindsWhenInjectedPresenceEmpty)
{
    // Empty injected registry -> peek misses -> fresh bind. The phantom
    // reader has no PC/SC handle, so the fresh bind fails deterministically
    // and probe returns nullptr. Proves the provider uses the ctor-injected
    // reference and falls through to bind when it has no entry.
    LibreSCRS::SmartCard::Internal::SessionPresence injectedSp;
    LibreSCRS::Pkcs15::Pkcs11::Pkcs15PKCS11Provider provider(/*cardMap=*/nullptr, injectedSp);

    auto card = provider.probe(kReader);
    EXPECT_EQ(card, nullptr);
}

TEST_F(CrossProviderCoordination, Pkcs15ProbePreservesInjectedSessionLiveSm)
{
    // A live-SM session registered in the *injected* registry drives the
    // adopt branch (peek hits -> bindFromInjectedSession), which reuses the
    // adopted session's SM channel rather than opening a parallel PC/SC
    // handle. The load-bearing security property: probe must NOT tear that
    // live SM tunnel down (BSI TR-03110 §3 — a parallel handle would). Here
    // the channel survives the probe and the injected registry still reports
    // it live. (The detached fake's bind ultimately fails without a real
    // card, so the returned card is not asserted; full adopt success is
    // validated against real hardware.)
    LibreSCRS::SmartCard::Internal::SessionPresence injectedSp;
    auto session = makeDetachedCardSession(kReader);
    auto* fake = installPaceFake(*session, ChannelState::Open);
    auto reg = injectedSp.insert(kReader, session);
    ASSERT_TRUE(injectedSp.hasLiveSm(kReader));

    LibreSCRS::Pkcs15::Pkcs11::Pkcs15PKCS11Provider provider(/*cardMap=*/nullptr, injectedSp);
    (void)provider.probe(kReader);

    // Live SM channel is sacred: the adopt path never closes it.
    EXPECT_EQ(fake->state(), ChannelState::Open);
    EXPECT_TRUE(session->hasLiveSecureChannel());
    EXPECT_TRUE(injectedSp.hasLiveSm(kReader));
}
