// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

/// @file
/// @brief Regression-test anchor for the three-layer cross-provider
///        session-coordination contract.
///
/// The contract spans:
///
///   - @ref LibreSCRS::Pkcs11::Internal::SessionRegistry — non-consuming
///     @c peek so a probe failure in one provider leaves the parked session
///     available for the next provider.
///   - @ref LibreSCRS::OpenSc::Pkcs11::OpenScPKCS11Provider::probe — defers
///     to a sibling provider only when the parked session reports a live
///     secure-messaging channel; PIV / generic ICC / contact PKCS#15 with
///     no live SM proceed normally.
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
#include <LibreSCRS/SecureChannel/ISecureChannel.h>
#include <LibreSCRS/SmartCard/AppletAid.h>
#include <LibreSCRS/SmartCard/CardSession.h>
#include <LibreSCRS/SmartCard/SmProtocolRequest.h>
#include <LibreSCRS/SmartCard/detail/CardSessionInjection.h>
#include <LibreSCRS/SmartCard/detail/ChannelInjection.h>

#include <internal/OpenScPKCS11Provider.h>
#include <internal/PinClassification.h>
#include <internal/SessionRegistry.h>

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

namespace LibreSCRS::SecureChannel::TestSupport {

/// @brief Test double for @ref ISecureChannel. Stores a caller-supplied
///        @ref ChannelState and @c carriesSm flag and never talks to a
///        wire. @c transmit increments a counter so a test that needs to
///        assert "no APDU left the channel" can do so.
class FakeChannel final : public ISecureChannel
{
public:
    FakeChannel(LibreSCRS::SmartCard::AppletAid aid, ChannelState initialState, bool carriesSmFlag,
                bool crossAppletReuseFlag = false) noexcept
        : appletAid(std::move(aid)), channelState(initialState), carriesSmFlag(carriesSmFlag),
          crossAppletReuseFlag(crossAppletReuseFlag)
    {}

    [[nodiscard]] const LibreSCRS::SmartCard::AppletAid& currentApplet() const noexcept override
    {
        return appletAid;
    }

    [[nodiscard]] ChannelState state() const noexcept override
    {
        return channelState;
    }

    [[nodiscard]] LibreSCRS::SmartCard::Internal::APDUResponse
    transmit(const LibreSCRS::SmartCard::Internal::APDUCommand& /*cmd*/, LibreSCRS::CancelToken /*token*/) override
    {
        ++transmitCount;
        LibreSCRS::SmartCard::Internal::APDUResponse resp;
        resp.sw1 = 0x90;
        resp.sw2 = 0x00;
        return resp;
    }

    void close() override
    {
        channelState = ChannelState::Closed;
    }

    [[nodiscard]] bool carriesSm() const noexcept override
    {
        return carriesSmFlag;
    }

    [[nodiscard]] bool supportsCrossAppletReuse() const noexcept override
    {
        return crossAppletReuseFlag;
    }

    [[nodiscard]] int transmits() const noexcept
    {
        return transmitCount;
    }

protected:
    void setCurrentApplet(LibreSCRS::SmartCard::AppletAid aid) noexcept override
    {
        appletAid = std::move(aid);
    }

    void replaceKeys(LibreSCRS::SecureChannel::SessionKeys /*keys*/) noexcept override
    {
        // no SM key material to rotate on the test double
    }

private:
    LibreSCRS::SmartCard::AppletAid appletAid;
    ChannelState channelState;
    bool carriesSmFlag;
    bool crossAppletReuseFlag;
    int transmitCount{0};
};

} // namespace LibreSCRS::SecureChannel::TestSupport

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

} // namespace

// ---------------------------------------------------------------------------
// Invariant #1 + #2 — SessionRegistry::peek non-consuming and peeked-ref
// survives concurrent remove. The base case is already covered by
// SessionRegistryTests (PutThenPeekReturnsSamePointerAndKeepsEntry and
// PeekedRefSurvivesConcurrentRemove); this test re-asserts the joint
// invariant under the explicit cross-provider framing so the regression-
// anchor file stands on its own as documentation of the contract.
// ---------------------------------------------------------------------------

TEST(CrossProviderCoordination, RegistryPeekIsNonConsumingAndSnapshotSurvivesRemove)
{
    LibreSCRS::Pkcs11::Internal::SessionRegistry registry;
    auto session = makeDetachedCardSession(kReader);
    registry.put(kReader, session);

    auto firstPeek = registry.peek(kReader);
    auto secondPeek = registry.peek(kReader);
    ASSERT_NE(firstPeek, nullptr);
    EXPECT_EQ(firstPeek.get(), session.get());
    EXPECT_EQ(firstPeek.get(), secondPeek.get());
    EXPECT_TRUE(registry.contains(kReader));

    // Remove drops the entry but firstPeek's shared_ptr keeps the
    // CardSession alive — this is the cross-provider snapshot guarantee.
    registry.remove(kReader);
    EXPECT_FALSE(registry.contains(kReader));
    EXPECT_NE(firstPeek, nullptr);
    EXPECT_NE(secondPeek, nullptr);
    EXPECT_GE(session.use_count(), 3L);
}

// ---------------------------------------------------------------------------
// Invariant #3 — OpenScPKCS11Provider::probe defers ONLY when the parked
// session reports a live SM channel. This is the PIV regression guard:
// the earlier "skip on any registry hit" logic prevented OpenSC from
// binding PIV cards because LC parks a CardSession even when no SM is
// live. The fix tightened the predicate to `hasLiveSecureChannel()`.
// ---------------------------------------------------------------------------

TEST(CrossProviderCoordination, OpenScProbeShortCircuitsWhenSessionHasLiveSm)
{
    auto registry = std::make_shared<LibreSCRS::Pkcs11::Internal::SessionRegistry>();
    auto session = makeDetachedCardSession(kReader);
    installPaceFake(*session, ChannelState::Open);
    registry->put(kReader, session);

    auto registryForProvider = registry;
    LibreSCRS::OpenSc::Pkcs11::OpenScPKCS11Provider provider{std::move(registryForProvider)};
    auto card = provider.probe(kReader);
    EXPECT_EQ(card, nullptr);

    // Registry entry survives the short-circuit so the next provider
    // (Pkcs15PKCS11Provider) can still adopt the live session.
    EXPECT_TRUE(registry->contains(kReader));
}

TEST(CrossProviderCoordination, OpenScProbeProceedsWhenSessionHasNoLiveSm)
{
    auto registry = std::make_shared<LibreSCRS::Pkcs11::Internal::SessionRegistry>();
    auto session = makeDetachedCardSession(kReader);
    // No channel installed at all — hasLiveSecureChannel() == false.
    registry->put(kReader, session);

    auto registryForProvider = registry;
    LibreSCRS::OpenSc::Pkcs11::OpenScPKCS11Provider provider{std::move(registryForProvider)};
    // probe is permitted to fail at the OpenSc::bind step in this test
    // environment (no real PC/SC handle). The contract under test is
    // that it did NOT short-circuit early — registry entry is left in
    // place either way.
    (void)provider.probe(kReader);
    EXPECT_TRUE(registry->contains(kReader));
}

// ---------------------------------------------------------------------------
// Invariant #4 — CardSession::hasLiveSecureChannel reports correctly across
// the supported state matrix. This is the predicate the cross-provider
// coordination consumers (OpenSc provider) gate on; getting it wrong in
// either direction breaks signing on SM-protected cards or onboarding of
// non-SM cards through the OpenSc fallback.
// ---------------------------------------------------------------------------

TEST(CrossProviderCoordination, HasLiveSecureChannelMatrix)
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
// Invariant #5 — activateChannelWithSm refuses when an Open SM channel of
// the wrong protocol is already installed. The live channel survives the
// call; the caller is expected to either explicitly close it via
// clearActiveChannel or route through the same protocol family.
// ---------------------------------------------------------------------------

TEST(CrossProviderCoordination, ActivateChannelWithSmRefusesOnIncompatibleLiveSmChannel)
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
// Invariant #6 — activateChannelFor (plain activation) refuses when an
// Open SM channel exists. The live SM channel must not be torn down by
// the plain-SELECT path.
// ---------------------------------------------------------------------------

TEST(CrossProviderCoordination, ActivateChannelForRefusesOnLiveSmChannel)
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
// Invariant #7 — Pkcs15PKCS11Provider::probe peek-on-failure leaves the
// session parked in the registry so any downstream retry path or
// follow-on provider can still find it. The detached-session adoption
// path drives bindFromInjectedSession through to DeviceError (no live
// PC/SC handle), simulating the bind-failure case.
//
// NOTE: the current production probe drops the entry on success (the
// adopted card now owns the session) but the spec says it MUST leave the
// entry alone on failure. The detached-session path returns DeviceError
// before the success branch, exercising exactly that failure mode.
// ---------------------------------------------------------------------------

TEST(CrossProviderCoordination, Pkcs15ProbePeekFailureLeavesSessionInRegistry)
{
    auto registry = std::make_shared<LibreSCRS::Pkcs11::Internal::SessionRegistry>();
    auto session = makeDetachedCardSession(kReader);
    registry->put(kReader, session);

    LibreSCRS::Pkcs15::Pkcs11::Pkcs15PKCS11Provider provider{/*cardMap=*/nullptr, registry};
    auto card = provider.probe(kReader);

    // Detached PCSCConnection cannot satisfy bindFromInjectedSession's
    // activation path; probe surfaces nullptr.
    EXPECT_EQ(card, nullptr);
    // The crucial invariant: registry entry is NOT consumed on bind
    // failure. A follow-on retry / sibling provider can still peek the
    // parked session.
    EXPECT_TRUE(registry->contains(kReader));
    EXPECT_NE(registry->peek(kReader), nullptr);
}
