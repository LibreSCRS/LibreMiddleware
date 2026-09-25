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
///
/// @par Why a counting PC/SC provider, and not a null card
/// The deferral assertions used to read "probe returned nullptr", which is
/// also what binding returns when there is no card — and there never is one
/// here. Deleting the short-circuit under test left the suite green. OpenSC
/// reaches PC/SC through a library it dlopens by name, so pointing
/// OPENSC_CONF at a counting provider makes the question answerable directly:
/// did OpenSC establish a context and open a handle, or not.

#include "pkcs15_pkcs11_card.h"

#include "apdu.h"
#include "chip_auth_card_oracle.h"
#include <pcsc_connection.h>

#include <LibreSCRS/Secure/Buffer.h>
#include <LibreSCRS/Secure/String.h>
#include <LibreSCRS/SecureChannel/BacParams.h>
#include <LibreSCRS/SecureChannel/ChannelErrors.h>
#include <LibreSCRS/SmartCard/detail/Unwrap.h>
#include <LibreSCRS_internal/SecureChannel/ChipAuthChannel.h>
#include <LibreSCRS_internal/SecureChannel/ISecureChannel.h>
#include <LibreSCRS_internal/SecureChannel/SessionKeys.h>
#include <LibreSCRS_internal/SmartCard/SessionPresence.h>
#include <LibreSCRS_internal/SmartCard/SmartCardServices.h>
#include <LibreSCRS/SmartCard/AppletAid.h>
#include <LibreSCRS/SmartCard/CardSession.h>
#include <LibreSCRS/SmartCard/SmProtocolRequest.h>
#include <LibreSCRS/SmartCard/detail/CardSessionInjection.h>
#include <LibreSCRS/SmartCard/detail/ChannelInjection.h>

#include "fake_channel.h"

#include "counting_pcsc_shim.h"

#include <internal/OpenScPKCS11Provider.h>
#include <internal/PinClassification.h>

#include "pkcs15_types.h"

#include <gtest/gtest.h>

#include <dlfcn.h>

#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

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

// A structurally valid four-byte T=1 ATR. Nothing is expected to recognise it;
// the reader layer only has to be willing to hand it on.
constexpr const char* kShimAtr = "3B800181";

// A dlopen-ed view of the counting provider OpenSC loads.
//
// Process-wide and kept open for the life of the binary on purpose: OpenSC
// dlopens and dlcloses the same path around each context, and if this view let
// go between cases the mapping would be unloaded and the counters would come
// back zeroed for a reason that has nothing to do with what was measured.
class CountingShim
{
public:
    CountingShim()
    {
        handle = ::dlopen(LIBRESCRS_PCSC_SHIM_PATH, RTLD_LAZY | RTLD_LOCAL);
        if (handle == nullptr) {
            const char* why = ::dlerror();
            error = (why != nullptr) ? why : "dlopen failed";
            return;
        }
        countsFn = reinterpret_cast<CountsFn>(::dlsym(handle, "librescrs_shim_counts"));
        openHandlesFn = reinterpret_cast<OpenHandlesFn>(::dlsym(handle, "librescrs_shim_open_handles"));
        resetFn = reinterpret_cast<ResetFn>(::dlsym(handle, "librescrs_shim_reset"));
        listReadersFn = reinterpret_cast<ListReadersFn>(::dlsym(handle, "SCardListReaders"));
        connectFn = reinterpret_cast<ConnectFn>(::dlsym(handle, "SCardConnect"));
        statusFn = reinterpret_cast<StatusFn>(::dlsym(handle, "SCardStatus"));
        disconnectFn = reinterpret_cast<DisconnectFn>(::dlsym(handle, "SCardDisconnect"));
        if (countsFn == nullptr || openHandlesFn == nullptr || resetFn == nullptr || listReadersFn == nullptr ||
            connectFn == nullptr || statusFn == nullptr || disconnectFn == nullptr)
            error = "the counting provider is missing one of its entry points";
    }

    CountingShim(const CountingShim&) = delete;
    CountingShim& operator=(const CountingShim&) = delete;

    [[nodiscard]] bool loaded() const
    {
        return error.empty();
    }
    [[nodiscard]] const std::string& why() const
    {
        return error;
    }

    [[nodiscard]] LibrescrsShimCounts counts(const char* reader) const
    {
        return countsFn(reader);
    }
    [[nodiscard]] unsigned long openHandles() const
    {
        return openHandlesFn();
    }
    void reset() const
    {
        resetFn();
    }

    /// @brief The provider's own SCardListReaders, for the two-call case below.
    [[nodiscard]] LONG listReaders(char* buffer, DWORD* length) const
    {
        return listReadersFn(0, nullptr, buffer, length);
    }

    [[nodiscard]] LONG connect(const char* reader, SCARDHANDLE* card) const
    {
        DWORD activeProtocol = 0;
        return connectFn(0, reader, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T1, card, &activeProtocol);
    }
    [[nodiscard]] LONG status(SCARDHANDLE card, char* name, DWORD* nameLength, unsigned char* atr,
                              DWORD* atrLength) const
    {
        return statusFn(card, name, nameLength, nullptr, nullptr, atr, atrLength);
    }
    [[nodiscard]] LONG disconnect(SCARDHANDLE card) const
    {
        return disconnectFn(card, SCARD_LEAVE_CARD);
    }

private:
    using CountsFn = LibrescrsShimCounts (*)(const char*);
    using OpenHandlesFn = unsigned long (*)();
    using ResetFn = void (*)();
    using ListReadersFn = LONG (*)(SCARDCONTEXT, const char*, char*, DWORD*);
    using ConnectFn = LONG (*)(SCARDCONTEXT, const char*, DWORD, DWORD, SCARDHANDLE*, DWORD*);
    using StatusFn = LONG (*)(SCARDHANDLE, char*, DWORD*, DWORD*, DWORD*, unsigned char*, DWORD*);
    using DisconnectFn = LONG (*)(SCARDHANDLE, DWORD);

    void* handle = nullptr;
    CountsFn countsFn = nullptr;
    OpenHandlesFn openHandlesFn = nullptr;
    ResetFn resetFn = nullptr;
    ListReadersFn listReadersFn = nullptr;
    ConnectFn connectFn = nullptr;
    StatusFn statusFn = nullptr;
    DisconnectFn disconnectFn = nullptr;
    std::string error;
};

const CountingShim& shim()
{
    static const CountingShim view;
    return view;
}

// Point OpenSC at the counting provider. The configuration file is written into
// the shim's own directory in the build tree -- beside the library it names, and
// never under /tmp, which is RAM on this project's machines.
void installCountingPcscProvider()
{
    static const std::string confPath = [] {
        const std::filesystem::path shimPath{LIBRESCRS_PCSC_SHIM_PATH};
        const std::filesystem::path conf = shimPath.parent_path() / "opensc-counting-shim.conf";
        std::ofstream out(conf);
        out << "app default {\n"
            << "    reader_driver pcsc {\n"
            << "        provider_library = \"" << shimPath.string() << "\";\n"
            << "    }\n"
            << "}\n";
        return conf.string();
    }();

    ::setenv("OPENSC_CONF", confPath.c_str(), 1);
    // ';'-separated, not the PC/SC multi-string's NUL: setenv takes a C string,
    // so a NUL byte would end the value. The provider builds the multi-string.
    ::setenv("LIBRESCRS_SHIM_READERS", kReader, 1);
    ::setenv("LIBRESCRS_SHIM_ATR", kShimAtr, 1);
}

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
        ASSERT_TRUE(shim().loaded()) << shim().why();
        installCountingPcscProvider();
        shim().reset();
    }

    void TearDown() override
    {
        shim().reset();
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

    // The load-bearing assertion, and the reason this suite loads a counting
    // PC/SC provider: a null return is what binding without a card returns too,
    // so it says nothing about whether the provider deferred. Establishing a
    // PC/SC context is the first thing OpenSC does and the first thing that
    // would disturb a live secure channel; zero of them is the invariant.
    EXPECT_EQ(shim().counts(nullptr).establishContext, 0u);

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

    // The positive control for the assertion above: with no live secure channel
    // the provider goes all the way to the PC/SC layer. Without this half, a
    // provider that short-circuited unconditionally would pass the case above.
    //
    // Two handles, pinned as measured rather than assumed: OpenSC opens one
    // while enumerating readers, to probe the reader's features, and one to
    // connect to the card. Both are closed before probe returns, which is the
    // half of the contract the deferral cases cannot show.
    const auto seen = shim().counts(kReader);
    EXPECT_EQ(seen.establishContext, 1u);
    EXPECT_EQ(seen.connect, 2u);
    EXPECT_EQ(shim().openHandles(), 0u) << "every handle this probe opened must be closed on return";
    EXPECT_FALSE(sessionPresence().hasLiveSm(kReader));
}

// ---------------------------------------------------------------------------
// The counting provider is itself a measuring instrument, so its own answers
// have to be right. PC/SC's two-call convention is where a provider gets this
// wrong invisibly: every caller that first asks for the length and then passes
// a buffer of exactly that size cannot tell a provider that reports the length
// of the data from one that echoes the buffer size back. A caller with a LARGER
// buffer can, and OpenSC is such a caller in places.
// ---------------------------------------------------------------------------

TEST_F(CrossProviderCoordination, CountingProviderReportsTheDataLengthNotTheBufferSize)
{
    DWORD needed = 0;
    ASSERT_EQ(shim().listReaders(nullptr, &needed), SCARD_S_SUCCESS);
    // One reader name, its NUL, and the multi-string's own terminator.
    ASSERT_EQ(needed, static_cast<DWORD>(std::strlen(kReader) + 2));

    std::vector<char> oversized(needed + 64, '\x7F');
    DWORD given = static_cast<DWORD>(oversized.size());
    ASSERT_EQ(shim().listReaders(oversized.data(), &given), SCARD_S_SUCCESS);
    EXPECT_EQ(given, needed) << "a provider that reports the buffer size hides a length bug";
    EXPECT_STREQ(oversized.data(), kReader);
    EXPECT_EQ(oversized[std::strlen(kReader) + 1], '\0') << "the multi-string must be doubly terminated";

    std::vector<char> tooSmall(needed - 1, '\x7F');
    DWORD small = static_cast<DWORD>(tooSmall.size());
    EXPECT_EQ(shim().listReaders(tooSmall.data(), &small), SCARD_E_INSUFFICIENT_BUFFER);
    EXPECT_EQ(small, needed);
}

TEST_F(CrossProviderCoordination, CountingProviderReportsTheStatusLengthsNotTheBufferSizes)
{
    // SCardStatus carries the same convention twice over, for the reader name
    // and for the ATR, and in this suite's path the reader driver takes the ATR
    // from SCardGetStatusChange instead -- so a length bug here would be
    // invisible in both directions unless something asks on purpose.
    SCARDHANDLE card = 0;
    ASSERT_EQ(shim().connect(kReader, &card), SCARD_S_SUCCESS);

    DWORD nameNeeded = 0;
    DWORD atrNeeded = 0;
    ASSERT_EQ(shim().status(card, nullptr, &nameNeeded, nullptr, &atrNeeded), SCARD_S_SUCCESS);
    ASSERT_EQ(nameNeeded, static_cast<DWORD>(std::strlen(kReader) + 1));
    ASSERT_GT(atrNeeded, 0u);

    std::vector<char> name(nameNeeded + 64, '\x7F');
    std::vector<unsigned char> atr(atrNeeded + 64, 0x7Fu);
    DWORD nameGiven = static_cast<DWORD>(name.size());
    DWORD atrGiven = static_cast<DWORD>(atr.size());
    ASSERT_EQ(shim().status(card, name.data(), &nameGiven, atr.data(), &atrGiven), SCARD_S_SUCCESS);
    EXPECT_EQ(nameGiven, nameNeeded) << "the reader name length must be the data's, not the buffer's";
    EXPECT_EQ(atrGiven, atrNeeded) << "the ATR length must be the data's, not the buffer's";
    EXPECT_STREQ(name.data(), kReader);

    std::vector<char> shortName(nameNeeded - 1, '\x7F');
    DWORD shortGiven = static_cast<DWORD>(shortName.size());
    DWORD atrAgain = static_cast<DWORD>(atr.size());
    EXPECT_EQ(shim().status(card, shortName.data(), &shortGiven, atr.data(), &atrAgain), SCARD_E_INSUFFICIENT_BUFFER);
    EXPECT_EQ(shortGiven, nameNeeded);

    EXPECT_EQ(shim().disconnect(card), SCARD_S_SUCCESS);
    EXPECT_EQ(shim().openHandles(), 0u);
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

// A live Chip Authentication tunnel (from a prior eMRTD contact read) must be
// RIDDEN by the PKCS#15 adopt path, not refused: the acquire now derives its
// SM request from the session's recorded protocol, so activateChannelWithSm
// takes the wrapped-SELECT reuse path instead of refusing a hardcoded
// PaceRequest against a ChipAuthChannel. Proven by the card seeing the wrapped
// SELECT (the oracle verifies its MAC) and the tunnel surviving.
TEST_F(CrossProviderCoordination, Pkcs15AdoptRidesLiveChipAuthTunnel)
{
    LibreSCRS::SmartCard::Internal::SessionPresence injectedSp;
    auto session = makeDetachedCardSession(kReader);

    // Wire an AES SM oracle behind the detached connection so the wrapped
    // SELECT the reuse path issues round-trips.
    auto oracle = std::make_shared<LibreSCRS::Test::AesSmCardOracle>(
        std::vector<std::uint8_t>(16, 0x11), std::vector<std::uint8_t>(16, 0x22), std::vector<std::uint8_t>(16, 0x00));
    LibreSCRS::SmartCard::detail::unwrap(*session).setDetachedRawResponder(
        [oracle](std::span<const std::uint8_t> w) { return oracle->respond(w); });

    // Install a real ChipAuthChannel (dynamic_cast in channelMatchesProtocol
    // requires the concrete type) bound to the eMRTD applet, recorded as a
    // ChipAuthRequest — the state a plain→CA upgrade leaves.
    LibreSCRS::SecureChannel::SessionKeys keys;
    keys.encKey = LibreSCRS::Secure::Buffer{16, 0x11};
    keys.macKey = LibreSCRS::Secure::Buffer{16, 0x22};
    keys.ssc = LibreSCRS::Secure::Buffer{16, 0x00};
    keys.cipher = LibreSCRS::SecureChannel::SmCipher::Aes;
    auto ca = std::make_unique<LibreSCRS::SecureChannel::ChipAuthChannel>(
        LibreSCRS::SmartCard::detail::unwrap(*session), makeAid(), std::move(keys));
    ChannelInjector::installForTesting(*session, std::move(ca),
                                       SmProtocolRequest{LibreSCRS::SmartCard::ChipAuthRequest{}});

    auto reg = injectedSp.insert(kReader, session);
    ASSERT_TRUE(injectedSp.hasLiveSm(kReader));

    LibreSCRS::Pkcs15::Pkcs11::Pkcs15PKCS11Provider provider(/*cardMap=*/nullptr, injectedSp);
    (void)provider.probe(kReader);

    // The wrapped SELECT to the PKCS#15 applet reached the card over the CA
    // tunnel (had the request been refused Internal, no APDU would have gone
    // out), and the tunnel is untouched.
    EXPECT_GT(oracle->verifiedCommands(), 0)
        << "the PKCS#15 acquire must ride the CA tunnel with a wrapped SELECT, not refuse it";
    EXPECT_TRUE(session->hasLiveSecureChannel());
}

// Riding a live Chip Authentication tunnel proves plain readability, not PACE:
// a ChipAuthRequest is only ever recorded by a plain→CA upgrade, so the adopt
// must NOT latch the PACE requirement off that success. Latched, every later
// per-op acquire would fall back to PACE-CAN once the tunnel dies — on a
// contact interface that cannot satisfy it — instead of the plain activation
// that provably works; while the tunnel lives, the plain path's cross-applet
// reuse rides it anyway.
TEST_F(CrossProviderCoordination, AdoptOverChipAuthTunnelDoesNotLatchPaceRequirement)
{
    auto session = makeDetachedCardSession(kReader);

    auto oracle = std::make_shared<LibreSCRS::Test::AesSmCardOracle>(
        std::vector<std::uint8_t>(16, 0x11), std::vector<std::uint8_t>(16, 0x22), std::vector<std::uint8_t>(16, 0x00));
    LibreSCRS::SmartCard::detail::unwrap(*session).setDetachedRawResponder(
        [oracle](std::span<const std::uint8_t> w) { return oracle->respond(w); });

    LibreSCRS::SecureChannel::SessionKeys keys;
    keys.encKey = LibreSCRS::Secure::Buffer{16, 0x11};
    keys.macKey = LibreSCRS::Secure::Buffer{16, 0x22};
    keys.ssc = LibreSCRS::Secure::Buffer{16, 0x00};
    keys.cipher = LibreSCRS::SecureChannel::SmCipher::Aes;
    auto ca = std::make_unique<LibreSCRS::SecureChannel::ChipAuthChannel>(
        LibreSCRS::SmartCard::detail::unwrap(*session), makeAid(), std::move(keys));
    ChannelInjector::installForTesting(*session, std::move(ca),
                                       SmProtocolRequest{LibreSCRS::SmartCard::ChipAuthRequest{}});

    auto card = std::make_shared<LibreSCRS::Pkcs15::Pkcs11::Pkcs15Card>();
    (void)card->bindFromInjectedSession(kReader, session);

    EXPECT_GT(oracle->verifiedCommands(), 0) << "the bind must still ride the tunnel with a wrapped SELECT";
    EXPECT_FALSE(card->needsPaceFlag()) << "a CA tunnel is evidence of plain readability, not of PACE";
}
