// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

/// @file
/// @brief Regression-test anchor for the session-coordination contract that
///        keeps a live PACE/BAC SM tunnel from being invalidated.
///
/// The contract spans:
///
///   - @ref LibreSCRS::SmartCard::CardSession — refuses to corrupt a live
///     SM tunnel from @c activateChannelWithSm (protocol mismatch) or
///     @c activateChannelFor (plain activation requested while an Open SM
///     channel is installed). Both surface
///     @ref LibreSCRS::SecureChannel::ChannelActivationError::Internal
///     rather than tearing the tunnel down.
///   - the OpenSC card plugin — reaches the card only through the session it
///     is handed, never through a PC/SC connection of its own.
///
/// @par Why a counting PC/SC provider, and not a null card
/// The deferral assertions used to read "probe returned nullptr", which is
/// also what binding returns when there is no card — and there never is one
/// here. Deleting the short-circuit under test left the suite green. OpenSC
/// reaches PC/SC through a library it dlopens by name, so pointing
/// OPENSC_CONF at a counting provider makes the question answerable directly:
/// did OpenSC establish a context and open a handle, or not.

#include "apdu.h"
#include "chip_auth_card_oracle.h"
#include <pcsc_connection.h>

#include <LibreSCRS/Plugin/CardPluginService.h>
#include <LibreSCRS/Secure/Buffer.h>
#include <LibreSCRS/Secure/String.h>
#include <LibreSCRS/SecureChannel/BacParams.h>
#include <LibreSCRS/SecureChannel/ChannelErrors.h>
#include <LibreSCRS/SmartCard/detail/Unwrap.h>
#include <LibreSCRS_internal/SecureChannel/ChipAuthChannel.h>
#include <LibreSCRS_internal/SecureChannel/ISecureChannel.h>
#include <LibreSCRS_internal/SecureChannel/SessionKeys.h>
#include <LibreSCRS/SmartCard/AppletAid.h>
#include <LibreSCRS/SmartCard/CardSession.h>
#include <LibreSCRS/SmartCard/SmProtocolRequest.h>
#include <LibreSCRS/SmartCard/testing/CardSessionTesting.h>
#include <LibreSCRS/SmartCard/detail/ChannelInjection.h>

#include "fake_channel.h"

#include "counting_pcsc_shim.h"

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

namespace {

using LibreSCRS::SecureChannel::ChannelActivationError;
using LibreSCRS::SecureChannel::ChannelState;
using LibreSCRS::SecureChannel::TestSupport::FakeChannel;
using LibreSCRS::SmartCard::AppletAid;
using LibreSCRS::SmartCard::CardSession;
using LibreSCRS::SmartCard::PaceRequest;
using LibreSCRS::SmartCard::SmProtocolRequest;
using LibreSCRS::SmartCard::detail::ChannelInjector;
using LibreSCRS::SmartCard::Testing::makeDetachedCardSession;

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
// The OpenSC card plugin carries its own copy of OpenSC, and that copy has no
// PC/SC reader driver: the plugin talks to the card only through the session it
// is handed. The counting provider is
// configured here, and a probe through the plugin must not reach it at all --
// not to enumerate readers, and not to connect to the one being probed. A
// plugin linked against the PC/SC-enabled OpenSC build loads the provider while creating
// its context and turns this red.
// ---------------------------------------------------------------------------

TEST_F(CrossProviderCoordination, OpenScPluginProbeReachesNoPcscProvider)
{
    LibreSCRS::Plugin::CardPluginService registry{std::filesystem::path{PLUGIN_DIR}};
    std::shared_ptr<LibreSCRS::Plugin::CardPlugin> opensc;
    for (const auto& p : registry.plugins()) {
        if (p->pluginId() == "opensc")
            opensc = p;
    }
    ASSERT_NE(opensc, nullptr) << "the OpenSC card plugin is not in " << PLUGIN_DIR;

    auto session = makeDetachedCardSession(kReader);
    const std::vector<std::uint8_t> atr{0x3B, 0x80, 0x01, 0x81};
    // A detached session answers no APDU, so the plugin declines the card; it
    // gets that far only after creating its OpenSC context, which is the step
    // that used to reach the provider (a plugin relinked against the PC/SC copy
    // turns the counts below red).
    EXPECT_FALSE(opensc->canHandleConnection(atr, *session));

    const auto seen = shim().counts(nullptr);
    EXPECT_EQ(seen.establishContext, 0u);
    EXPECT_EQ(seen.listReaders, 0u);
    EXPECT_EQ(seen.connect, 0u);
    EXPECT_EQ(shim().openHandles(), 0u);
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
