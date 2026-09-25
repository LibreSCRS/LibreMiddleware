// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

/// @file
/// @brief A census of the PC/SC handles one document signature opens.
///
/// Signing a document today loads the PKCS#11 module into the signing process
/// and asks it for its slots, and the module probes every reader the PC/SC
/// layer reports. On a reader whose session carries no live secure channel that
/// probe opens a second handle to the card the caller is already talking to,
/// and on every other reader it opens one the caller never asked about.
///
/// This test pins those numbers as measured. It is not a wish: the counts below
/// record a known violation, so an intended change moves them deliberately and
/// an unintended one is visible. When signing stops loading a PKCS#11 module in
/// this process these counts become zero.
///
/// @par What it cannot tell you
/// It counts handles; it says nothing about what a handle does to a card,
/// because there is no card here. The numbers are also those of a signature
/// whose bind FAILS — the counting provider answers every APDU with 6A 82 — so
/// a handle opened only on the path where the bind succeeds would not move
/// them. Both limits are stated in `CHANGELOG.md` under known limitations, and
/// closing them needs hardware, not another in-process test.
///
/// A third limit is the configuration: this file WRITES the OPENSC_CONF it
/// measures against, so every number here is a number for the reader driver's own
/// defaults. A host's `/etc/opensc.conf` can set `connect_exclusive`,
/// `disconnect_action` or `provider_library`, which change the bind path without
/// moving any count in this file.
///
/// @par How the two PC/SC layers are told apart
/// There are two paths to PC/SC in this picture and they must be counted
/// separately. The counting provider is therefore present twice, once per path,
/// from one source:
///   * compiled INTO this executable, where its definitions preempt the
///     middleware's own SCardConnect and friends for every library in the
///     process -- that is the "stub" below, and it counts the middleware's own
///     opens, including the PKCS#11 module's copy of them;
///   * as a shared object OpenSC dlopens through the OPENSC_CONF this test
///     writes -- that is the "shim" below, reached through dlsym on the handle
///     so it answers about its own globals, and it counts what OpenSC does.
/// dlopen and dlclose are interposed the same way, which is how the module's
/// own load and unload become observable from outside it. A linker --wrap would
/// not do: the call that loads the module is made inside the signing library,
/// and --wrap only redirects references in the objects it links.

#include "counting_pcsc_shim.h"
#include "fake_channel.h"

#include <LibreSCRS/Auth/AuthRequirement.h>
#include <LibreSCRS/Auth/CredentialProvider.h>
#include <LibreSCRS/Auth/CredentialResult.h>
#include <LibreSCRS/Plugin/CardPlugin.h>
#include <LibreSCRS/Signing/Enums.h>
#include <LibreSCRS/Signing/SigningRequest.h>
#include <LibreSCRS/Signing/SigningService.h>
#include <LibreSCRS/SmartCard/AppletAid.h>
#include <LibreSCRS/SmartCard/CardSession.h>
#include <LibreSCRS/SmartCard/detail/CardSessionInjection.h>
#include <LibreSCRS/SmartCard/detail/ChannelInjection.h>
#include <LibreSCRS/Trust/TrustStoreService.h>
#include <LibreSCRS_internal/SmartCard/SessionPresence.h>
#include <LibreSCRS_internal/SmartCard/SmartCardServices.h>

#include <gtest/gtest.h>

#include <dlfcn.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <memory>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

// ---------------------------------------------------------------------------
// dlopen / dlclose interposition
// ---------------------------------------------------------------------------

namespace {
// A dlopen can arrive from another thread in this process -- OpenSSL providers
// and p11-kit both load on demand -- so the three records below are guarded.
// g_liveHandles also has to shrink on dlclose: the loader reuses an address, and
// a stale entry would attribute a later handle to an earlier path.
std::mutex g_dlMutex;
std::vector<std::string> g_dlopened;
std::vector<std::string> g_dlclosed;
std::vector<std::pair<void*, std::string>> g_liveHandles;

void resetDlRecords()
{
    const std::scoped_lock lock(g_dlMutex);
    g_dlopened.clear();
    g_dlclosed.clear();
}

std::size_t countContaining(const std::vector<std::string>& paths, std::string_view needle)
{
    const std::scoped_lock lock(g_dlMutex);
    return static_cast<std::size_t>(std::count_if(
        paths.begin(), paths.end(), [needle](const std::string& p) { return p.find(needle) != std::string::npos; }));
}
} // namespace

extern "C" void* dlopen(const char* path, int flags)
{
    using Fn = void* (*)(const char*, int);
    static Fn real = reinterpret_cast<Fn>(::dlsym(RTLD_NEXT, "dlopen"));
    void* handle = real(path, flags);
    if (path != nullptr) {
        const std::scoped_lock lock(g_dlMutex);
        g_dlopened.emplace_back(path);
        if (handle != nullptr)
            g_liveHandles.emplace_back(handle, path);
    }
    return handle;
}

extern "C" int dlclose(void* handle)
{
    using Fn = int (*)(void*);
    static Fn real = reinterpret_cast<Fn>(::dlsym(RTLD_NEXT, "dlclose"));
    {
        const std::scoped_lock lock(g_dlMutex);
        for (auto it = g_liveHandles.begin(); it != g_liveHandles.end(); ++it) {
            if (it->first == handle) {
                g_dlclosed.push_back(it->second);
                g_liveHandles.erase(it);
                break;
            }
        }
    }
    return real(handle);
}

// ---------------------------------------------------------------------------

namespace {

using LibreSCRS::SecureChannel::ChannelState;
using LibreSCRS::SecureChannel::TestSupport::FakeChannel;
using LibreSCRS::SmartCard::AppletAid;
using LibreSCRS::SmartCard::CardSession;
using LibreSCRS::SmartCard::detail::ChannelInjector;
using LibreSCRS::SmartCard::detail::makeDetachedCardSession;
using LibreSCRS::SmartCard::Internal::ensureSessionPresenceInitialised;
using LibreSCRS::SmartCard::Internal::sessionPresence;
using LibreSCRS::SmartCard::Internal::shutdownSessionPresenceForTest;

// Three readers: one carrying a live secure channel, one the signature targets,
// and one neither the caller nor the signature has any business with.
constexpr const char* kSmReader = "R-A";
constexpr const char* kTargetReader = "R-B";
constexpr const char* kNeighbourReader = "R-C";
constexpr const char* kShimAtr = "3B800181";
constexpr const char* kModuleName = "librescrs-pkcs11";

/// @brief OpenSC's copy of the counting provider, reached by handle so its own
///        globals answer rather than this executable's.
class OpenScSideShim
{
public:
    OpenScSideShim()
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
        if (countsFn == nullptr || openHandlesFn == nullptr || resetFn == nullptr)
            error = "the counting provider is missing one of its entry points";
    }

    OpenScSideShim(const OpenScSideShim&) = delete;
    OpenScSideShim& operator=(const OpenScSideShim&) = delete;

    [[nodiscard]] bool loaded() const
    {
        return error.empty();
    }
    [[nodiscard]] const std::string& why() const
    {
        return error;
    }
    [[nodiscard]] unsigned long connect(const char* reader) const
    {
        return countsFn(reader).connect;
    }
    [[nodiscard]] unsigned long establishContext() const
    {
        return countsFn(nullptr).establishContext;
    }
    [[nodiscard]] unsigned long openHandles() const
    {
        return openHandlesFn();
    }
    void reset() const
    {
        resetFn();
    }

private:
    using CountsFn = LibrescrsShimCounts (*)(const char*);
    using OpenHandlesFn = unsigned long (*)();
    using ResetFn = void (*)();

    void* handle = nullptr;
    CountsFn countsFn = nullptr;
    OpenHandlesFn openHandlesFn = nullptr;
    ResetFn resetFn = nullptr;
    std::string error;
};

const OpenScSideShim& shim()
{
    static const OpenScSideShim view;
    return view;
}

/// @brief This executable's own copy: the PC/SC layer the middleware reaches.
unsigned long stubConnect(const char* reader)
{
    return librescrs_shim_counts(reader).connect;
}

AppletAid makeAid()
{
    return AppletAid{0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01};
}

class StubPkiPlugin : public LibreSCRS::Plugin::CardPlugin
{
public:
    StubPkiPlugin()
    {
        setIdentity("stub-pki", "Stub PKI", /*priority=*/1000);
    }
    LibreSCRS::Plugin::CardCapabilities capabilities() const override
    {
        return LibreSCRS::Plugin::CardCapabilities::PKI;
    }
    std::span<const LibreSCRS::Plugin::Atr> supportedAtrs() const noexcept override
    {
        static constexpr std::array<LibreSCRS::Plugin::Atr, 0> kAtrs{};
        return kAtrs;
    }
    LibreSCRS::Plugin::ReadResult doReadCard(LibreSCRS::SmartCard::CardSession&, GroupCallback) const override
    {
        return LibreSCRS::Plugin::ReadResult::ok(LibreSCRS::Plugin::CardData{});
    }
    LibreSCRS::Plugin::CredentialCounters readCounters(LibreSCRS::SmartCard::CardSession&,
                                                       std::string_view) const override
    {
        return {};
    }
};

std::shared_ptr<LibreSCRS::Signing::SigningService> makeSigningService()
{
    LibreSCRS::Trust::TrustConfig trust;
    trust.trustedListSources.push_back({"https://www.mit.gov.rs/TrustedList/TSL-RS.xml", false, false});
    auto trustResult = LibreSCRS::Trust::TrustStoreService::create(std::move(trust));
    if (!trustResult.has_value())
        return nullptr;
    return std::make_shared<LibreSCRS::Signing::SigningService>(*trustResult, LibreSCRS::Signing::TsaProvider{});
}

LibreSCRS::Signing::SigningRequest makeBufferRequest()
{
    LibreSCRS::Signing::SigningRequest::Builder b;
    b.format(LibreSCRS::Signing::SignatureFormat::Pades)
        .level(LibreSCRS::Signing::SignatureLevel::B_B)
        .packaging(LibreSCRS::Signing::PackagingMode::Enveloped);
    return std::move(b).buildForBufferSign();
}

/// @brief Sign a buffer through the facade and return the public outcome.
LibreSCRS::Signing::SigningResult signOnce(const std::shared_ptr<LibreSCRS::Signing::SigningService>& svc,
                                           const std::shared_ptr<CardSession>& session)
{
    auto request = makeBufferRequest();
    auto provider = [](const LibreSCRS::Auth::AuthRequirement&) {
        std::vector<LibreSCRS::Auth::CredentialEntry> values;
        values.emplace_back("pin", LibreSCRS::Secure::String{"0000"});
        return LibreSCRS::Auth::CredentialResult::ok(std::move(values));
    };
    auto plugin = std::make_shared<StubPkiPlugin>();
    // A %PDF- prefix clears the fail-fast document pre-check so the pipeline
    // reaches the backend instead of rejecting the bytes.
    static const std::vector<std::uint8_t> document{'%', 'P', 'D', 'F', '-', '1', '.', '7', '\n', '%', 0xE2, 0xE3};
    return svc->sign(request, std::span<const std::uint8_t>{document}, provider, plugin, session);
}

void setReaderSet(const std::string& semicolonSeparated)
{
    ::setenv("LIBRESCRS_SHIM_READERS", semicolonSeparated.c_str(), 1);
}

/// @brief Point OpenSC at the counting provider, and the signing facade at the
///        PKCS#11 module this build produced.
void installCountingProviders()
{
    static const std::string confPath = [] {
        const std::filesystem::path shimPath{LIBRESCRS_PCSC_SHIM_PATH};
        const std::filesystem::path conf = shimPath.parent_path() / "opensc-census-shim.conf";
        std::ofstream out(conf);
        out << "app default {\n"
            << "    reader_driver pcsc {\n"
            << "        provider_library = \"" << shimPath.string() << "\";\n"
            << "    }\n"
            << "}\n";
        return conf.string();
    }();

    ::setenv("OPENSC_CONF", confPath.c_str(), 1);
    ::setenv("LIBRESCRS_SHIM_ATR", kShimAtr, 1);
    ::setenv("LIBRESCRS_PKCS11_MODULE", LIBRESCRS_PKCS11_MODULE_PATH, 1);
    setReaderSet(std::string{kSmReader} + ";" + kTargetReader + ";" + kNeighbourReader);
}

class PcscHandleCensusPinsKnownSecondHandleTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        ensureSessionPresenceInitialised();
        shutdownSessionPresenceForTest();
        ASSERT_TRUE(shim().loaded()) << shim().why();
        installCountingProviders();
        shim().reset();
        librescrs_shim_reset();
        resetDlRecords();

        service = makeSigningService();
        ASSERT_NE(service, nullptr);

        // Handle #1 in the census: the session the caller is already holding on
        // the reader the signature targets. Detached, so it performs no PC/SC
        // call of its own and every count below is the signature's.
        target = makeDetachedCardSession(kTargetReader);

        // A neighbour whose session carries a live secure channel, registered in
        // the process-wide presence registry the module's providers consult.
        smSession = makeDetachedCardSession(kSmReader);
        ChannelInjector::installForTesting(
            *smSession, std::make_unique<FakeChannel>(makeAid(), ChannelState::Open, /*carriesSm=*/true));
        registration = sessionPresence().insert(kSmReader, smSession);
        ASSERT_TRUE(sessionPresence().hasLiveSm(kSmReader));
    }

    void TearDown() override
    {
        shim().reset();
        librescrs_shim_reset();
    }

    std::shared_ptr<LibreSCRS::Signing::SigningService> service;
    std::shared_ptr<CardSession> target;
    std::shared_ptr<CardSession> smSession;
    LibreSCRS::SmartCard::Internal::SessionPresence::Registration registration;
};

} // namespace

TEST_F(PcscHandleCensusPinsKnownSecondHandleTest, DocumentSignatureOpensASecondHandleOnTheTargetReader)
{
    const auto result = signOnce(service, target);

    // The middleware's own PC/SC layer, which is where the PKCS#11 module's
    // PKCS#15 provider opens handles.
    //
    //  * the reader carrying a live secure channel gets NO new handle: the
    //    provider adopts the session already registered for it;
    //  * the reader the signature targets gets ONE, and that is the known
    //    violation this test exists to pin: the caller already holds a session
    //    on it, and the module opens a second handle to the same card;
    //  * the neighbour, which neither the caller nor the signature has any
    //    business with, gets one too, because the module probes every reader
    //    the PC/SC layer reports.
    EXPECT_EQ(stubConnect(kSmReader), 0u);
    EXPECT_EQ(stubConnect(kTargetReader), 1u);
    EXPECT_EQ(stubConnect(kNeighbourReader), 1u);

    // OpenSC's PC/SC layer, and the number that is easiest to get wrong about
    // this architecture. Two contexts, not three: the provider refuses to bind
    // the reader with the live secure channel, so no context is established for
    // it. But establishing a context for ANY reader makes OpenSC enumerate all
    // of them and open a transient shared handle on each one that reports a
    // card, to read its features -- including the reader it just refused to
    // bind. So the short-circuit stops the bind, not the handle: two contexts
    // touch the secure-channel reader twice, and each context's own target once
    // more on top of that.
    EXPECT_EQ(shim().establishContext(), 2u);
    EXPECT_EQ(shim().connect(kSmReader), 2u);
    EXPECT_EQ(shim().connect(kTargetReader), 3u);
    EXPECT_EQ(shim().connect(kNeighbourReader), 3u);

    // Every handle either layer opened is closed before the call returns, and
    // the module is unloaded. This is the half of the picture that bounds the
    // damage: the handles are transient, not held for the process's life.
    EXPECT_EQ(librescrs_shim_open_handles(), 0u);
    EXPECT_EQ(shim().openHandles(), 0u);
    EXPECT_EQ(countContaining(g_dlopened, kModuleName), 1u) << "the module is loaded exactly once per signature";
    EXPECT_EQ(countContaining(g_dlclosed, kModuleName), 1u) << "and unloaded before the call returns";

    // In-process sanity, NOT evidence about the card: the adopt path did not
    // tear down the channel object or drop the registry entry. Both of these
    // read a member of an injected fake on a session that owns no PC/SC handle,
    // so no number the counting provider produces can change them -- they would
    // stay green even if a real transient handle killed a real tunnel. Whether
    // a live secure channel survives these handles is not yet confirmed on a
    // card; see the note at the top of this file.
    EXPECT_TRUE(smSession->hasLiveSecureChannel());
    EXPECT_TRUE(sessionPresence().hasLiveSm(kSmReader));

    // The signature itself fails, and must: no card answers any APDU here. The
    // counts above are what a signature costs before it gets that far.
    EXPECT_EQ(result.status, LibreSCRS::Signing::SigningResult::Status::SigningEngineError);
}

// The module targets the reader by NAME, not by the index it had in some earlier
// listing. Drop a reader from the set between two signatures and the target
// still gets exactly one handle while the dropped one gets none -- an
// index-based lookup would follow the shift and land on the wrong card.
TEST_F(PcscHandleCensusPinsKnownSecondHandleTest, ReaderSetChangeKeepsTargetByName)
{
    (void)signOnce(service, target);
    ASSERT_EQ(stubConnect(kTargetReader), 1u);
    ASSERT_EQ(stubConnect(kNeighbourReader), 1u);

    // Both copies of the counting provider re-read the reader set on reset and
    // not before: a silent re-read would let a test change the set without
    // saying so, and this is the one case that means to change it.
    librescrs_shim_reset();
    shim().reset();
    setReaderSet(std::string{kSmReader} + ";" + kTargetReader);

    (void)signOnce(service, target);

    EXPECT_EQ(stubConnect(kTargetReader), 1u);
    EXPECT_EQ(stubConnect(kNeighbourReader), 0u);
    EXPECT_EQ(stubConnect(kSmReader), 0u);
    EXPECT_EQ(librescrs_shim_open_handles(), 0u);
}
