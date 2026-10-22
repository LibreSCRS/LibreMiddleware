// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

/// @file
/// @brief A census of the PC/SC handles one document signature opens.
///
/// A document is signed through the card plugin on the session the caller
/// already holds: no PKCS#11 module is loaded into the signing process, so no
/// slot is listed and no reader is probed. This test counts every handle either
/// PC/SC layer opens during one signature and finds none -- not on the reader
/// the signature targets, where the caller's session is the only connection,
/// not on a reader whose session carries a live secure channel, and not on a
/// neighbour nobody asked about. A neighbour's own operation is never waited on.
///
/// Before this, signing loaded the module, which opened a second handle to the
/// target card and a handle on every other reader that reported a card. dlopen
/// is interposed here, so a regression that loads a module named like it again
/// is counted.
///
/// @par What it cannot tell you
/// It counts handles; it says nothing about what a handle does to a card,
/// because there is no card here. This file also WRITES the OPENSC_CONF it
/// measures against, so every number is a number for the reader driver's own
/// defaults.
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
///
/// @par Where the census can be taken
/// The first path depends on ELF's flat symbol lookup: a definition exported
/// by the executable preempts the same name in every library loaded after it.
/// Mach-O binds each undefined symbol to the image it was linked against (the
/// two-level namespace), so on macOS the middleware's and the module's
/// SCardConnect, dlopen and dlclose go to PCSC.framework and libdyld and never
/// reach the copies here. The module then asks the real PC/SC service for its
/// readers, finds none on a machine without them, and OpenSC is never reached:
/// every count reads zero, measured on the macOS CI runner. Zero is also what
/// several of these assertions expect, so on such a platform the suite skips
/// rather than pass on numbers nothing produced. The OpenSC-side copy alone
/// does not depend on this -- OpenSC loads it by path -- and the
/// cross-provider coordination suite, which uses only that copy, runs there.

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
#include <chrono>
#include <future>
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

#include "soft_key_plugin.h"

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
    // A detached CMS signature: any bytes are a document to it.
    b.format(LibreSCRS::Signing::SignatureFormat::Cades)
        .level(LibreSCRS::Signing::SignatureLevel::B_B)
        .packaging(LibreSCRS::Signing::PackagingMode::Detached);
    return std::move(b).buildForBufferSign();
}

/// @brief Sign a buffer through the facade with a plugin whose key really
///        signs, and return the public outcome.
LibreSCRS::Signing::SigningResult signOnce(const std::shared_ptr<LibreSCRS::Signing::SigningService>& svc,
                                           const std::shared_ptr<CardSession>& session)
{
    auto provider = [](const LibreSCRS::Auth::AuthRequirement&) {
        std::vector<LibreSCRS::Auth::CredentialEntry> values;
        values.emplace_back("pin", LibreSCRS::Secure::String{"0000"});
        return LibreSCRS::Auth::CredentialResult::ok(std::move(values));
    };
    auto plugin = std::make_shared<LibreSCRS::TestSupport::SoftKeyPlugin>();
    static const std::vector<std::uint8_t> document{'t', 'o', ' ', 'b', 'e', ' ', 's', 'i', 'g', 'n', 'e', 'd'};
    return svc->sign(makeBufferRequest(), std::span<const std::uint8_t>{document}, provider, plugin, session);
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
    setReaderSet(std::string{kSmReader} + ";" + kTargetReader + ";" + kNeighbourReader);
}

class PcscHandleCensusTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
#if !defined(__linux__)
        GTEST_SKIP() << "the census counts the middleware's PC/SC calls through this executable's exported "
                        "SCardConnect, dlopen and dlclose, which preempt the libraries' own only under ELF's "
                        "flat symbol lookup; this platform binds each library's references to the image it was "
                        "linked against, so nothing here would be counted";
#endif
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

TEST_F(PcscHandleCensusTest, DocumentSignatureOpensNoHandleBeyondTheSession)
{
    const auto result = signOnce(service, target);
    // EXPECT, not ASSERT: a regression is most readable in the counts below.
    EXPECT_EQ(result.status, LibreSCRS::Signing::SigningResult::Status::Ok)
        << result.diagnosticDetail.value_or("no detail");

    // The middleware's own PC/SC layer: the caller's session is the one
    // connection to the target card, and no other reader is touched.
    EXPECT_EQ(stubConnect(kSmReader), 0u);
    EXPECT_EQ(stubConnect(kTargetReader), 0u);
    EXPECT_EQ(stubConnect(kNeighbourReader), 0u);

    // OpenSC's PC/SC layer: no context is established, so no reader is
    // enumerated and none is connected to.
    EXPECT_EQ(shim().establishContext(), 0u);
    EXPECT_EQ(shim().connect(kSmReader), 0u);
    EXPECT_EQ(shim().connect(kTargetReader), 0u);
    EXPECT_EQ(shim().connect(kNeighbourReader), 0u);

    EXPECT_EQ(librescrs_shim_open_handles(), 0u);
    EXPECT_EQ(shim().openHandles(), 0u);
    EXPECT_EQ(countContaining(g_dlopened, kModuleName), 0u) << "no PKCS#11 module is loaded to sign";

    // In-process sanity only: the neighbour's secure channel and its registry
    // entry are untouched.
    EXPECT_TRUE(smSession->hasLiveSecureChannel());
    EXPECT_TRUE(sessionPresence().hasLiveSm(kSmReader));
}

// An operation running on a neighbouring reader is neither waited on nor
// touched: the neighbour's plugin holds its operation open until the signature
// on the target has finished, so a signature that waited for it would never
// finish at all.
TEST_F(PcscHandleCensusTest, ConcurrentOperationOnNeighbourIsUndisturbed)
{
    auto neighbour = makeDetachedCardSession(kNeighbourReader);
    auto neighbourPlugin = std::make_shared<LibreSCRS::TestSupport::SigningStubPlugin>();
    std::promise<void> inside;
    std::promise<void> release;
    auto released = release.get_future().share();
    neighbourPlugin->respond = [&inside, released](const LibreSCRS::TestSupport::SigningStubPlugin::SignCall&) {
        inside.set_value();
        released.wait();
        LibreSCRS::Plugin::SignResult r;
        r.outcome = LibreSCRS::Plugin::SignResultOutcome::Ok;
        r.signature = {0x01};
        return r;
    };
    auto neighbourOperation = std::async(std::launch::async, [&] {
        return neighbourPlugin->sign(*neighbour, 0x01, std::vector<std::uint8_t>(32, 0x11),
                                     LibreSCRS::Plugin::SignMechanism::ECDSA_SHA256);
    });
    inside.get_future().wait();

    const auto started = std::chrono::steady_clock::now();
    auto result = std::async(std::launch::async, [&] { return signOnce(service, target); });
    const auto status = result.wait_for(std::chrono::seconds(30));
    release.set_value();
    ASSERT_EQ(status, std::future_status::ready) << "the signature waited for the neighbour's operation";
    const auto elapsed = std::chrono::steady_clock::now() - started;

    EXPECT_EQ(result.get().status, LibreSCRS::Signing::SigningResult::Status::Ok);
    EXPECT_EQ(neighbourOperation.get().outcome, LibreSCRS::Plugin::SignResultOutcome::Ok);
    EXPECT_EQ(stubConnect(kNeighbourReader), 0u);
    EXPECT_EQ(shim().connect(kNeighbourReader), 0u);
    EXPECT_LT(elapsed, std::chrono::seconds(10)) << "a B-B signature in memory takes milliseconds";
}
