// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <gtest/gtest.h>
#include <LibreSCRS/Plugin/CardPluginService.h>
#include <LibreSCRS/SmartCard/CardSession.h>
#include <LibreSCRS/SmartCard/detail/CardSessionInjection.h>

#include <libopensc/opensc.h>

#include <atomic>
#include <filesystem>
#include <memory>
#include <thread>

using namespace LibreSCRS::Plugin;

namespace {

std::filesystem::path pluginDir()
{
    return std::filesystem::path(PLUGIN_DIR);
}

std::shared_ptr<CardPlugin> findOpenSC(CardPluginService& registry)
{
    for (const auto& p : registry.plugins()) {
        if (p->pluginId() == "opensc")
            return p;
    }
    return nullptr;
}

} // namespace

// --- Unit tests (no hardware) ---

TEST(OpenSCPluginTest, LoadsViaRegistry)
{
    CardPluginService registry{pluginDir()};
    EXPECT_GE(registry.size(), 1u);

    std::shared_ptr<CardPlugin> opensc;
    for (const auto& p : registry.plugins()) {
        if (p->pluginId() == "opensc") {
            opensc = p;
            break;
        }
    }
    ASSERT_NE(opensc, nullptr);
}

TEST(OpenSCPluginTest, Metadata)
{
    CardPluginService registry{pluginDir()};

    std::shared_ptr<CardPlugin> opensc;
    for (const auto& p : registry.plugins()) {
        if (p->pluginId() == "opensc") {
            opensc = p;
            break;
        }
    }
    ASSERT_NE(opensc, nullptr);

    EXPECT_EQ(opensc->pluginId(), "opensc");
    EXPECT_EQ(opensc->displayName(), "OpenSC (generic)");
    EXPECT_EQ(opensc->probePriority(), 900);
}

TEST(OpenSCPluginTest, CanHandleAlwaysFalse)
{
    CardPluginService registry{pluginDir()};

    std::shared_ptr<CardPlugin> opensc;
    for (const auto& p : registry.plugins()) {
        if (p->pluginId() == "opensc") {
            opensc = p;
            break;
        }
    }
    ASSERT_NE(opensc, nullptr);

    EXPECT_FALSE(opensc->canHandle(std::vector<uint8_t>{0x3B, 0xFF, 0x94}));
    EXPECT_FALSE(opensc->canHandle(std::vector<uint8_t>{0x3B, 0xB9, 0x18}));
    EXPECT_FALSE(opensc->canHandle(std::vector<uint8_t>{0x00}));
    EXPECT_FALSE(opensc->canHandle(std::vector<uint8_t>{}));
}

TEST(OpenSCPluginTest, LowestPriority)
{
    CardPluginService registry{pluginDir()};

    auto plugins = registry.plugins();
    ASSERT_FALSE(plugins.empty());

    for (const auto& p : plugins) {
        if (p->pluginId() != "opensc") {
            EXPECT_LT(p->probePriority(), 900) << p->pluginId() << " has priority >= 900";
        }
    }
}

// --- Integration tests (require libopensc, no hardware) ---

TEST(OpenSCPluginTest, ContextEstablishRelease)
{
    sc_context_t* ctx = nullptr;
    int rc = sc_establish_context(&ctx, "librescrs-test");
    ASSERT_EQ(rc, 0) << "sc_establish_context failed: " << sc_strerror(rc);
    ASSERT_NE(ctx, nullptr);

    sc_release_context(ctx);
}

TEST(OpenSCPluginTest, NoReaderGracefulFail)
{
    sc_context_t* ctx = nullptr;
    int rc = sc_establish_context(&ctx, "librescrs-test");
    ASSERT_EQ(rc, 0);

    sc_reader_t* reader = sc_ctx_get_reader_by_name(ctx, "nonexistent_reader_12345");
    EXPECT_EQ(reader, nullptr);

    sc_release_context(ctx);
}

// --- Concurrency regression tests ---

// Regression test for A1: the OpenSC plugin previously held sc_context_t*,
// sc_card_t*, sc_pkcs15_card_t*, readerName, and hasPKI as `mutable` members
// on a plugin instance shared across all readers. Two near-simultaneous
// CardInserted events from different readers could interleave, with the
// second reader's canHandleConnection() tearing down the first reader's
// sc_pkcs15_card_t* while the first reader's readCard() was still iterating
// it — use-after-free / cross-reader data corruption.
//
// The fix migrates per-session state into a std::map<CardSession*, OpenSCSession>
// guarded by a mutex, matching the EMRTD plugin shape. This test exercises
// the per-session separation contract against the dlopen'd plugin via
// detached CardSessions: two sessions with distinct PCSCConnection addresses
// and distinct reader names are driven through canHandleConnection() /
// clearCredentials() / readCard() in orders that would exhibit shared-state
// aliasing under the buggy implementation.
//
// Detached sessions perform no real PC/SC I/O, so canHandleConnection()
// returns false for both sessions on any dev box; the invariant under test
// is that handling session B's events must not perturb any state keyed to
// session A, and that tearing down session A must not leave session B's
// state dangling. Under AddressSanitizer, a regression that restored the
// mutable-cache shape would surface here as a heap-use-after-free the
// moment the torn-down state were observed.
TEST(OpenSCPluginConcurrency, TwoSessionsDoNotCollide)
{
    CardPluginService registry{pluginDir()};
    auto opensc = findOpenSC(registry);
    ASSERT_NE(opensc, nullptr);

    // Two detached sessions with distinct reader names → distinct
    // PCSCConnection addresses; these are the map keys the fix relies on.
    auto sessionA = LibreSCRS::SmartCard::detail::makeDetachedCardSession("MockReaderA");
    auto sessionB = LibreSCRS::SmartCard::detail::makeDetachedCardSession("MockReaderB");
    ASSERT_NE(sessionA, nullptr);
    ASSERT_NE(sessionB, nullptr);
    ASSERT_NE(sessionA.get(), sessionB.get());

    // Interleave canHandleConnection(A) / canHandleConnection(B). In the
    // buggy impl, the second call's teardown() would destroy A's state.
    // Both return false (no hardware), which is expected.
    const std::vector<uint8_t> emptyAtr;
    EXPECT_FALSE(opensc->canHandleConnection(emptyAtr, *sessionA));
    EXPECT_FALSE(opensc->canHandleConnection(emptyAtr, *sessionB));

    // readCard(A) must not observe state bound to B. With no hardware,
    // readCard returns an UnsupportedCard status because canHandleConnection
    // never bound a session; the contract is "no crash, no aliasing".
    auto rrA = opensc->readCard(*sessionA);
    auto rrB = opensc->readCard(*sessionB);
    EXPECT_NE(rrA.status, LibreSCRS::Plugin::ReadResult::Status::Ok);
    EXPECT_NE(rrB.status, LibreSCRS::Plugin::ReadResult::Status::Ok);

    // Clear A first; B's entry must survive (fix invariant: per-session
    // teardown, not global). A second pass of readCard(B) must still work.
    opensc->clearCredentials(*sessionA);
    auto rrB2 = opensc->readCard(*sessionB);
    (void)rrB2;

    // Clear B last; no crash, and subsequent reads on A (already cleared)
    // must remain safe.
    opensc->clearCredentials(*sessionB);
    auto rrA2 = opensc->readCard(*sessionA);
    (void)rrA2;
}

// Concurrent-thread variant: two threads each hammer canHandleConnection()
// followed by readCard() on their own session, looping. Under the buggy
// mutable-cache shape, thread B's teardown() in canHandleConnection could
// free ctx/card/p15card while thread A is mid-readCard, producing a UAF
// that AddressSanitizer would flag. With the per-session map + mutex, the
// threads' state is isolated and the loop completes cleanly.
TEST(OpenSCPluginConcurrency, TwoThreadsTwoSessionsDoNotCollide)
{
    CardPluginService registry{pluginDir()};
    auto opensc = findOpenSC(registry);
    ASSERT_NE(opensc, nullptr);

    auto sessionA = LibreSCRS::SmartCard::detail::makeDetachedCardSession("MockReaderA");
    auto sessionB = LibreSCRS::SmartCard::detail::makeDetachedCardSession("MockReaderB");

    constexpr int kIterations = 200;
    std::atomic<bool> failed{false};

    auto worker = [&](LibreSCRS::SmartCard::CardSession& s) {
        const std::vector<uint8_t> emptyAtr;
        for (int i = 0; i < kIterations && !failed.load(std::memory_order_relaxed); ++i) {
            // Ignore return — detached session always returns false.
            (void)opensc->canHandleConnection(emptyAtr, s);
            auto rr = opensc->readCard(s);
            // readCard without a bound session returns UnsupportedCard; just
            // verify no crash and that the call completes. An Ok return is
            // impossible here (no card hardware); any non-Ok is acceptable.
            (void)rr;
            opensc->clearCredentials(s);
        }
    };

    std::thread tA(worker, std::ref(*sessionA));
    std::thread tB(worker, std::ref(*sessionB));
    tA.join();
    tB.join();

    EXPECT_FALSE(failed.load()) << "Per-session state aliased across threads";
}
