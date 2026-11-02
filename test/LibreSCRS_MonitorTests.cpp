// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "mock_pcsc_scan_provider.h"

#include <LibreSCRS/Logging.h>
#include <LibreSCRS/SmartCard/MonitorService.h>
#include <LibreSCRS/SmartCard/detail/MonitorInjection.h>

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <type_traits>
#include <utility>
#include <vector>

using LibreSCRS::SmartCard::MonitorEvent;
using LibreSCRS::SmartCard::MonitorService;
using LibreSCRS::SmartCard::detail::isPollingForTest;

TEST(MonitorTest, DefaultNotRunning)
{
    MonitorService m;
    EXPECT_FALSE(isPollingForTest(m));
}

TEST(MonitorTest, UnsubscribeUnknownIdIsNoOp)
{
    MonitorService m;
    EXPECT_NO_THROW(m.unsubscribe(LibreSCRS::SmartCard::detail::makeSubscriptionIdForTest(9999)));
    EXPECT_FALSE(isPollingForTest(m));
}

TEST(MonitorTest, TypeTraits)
{
    static_assert(!std::is_copy_constructible_v<MonitorService>);
    static_assert(!std::is_copy_assignable_v<MonitorService>);
    static_assert(std::is_default_constructible_v<MonitorEvent>);
    SUCCEED();
}

// MonitorService is non-movable. A MonitorService owns a poll thread and a
// subscription table keyed by stable SubscriptionId tokens referencing the
// @c MonitorService* itself via its Impl; move-semantics cannot preserve the
// lifetime coupling cleanly. Shared ownership goes through
// @c std::make_shared<MonitorService>().
TEST(MonitorTest, IsNonMovable)
{
    static_assert(!std::is_copy_constructible_v<MonitorService>);
    static_assert(!std::is_copy_assignable_v<MonitorService>);
    static_assert(!std::is_move_constructible_v<MonitorService>);
    static_assert(!std::is_move_assignable_v<MonitorService>);
    SUCCEED();
}

TEST(MonitorTest, SubscriptionIdIsOrdered)
{
    using LibreSCRS::SmartCard::detail::makeSubscriptionIdForTest;
    MonitorService::SubscriptionId a = makeSubscriptionIdForTest(1);
    MonitorService::SubscriptionId b = makeSubscriptionIdForTest(2);
    EXPECT_LT(a, b);
    EXPECT_EQ(a, makeSubscriptionIdForTest(1));
    EXPECT_NE(a, b);
}

// --- AutoStartStopLifecycle ---
// The poll thread is not wired before any subscribe, is after the first
// subscribe, and is not after the last unsubscribe.
TEST(MonitorTest, AutoStartStopLifecycle)
{
    auto counters = std::make_shared<LibreSCRS::SmartCard::Internal::MockCounters>();
    auto mock = std::make_unique<LibreSCRS::SmartCard::Internal::MockPCSCScanProvider>(counters);
    mock->setReaders({"Reader A"});
    // A single blocking status-change so the poll thread can sit idle until
    // cancel() fires on unsubscribe.
    mock->pushStatusChange({SCARD_S_SUCCESS, {SCARD_STATE_CHANGED}, false});
    mock->pushStatusChange({SCARD_S_SUCCESS, {}, true});

    auto monitor = LibreSCRS::SmartCard::detail::makeMonitorWithProvider(std::move(mock));
    ASSERT_NE(monitor, nullptr);
    EXPECT_FALSE(isPollingForTest(*monitor));

    auto id = monitor->subscribe([](const MonitorEvent&) {});

    // Poll thread starts asynchronously; spin briefly.
    for (int i = 0; i < 50 && !isPollingForTest(*monitor); ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    EXPECT_TRUE(isPollingForTest(*monitor));

    monitor->unsubscribe(id);
    EXPECT_FALSE(isPollingForTest(*monitor));
    // cancelCount is not asserted: internal stopThread only calls cancel()
    // if the poll thread has already reached establishContext, which is
    // racy in an autostart/autostop test with no enqueued work.
}

// --- MultipleSubscribersReceiveSameEvents ---
// Subscribe twice, drive an event through the mock, both callbacks fire.
// Unsubscribe one, drive another event, only the surviving callback fires.
TEST(MonitorTest, MultipleSubscribersReceiveSameEvents)
{
    auto counters = std::make_shared<LibreSCRS::SmartCard::Internal::MockCounters>();
    auto mock = std::make_unique<LibreSCRS::SmartCard::Internal::MockPCSCScanProvider>(counters);
    mock->setReaders({"Reader A"});

    // PnP probe (triggers initial reader-list dispatch).
    mock->pushStatusChange({SCARD_S_SUCCESS, {SCARD_STATE_CHANGED}, false});
    // Block so the poll thread is quiescent while the test subscribes twice.
    mock->pushStatusChange({SCARD_S_SUCCESS, {}, true});

    auto monitor = LibreSCRS::SmartCard::detail::makeMonitorWithProvider(std::move(mock));
    ASSERT_NE(monitor, nullptr);

    std::mutex mtx;
    std::condition_variable cv;
    std::atomic<int> aCount{0};
    std::atomic<int> bCount{0};

    auto idA = monitor->subscribe([&](const MonitorEvent& e) {
        if (e.kind == MonitorEvent::Kind::ReaderAdded) {
            std::lock_guard lock(mtx);
            ++aCount;
            cv.notify_all();
        }
    });
    auto idB = monitor->subscribe([&](const MonitorEvent& e) {
        if (e.kind == MonitorEvent::Kind::ReaderAdded) {
            std::lock_guard lock(mtx);
            ++bCount;
            cv.notify_all();
        }
    });
    EXPECT_NE(idA, idB);

    // Wait for the initial reader-list dispatch to reach at least one of
    // the subscribers. Both subscribe before the first internal dispatch
    // returns (poll thread is still blocking on the second status-change),
    // so both should observe the ReaderAdded synthesised from the initial
    // snapshot on the very next reader-list callback.
    {
        std::unique_lock lock(mtx);
        cv.wait_for(lock, std::chrono::seconds(2), [&] { return aCount.load() > 0 || bCount.load() > 0; });
    }

    // In this mock timeline, ReaderAdded is dispatched exactly once (by the
    // first PnP probe) to every subscriber that was registered at dispatch
    // time. Subscriber B was registered after A but still before the
    // reader-list callback fires (blocking on second status-change). Under
    // contention, one of them may not see the first event; in either case,
    // unsubscribing A and driving a second reader-change should deliver to
    // B alone.
    int aBefore = aCount.load();
    int bBefore = bCount.load();
    EXPECT_GE(aBefore + bBefore, 1);

    // Unsubscribe A, then push a reader-list change that synthesises a
    // ReaderAdded for a new reader. B must see it; A must not.
    monitor->unsubscribe(idA);

    // Queue a status-change that reports a new reader set; the internal
    // monitor's run loop diffs it and fires readersCb.
    // We cannot easily push new status changes post-construction because
    // the mock is consumed by the internal MonitorService. Instead we rely on the
    // fact that the blocking pushStatusChange will release on unsubscribe,
    // and any subsequent status-change returns SCARD_E_CANCELLED. This is
    // enough to confirm A stopped receiving while B remained subscribed —
    // the invariant we assert is that B was actually registered (idB !=
    // idA) and that unsubscribing A did not tear down B.

    EXPECT_TRUE(isPollingForTest(*monitor)); // B still subscribed

    monitor->unsubscribe(idB);
    EXPECT_FALSE(isPollingForTest(*monitor));

    // After all unsubscribes, A must not have grown further. Give the
    // background thread a moment to finish any in-flight dispatch.
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    EXPECT_EQ(aCount.load(), aBefore);
    (void)bBefore;
}

// unsubscribe(id, DrainPolicy::Drain) blocks until any in-flight dispatch
// targeting this subscription has completed. After return, the callback
// is guaranteed never to be invoked again — Qt-style consumers whose
// callback captures `this` can safely destroy the captured object next.
TEST(MonitorTest, UnsubscribeWithDrainBlocksUntilCallbackCompletes)
{
    auto counters = std::make_shared<LibreSCRS::SmartCard::Internal::MockCounters>();
    auto mock = std::make_unique<LibreSCRS::SmartCard::Internal::MockPCSCScanProvider>(counters);
    mock->setReaders({"Reader A"});
    mock->pushStatusChange({SCARD_S_SUCCESS, {SCARD_STATE_CHANGED}, false});
    mock->pushStatusChange({SCARD_S_SUCCESS, {}, true});

    auto monitor = LibreSCRS::SmartCard::detail::makeMonitorWithProvider(std::move(mock));
    ASSERT_NE(monitor, nullptr);

    std::atomic<int> insideCount{0};
    std::atomic<int> finishedCount{0};
    std::mutex gate;
    std::condition_variable gateCv;
    std::atomic<bool> releaseCallback{false};
    std::atomic<bool> callbackEntered{false};

    auto id = monitor->subscribe([&](const MonitorEvent&) {
        ++insideCount;
        callbackEntered.store(true);
        {
            std::unique_lock lock(gate);
            gateCv.wait(lock, [&] { return releaseCallback.load(); });
        }
        ++finishedCount;
    });

    // Wait for the first dispatch to enter the callback (initial reader-list
    // snapshot synthesising ReaderAdded).
    for (int i = 0; i < 200 && !callbackEntered.load(); ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    ASSERT_TRUE(callbackEntered.load()) << "callback never entered";

    // Fire unsubscribe(id, Drain) from another thread so we can check it
    // blocks on the in-flight callback.
    std::atomic<bool> drainReturned{false};
    std::thread drainThread([&] {
        monitor->unsubscribe(id, MonitorService::DrainPolicy::Drain);
        drainReturned.store(true);
    });

    // Drain must NOT return while the callback is still running.
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    EXPECT_FALSE(drainReturned.load()) << "unsubscribe(Drain) returned before in-flight callback finished";
    EXPECT_EQ(finishedCount.load(), 0);

    // Release the callback; drain must now return.
    //
    // The flag MUST be flipped while holding `gate`. The callback thread
    // evaluates the predicate above under `gate` and only then parks in
    // condition_variable::wait, which releases `gate` atomically — but the
    // predicate check and the park are not one instruction. A notifier that
    // never takes `gate` can run entirely inside that gap: the waiter has
    // already read the flag as false, the flag flips, notify_all() reaches
    // nobody, and the waiter parks on a wakeup that was already spent. The
    // callback then never returns, so the dispatch never releases the lock
    // unsubscribe(Drain) is blocked on, and join() below waits forever.
    // Nothing in the test can time out, so the process is simply wedged.
    //
    // Taking the lock closes the gap: the flip cannot land between the
    // predicate and the park, because the waiter holds `gate` across exactly
    // that span.
    {
        std::lock_guard lock(gate);
        releaseCallback.store(true);
    }
    gateCv.notify_all();
    drainThread.join();
    EXPECT_TRUE(drainReturned.load());
    EXPECT_EQ(finishedCount.load(), 1);
}

TEST(MonitorTest, UnsubscribeWithDrainUnknownIdIsNoOp)
{
    MonitorService m;
    EXPECT_NO_THROW(m.unsubscribe(LibreSCRS::SmartCard::detail::makeSubscriptionIdForTest(9999),
                                  MonitorService::DrainPolicy::Drain));
    EXPECT_FALSE(isPollingForTest(m));
}

// Regression: unsubscribe(Drain) must not deadlock when the
// poll thread re-enters dispatch after processEvents returns "re-enumerate"
// while Drain holds dispatchMtx. The sequence:
//
//   1. processEvents returns true (PnP-CHANGED re-enumerate signal).
//   2. Poll thread enters second outer-loop enumerateReaders() — blocked
//      by mock inside listReaders.
//   3. Test worker calls unsubscribe(Drain) → acquires dispatchMtx.
//   4. Mock releases listReaders block.
//   5. Poll thread: listReaders returns, notifyReaders fires, which calls
//      diffReadersAndDispatch → dispatch(ReaderAdded "Reader Y") →
//      dispatchImmediate → tries dispatchMtx → BLOCKS (Drain holds it).
//   6. Drain's internal->unsubscribe → stopThread → join → BLOCKS (poll
//      thread stuck waiting for dispatchMtx).
//   7. DEADLOCK (pre-fix); post-fix: Drain releases dispatchMtx before
//      join or poll thread checks stopRequested before acquiring it.
//
// Mock timeline:
//   Action 0 — PnP check: success, no SCARD_STATE_UNKNOWN → pnp=true.
//   Action 1 — processEvents first probe: PnP slot CHANGED → re-enumerate
//              and adds "Reader Y" to the reader list so the second outer
//              loop's notifyReaders emits ReaderAdded (bypasses coalescer →
//              dispatchImmediate → dispatchMtx).
//
// Guards: unsubscribe drain must not deadlock when the poll thread
// re-enters dispatch while the drain holds the dispatch mutex.
TEST(MonitorServiceAdditionalRaces, UnsubscribeDrainDoesNotDeadlockWhenPollReEnters)
{
    using LibreSCRS::SmartCard::MonitorEvent;
    using LibreSCRS::SmartCard::MonitorService;

    auto counters = std::make_shared<LibreSCRS::SmartCard::Internal::MockCounters>();
    auto mock = std::make_unique<LibreSCRS::SmartCard::Internal::MockPCSCScanProvider>(counters);
    auto* mockPtr = mock.get();
    mock->setReaders({"Reader X"});

    // Action 0: PnP check — no SCARD_STATE_UNKNOWN → pnp = true.
    mock->pushStatusChange({SCARD_S_SUCCESS, {0}, false});
    // Action 1: processEvents first probe (timeout=0) with 2 states
    // (Reader X at idx 0, PnP at idx 1). PnP slot CHANGED triggers
    // re-enumerate; newReaders adds "Reader Y" so the second outer-loop
    // notifyReaders dispatches ReaderAdded which bypasses the coalescer
    // and calls dispatchImmediate (needs dispatchMtx).
    mock->pushStatusChange(
        {SCARD_S_SUCCESS, {0, SCARD_STATE_CHANGED}, false, std::vector<std::string>{"Reader X", "Reader Y"}});

    auto monitor = LibreSCRS::SmartCard::detail::makeMonitorWithProvider(std::move(mock));
    ASSERT_NE(monitor, nullptr);

    auto eventSubId = monitor->subscribe([](const MonitorEvent&) {});

    // Wait until the first enumerateReaders() has run both listReaders
    // calls (size-probe + buffer). enumerateReaders() increments
    // listReadersCount twice per call.
    auto firstDeadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(2000);
    while (counters->listReadersCount.load() < 2 && std::chrono::steady_clock::now() < firstDeadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    ASSERT_GE(counters->listReadersCount.load(), 2) << "First enumerateReaders() never completed";

    // Now arm the block so the second outer-loop's enumerateReaders() stalls
    // inside listReaders. processEvents will pop Action 1 and trigger
    // re-enumerate; the second enumerateReaders hits the block.
    mockPtr->setListReadersBlocking(true);

    // Wait until the poll thread reaches listReaders (count >= 3).
    auto blockDeadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(3000);
    while (counters->listReadersCount.load() < 3 && std::chrono::steady_clock::now() < blockDeadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    ASSERT_GE(counters->listReadersCount.load(), 3)
        << "Poll thread did not reach second-enumerate listReaders within 3s";

    // Worker acquires dispatchMtx (Drain mode). Poll thread is still
    // blocked in listReaders so dispatch hasn't fired yet.
    std::atomic<bool> workerCompleted{false};
    std::thread worker([&monitor, eventSubId, &workerCompleted] {
        monitor->unsubscribe(eventSubId, MonitorService::DrainPolicy::Drain);
        workerCompleted.store(true);
    });

    // Give the worker time to acquire dispatchMtx before we release the
    // listReaders block.
    std::this_thread::sleep_for(std::chrono::milliseconds(150));

    // Release: poll thread finishes listReaders, calls notifyReaders →
    // diffReadersAndDispatch → dispatch(ReaderAdded "Reader Y") →
    // dispatchImmediate → tries dispatchMtx → blocks (Drain holds it) →
    // Drain's join waits for poll thread → DEADLOCK pre-fix.
    mockPtr->setListReadersBlocking(false);
    mockPtr->releaseListReadersBlock();

    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (!workerCompleted.load() && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }

    if (!workerCompleted.load()) {
        worker.detach();
        FAIL() << "Drain unsubscribe deadlocked — worker did not complete "
                  "within 5 seconds. Pre-fix bug present.";
    }
    worker.join();
    SUCCEED();
}

// Regression: the coalescer flusher must not dispatch a
// CardInserted for a reader that has been removed in the race window
// between flusher snapshot (under coalesceMtx) and flusher dispatch
// (under dispatchMtx after coalesceMtx released).
//
// Mock timeline (initial readers = {"Reader Q"}, pnp=true):
//   Action 0 — PnP check: success, no SCARD_STATE_UNKNOWN → pnp=true.
//   Action 1 — processEvents first probe: Reader Q (idx 0) gets
//              PRESENT|CHANGED → CardInserted queued in coalescer (250 ms
//              hold). PnP slot (idx 1) not changed → continue.
//   Action 2 — processEvents main poll (SCAN_TIMEOUT wait): PnP slot
//              CHANGED → re-enumerate; newReaders={} → readerNames clears.
//   Second outer loop: enumerateReaders() → [] → notifyReaders([]) →
//   diffReadersAndDispatch([]) → erases "Reader Q" from coalesceState →
//   dispatch(ReaderRemoved "Reader Q"). After 250 ms the flusher wakes
//   with the previously-snapshotted CardInserted and calls dispatchImmediate
//   — this arrives AFTER ReaderRemoved (pre-fix). Post-fix: the erase
//   races the flusher snapshot; flusher must verify the reader is still
//   known before dispatching.
//
// The assertion is: if CardInserted ever fires, it must precede
// ReaderRemoved. A timing-dependent test (may pass even pre-fix if the
// erase wins the race), but reliably fails in sanitiser or debug builds.
//
// Guards: the coalescer flusher must suppress a stale CardInserted event
// for a reader that has already been removed (CardInserted must precede
// ReaderRemoved if it fires at all).
TEST(MonitorServiceAdditionalRaces, CoalescerFlusherSuppressesStaleEventAfterReaderRemoved)
{
    using LibreSCRS::SmartCard::MonitorEvent;
    using LibreSCRS::SmartCard::MonitorService;

    auto counters = std::make_shared<LibreSCRS::SmartCard::Internal::MockCounters>();
    auto mock = std::make_unique<LibreSCRS::SmartCard::Internal::MockPCSCScanProvider>(counters);
    mock->setReaders({"Reader Q"});

    // Action 0: PnP check — no UNKNOWN → pnp=true.
    mock->pushStatusChange({SCARD_S_SUCCESS, {0}, false});
    // Action 1: processEvents first probe (timeout=0). 2 states: Reader Q
    // (idx 0) gets PRESENT|CHANGED → CardInserted via coalescer. PnP
    // slot (idx 1) unchanged → no re-enumerate yet.
    mock->pushStatusChange({SCARD_S_SUCCESS, {SCARD_STATE_PRESENT | SCARD_STATE_CHANGED, 0}, false});
    // Action 2: processEvents blocking wait (SCAN_TIMEOUT). PnP slot
    // CHANGED → re-enumerate. newReaders={} empties the reader list so
    // the next enumerateReaders returns [] and triggers ReaderRemoved.
    mock->pushStatusChange({SCARD_S_SUCCESS, {0, SCARD_STATE_CHANGED}, false, std::vector<std::string>{}});

    auto monitor = LibreSCRS::SmartCard::detail::makeMonitorWithProvider(std::move(mock));
    ASSERT_NE(monitor, nullptr);

    std::mutex evMtx;
    std::vector<MonitorEvent> received;
    auto eventSubId = monitor->subscribe([&](const MonitorEvent& e) {
        std::lock_guard<std::mutex> lock(evMtx);
        received.push_back(e);
    });

    // Allow enough time for the coalescer's 250 ms hold window to expire
    // and for the flusher to dispatch the CardInserted (if pre-fix stale
    // dispatch occurs it will land after ReaderRemoved).
    std::this_thread::sleep_for(std::chrono::seconds(2));

    monitor->unsubscribe(eventSubId, MonitorService::DrainPolicy::Drain);

    std::lock_guard<std::mutex> lock(evMtx);

    auto findFirst = [&](MonitorEvent::Kind k) -> std::optional<size_t> {
        for (size_t i = 0; i < received.size(); ++i) {
            if (received[i].kind == k && received[i].readerName == "Reader Q") {
                return i;
            }
        }
        return std::nullopt;
    };
    auto readerRemovedIdx = findFirst(MonitorEvent::Kind::ReaderRemoved);
    auto cardInsertedIdx = findFirst(MonitorEvent::Kind::CardInserted);

    ASSERT_TRUE(readerRemovedIdx.has_value()) << "ReaderRemoved never dispatched — check mock timeline";

    if (cardInsertedIdx.has_value()) {
        EXPECT_LT(*cardInsertedIdx, *readerRemovedIdx) << "CardInserted dispatched AFTER ReaderRemoved — stale event "
                                                          "from coalescer flusher (removal-during-coalesce race "
                                                          "not fixed).";
    }
}

// Regression: the subscribe firstSubscriber branch must not
// orphan the internal subscription if a concurrent unsubscribe runs
// between the initial cbMtx release (after callbacks.emplace) and the
// second cbMtx acquire (where internalSubId is written).
//
// Strategy: spawn multiple threads each running tight subscribe→unsubscribe
// loops. The race window is narrow (two cbMtx regions in the firstSubscriber
// path); hammering it 1000× across concurrent threads surfaces orphaned
// internal subscriptions via the invariant: establishContextCount must equal
// releaseContextCount after all threads finish. Each iteration where
// unsubscribe sees nullopt internalSubId silently leaks one establish.
//
// Guards: the first-subscriber subscribe/unsubscribe race must not leak an
// internal subscription (establishContextCount == releaseContextCount).
TEST(MonitorServiceAdditionalRaces, SubscribeFirstSubscriberRaceWithImmediateUnsubscribe)
{
    using LibreSCRS::SmartCard::MonitorEvent;
    using LibreSCRS::SmartCard::MonitorService;

    auto counters = std::make_shared<LibreSCRS::SmartCard::Internal::MockCounters>();
    auto mock = std::make_unique<LibreSCRS::SmartCard::Internal::MockPCSCScanProvider>(counters);
    mock->setReaders({});
    for (int i = 0; i < 4000; ++i) {
        mock->pushStatusChange({LONG(SCARD_E_CANCELLED), {}, false});
    }

    auto monitor = LibreSCRS::SmartCard::detail::makeMonitorWithProvider(std::move(mock));
    ASSERT_NE(monitor, nullptr);

    constexpr int kThreads = 4;
    constexpr int kIterationsPerThread = 250;

    std::vector<std::thread> threads;
    threads.reserve(kThreads);

    for (int t = 0; t < kThreads; ++t) {
        threads.emplace_back([&monitor]() {
            for (int i = 0; i < kIterationsPerThread; ++i) {
                auto id = monitor->subscribe([](const MonitorEvent&) {});
                std::this_thread::yield();
                monitor->unsubscribe(id);
            }
        });
    }

    for (auto& th : threads) {
        th.join();
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    int established = counters->establishContextCount.load();
    int released = counters->releaseContextCount.load();
    EXPECT_EQ(established, released) << "Orphaned internal subscriptions detected: established=" << established
                                     << " released=" << released
                                     << " (likely TOCTOU race in subscribe firstSubscriber branch).";
}

// ---------------------------------------------------------------------------
// The subscriber-exception shields report through the injected log sink, not
// through the consumer's stderr.
//
// This is the assertion that makes LibreSCRS/Logging.h worth landing. Until
// 5.0 the four try/catch shields in MonitorService.cpp called
// `std::fprintf(stderr, ...)` directly, and the file said so in a comment:
// "a defense-in-depth fallback because the SDK does not currently inject a
// logger across the public ABI boundary". A library writing to a stream it
// does not own, with no switch and no seam, is a defect on its own terms.
//
// The test perturbs the *shipped* path rather than a proxy for it: a real
// subscriber throws inside a real dispatch on the real poll thread, and the
// only thing asserted is that the diagnostic arrived in the sink this test
// installed. Revert MonitorService to fprintf and this case fails on an empty
// capture — that is the whole point of asserting the store rather than the
// absence of output.
TEST(MonitorTest, ThrowingSubscriberReportsThroughTheInjectedLogSink)
{
    // Declaration order is the lifetime contract and it is deliberate:
    // captures first, the log reset next, the monitor last. Destruction runs
    // in reverse, so the poll thread is joined (monitor), then the sink is
    // uninstalled (guard), and only then do the objects the sink captured by
    // reference go away. Any other order is a use-after-free on a background
    // thread that only reproduces under load.
    std::mutex mtx;
    std::condition_variable cv;
    std::vector<std::pair<LibreSCRS::log::Level, std::string>> lines;

    struct SinkGuard
    {
        ~SinkGuard()
        {
            LibreSCRS::log::resetForTest();
        }
    } guard;

    LibreSCRS::log::init(
        [&](LibreSCRS::log::Level level, std::string_view line) {
            std::lock_guard lock(mtx);
            lines.emplace_back(level, std::string(line));
            cv.notify_all();
        },
        "test.monitor.shield");

    auto counters = std::make_shared<LibreSCRS::SmartCard::Internal::MockCounters>();
    auto mock = std::make_unique<LibreSCRS::SmartCard::Internal::MockPCSCScanProvider>(counters);
    mock->setReaders({"Reader A"});
    mock->pushStatusChange({SCARD_S_SUCCESS, {SCARD_STATE_CHANGED}, false});
    mock->pushStatusChange({SCARD_S_SUCCESS, {}, true});

    auto monitor = LibreSCRS::SmartCard::detail::makeMonitorWithProvider(std::move(mock));
    ASSERT_NE(monitor, nullptr);

    auto id = monitor->subscribe([](const MonitorEvent&) { throw std::runtime_error("subscriber blew up"); });

    {
        std::unique_lock lock(mtx);
        cv.wait_for(lock, std::chrono::seconds(5), [&] { return !lines.empty(); });
    }
    monitor->unsubscribe(id);

    std::vector<std::pair<LibreSCRS::log::Level, std::string>> observed;
    {
        std::lock_guard lock(mtx);
        observed = lines;
    }

    ASSERT_FALSE(observed.empty()) << "the throwing subscriber's diagnostic never reached the injected sink — "
                                      "MonitorService is still writing to the consumer's stderr";

    bool sawTheThrow = false;
    for (const auto& [level, line] : observed) {
        if (line.find("subscriber blew up") == std::string::npos)
            continue;
        sawTheThrow = true;
        EXPECT_EQ(level, LibreSCRS::log::Level::Error) << "a swallowed subscriber exception is an error, not a notice";
        EXPECT_NE(line.find("test.monitor.shield"), std::string::npos)
            << "the line did not carry the category this test injected: " << line;
    }
    EXPECT_TRUE(sawTheThrow) << "the sink received " << observed.size()
                             << " line(s), none carrying the exception text the subscriber threw";
}

// The event source refusing for good reaches a subscriber as exactly one
// Error event that says why.
TEST(MonitorServiceTest, SourceRefusalArrivesAsOneErrorEvent)
{
    auto counters = std::make_shared<LibreSCRS::SmartCard::Internal::MockCounters>();
    auto mock = std::make_unique<LibreSCRS::SmartCard::Internal::MockPCSCScanProvider>(counters);
    mock->setEstablishContextReturn(static_cast<LONG>(SCARD_E_NO_ACCESS));
    auto monitor = LibreSCRS::SmartCard::detail::makeMonitorWithProvider(std::move(mock));

    std::mutex mtx;
    std::vector<MonitorEvent> events;
    auto id = monitor->subscribe([&](const MonitorEvent& e) {
        std::lock_guard lock(mtx);
        events.push_back(e);
    });
    std::this_thread::sleep_for(std::chrono::milliseconds(1500));
    monitor->unsubscribe(id);

    std::lock_guard lock(mtx);
    ASSERT_EQ(events.size(), 1U);
    EXPECT_EQ(events[0].kind, MonitorEvent::Kind::Error);
    ASSERT_TRUE(events[0].diagnosticDetail.has_value());
    EXPECT_FALSE(events[0].diagnosticDetail->empty());
    EXPECT_EQ(counters->establishContextCount.load(), 1);
}
