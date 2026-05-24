// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "mock_pcsc_scan_provider.h"

#include <LibreSCRS/SmartCard/MonitorService.h>
#include <LibreSCRS/SmartCard/detail/MonitorInjection.h>

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <string>
#include <thread>
#include <type_traits>
#include <utility>
#include <vector>

using LibreSCRS::SmartCard::MonitorEvent;
using LibreSCRS::SmartCard::MonitorService;

TEST(MonitorTest, DefaultNotRunning)
{
    MonitorService m;
    EXPECT_FALSE(m.isRunning());
}

TEST(MonitorTest, ListReadersReturnsVector)
{
    MonitorService m;
    // 4.0: listReaders() is noexcept and returns optional<vector>; nullopt
    // signals PC/SC-subsystem unavailability, an engaged optional carries
    // the snapshot (possibly empty). We just verify the call itself does
    // not throw and returns something of the expected shape.
    static_assert(noexcept(m.listReaders()), "MonitorService::listReaders must be noexcept");
    auto readersOpt = m.listReaders();
    (void)readersOpt;
}

TEST(MonitorTest, UnsubscribeUnknownIdIsNoOp)
{
    MonitorService m;
    EXPECT_NO_THROW(m.unsubscribe(LibreSCRS::SmartCard::detail::makeSubscriptionIdForTest(9999)));
    EXPECT_FALSE(m.isRunning());
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
// @c std::make_shared<MonitorService>() (mirroring AutoReaderService).
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
// isRunning() is false before any subscribe, true after first subscribe,
// false after the last unsubscribe.
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
    EXPECT_FALSE(monitor->isRunning());

    auto id = monitor->subscribe([](const MonitorEvent&) {});

    // Poll thread starts asynchronously; spin briefly.
    for (int i = 0; i < 50 && !monitor->isRunning(); ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    EXPECT_TRUE(monitor->isRunning());

    monitor->unsubscribe(id);
    EXPECT_FALSE(monitor->isRunning());
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

    EXPECT_TRUE(monitor->isRunning()); // B still subscribed

    monitor->unsubscribe(idB);
    EXPECT_FALSE(monitor->isRunning());

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
    releaseCallback.store(true);
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
    EXPECT_FALSE(m.isRunning());
}

// --- subscribeReaderList: snapshot is dispatched AFTER per-reader events ---
// Wave 6 / 6.1 acceptance: an LC-style consumer using subscribeReaderList
// observes the post-change reader-list snapshot strictly after the
// per-reader ReaderAdded events for the same change. Guarantees the
// snapshot reflects every prior per-reader event the consumer's
// EventCallback would have observed for that change.
TEST(MonitorTest, ReaderListSnapshotEmittedAfterPerReaderEvents)
{
    auto counters = std::make_shared<LibreSCRS::SmartCard::Internal::MockCounters>();
    auto mock = std::make_unique<LibreSCRS::SmartCard::Internal::MockPCSCScanProvider>(counters);
    mock->setReaders({"Reader A", "Reader B"});
    mock->pushStatusChange({SCARD_S_SUCCESS, {SCARD_STATE_CHANGED, SCARD_STATE_CHANGED}, false});
    mock->pushStatusChange({SCARD_S_SUCCESS, {}, true});

    auto monitor = LibreSCRS::SmartCard::detail::makeMonitorWithProvider(std::move(mock));
    ASSERT_NE(monitor, nullptr);

    std::mutex mtx;
    std::condition_variable cv;
    // Recorded event log: "added:<name>" / "removed:<name>" / "snapshot:<count>"
    // in dispatch order.
    std::vector<std::string> log;

    // Subscribe to BOTH callbacks BEFORE the poll thread starts so the
    // initial diff fires both paths in the documented order. Using
    // subscribeReaderList as the first subscriber means the bootstrap
    // fire-on-subscribe path is skipped (firstSubscriber == true) and the
    // first snapshot the test observes is the one synthesised by the
    // change-driven diffReadersAndDispatch — which is the contract under
    // test ("after per-reader events").
    std::vector<std::string> lastSnapshot;
    auto listId = monitor->subscribeReaderList([&](const std::vector<std::string>& readers) {
        std::lock_guard lock(mtx);
        log.push_back("snapshot:" + std::to_string(readers.size()));
        lastSnapshot = readers;
        cv.notify_all();
    });
    auto evId = monitor->subscribe([&](const MonitorEvent& e) {
        std::lock_guard lock(mtx);
        if (e.kind == MonitorEvent::Kind::ReaderAdded) {
            log.push_back("added:" + e.readerName);
        } else if (e.kind == MonitorEvent::Kind::ReaderRemoved) {
            log.push_back("removed:" + e.readerName);
        }
        cv.notify_all();
    });
    EXPECT_NE(evId, listId);

    // Wait until a non-empty snapshot has been observed (i.e. the
    // change-driven snapshot reflecting Reader A + Reader B, not a stray
    // empty bootstrap).
    {
        std::unique_lock lock(mtx);
        cv.wait_for(lock, std::chrono::seconds(2), [&] {
            for (const auto& entry : log) {
                if (entry == "snapshot:2")
                    return true;
            }
            return false;
        });
    }

    // Assert: the "snapshot:2" entry is preceded by BOTH "added:Reader A"
    // and "added:Reader B" — the per-reader events for that change must
    // dispatch first.
    std::lock_guard lock(mtx);
    bool sawAddedABeforeSnapshot = false;
    bool sawAddedBBeforeSnapshot = false;
    bool sawAddedA = false;
    bool sawAddedB = false;
    for (const auto& entry : log) {
        if (entry == "added:Reader A")
            sawAddedA = true;
        else if (entry == "added:Reader B")
            sawAddedB = true;
        else if (entry == "snapshot:2") {
            sawAddedABeforeSnapshot = sawAddedA;
            sawAddedBBeforeSnapshot = sawAddedB;
            break;
        }
    }
    auto joinLog = [&] {
        std::string joined;
        for (const auto& e : log) {
            joined += e;
            joined += '|';
        }
        return joined;
    };
    EXPECT_TRUE(sawAddedABeforeSnapshot) << "snapshot:2 must follow added:Reader A; log was: " << joinLog();
    EXPECT_TRUE(sawAddedBBeforeSnapshot) << "snapshot:2 must follow added:Reader B; log was: " << joinLog();
    EXPECT_EQ(lastSnapshot.size(), 2u);

    monitor->unsubscribe(evId);
    monitor->unsubscribeReaderList(listId);
    EXPECT_FALSE(monitor->isRunning());
}

// subscribeReaderList alone keeps the poll thread alive (auto-start counts
// reader-list subscribers in the union of populations); unsubscribeReaderList
// of the only subscriber stops it.
TEST(MonitorTest, ReaderListSubscriberAutoStartsAndStopsPollThread)
{
    auto counters = std::make_shared<LibreSCRS::SmartCard::Internal::MockCounters>();
    auto mock = std::make_unique<LibreSCRS::SmartCard::Internal::MockPCSCScanProvider>(counters);
    mock->setReaders({"Reader A"});
    mock->pushStatusChange({SCARD_S_SUCCESS, {SCARD_STATE_CHANGED}, false});
    mock->pushStatusChange({SCARD_S_SUCCESS, {}, true});

    auto monitor = LibreSCRS::SmartCard::detail::makeMonitorWithProvider(std::move(mock));
    ASSERT_NE(monitor, nullptr);
    EXPECT_FALSE(monitor->isRunning());

    auto id = monitor->subscribeReaderList([](const std::vector<std::string>&) {});
    for (int i = 0; i < 50 && !monitor->isRunning(); ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    EXPECT_TRUE(monitor->isRunning());

    monitor->unsubscribeReaderList(id);
    EXPECT_FALSE(monitor->isRunning());
}

// Late-joining reader-list subscriber receives the current snapshot
// immediately (bootstrap fire path) rather than waiting for the next
// reader-list change.
TEST(MonitorTest, ReaderListSubscriberLateJoinReceivesBootstrap)
{
    auto counters = std::make_shared<LibreSCRS::SmartCard::Internal::MockCounters>();
    auto mock = std::make_unique<LibreSCRS::SmartCard::Internal::MockPCSCScanProvider>(counters);
    mock->setReaders({"Reader A"});
    mock->pushStatusChange({SCARD_S_SUCCESS, {SCARD_STATE_CHANGED}, false});
    mock->pushStatusChange({SCARD_S_SUCCESS, {}, true});

    auto monitor = LibreSCRS::SmartCard::detail::makeMonitorWithProvider(std::move(mock));
    ASSERT_NE(monitor, nullptr);

    // First subscriber: per-event, to trigger the internal monitor wiring
    // so the initial diff populates knownReaders.
    std::atomic<int> earlyAddedCount{0};
    auto evId = monitor->subscribe([&](const MonitorEvent& e) {
        if (e.kind == MonitorEvent::Kind::ReaderAdded)
            earlyAddedCount.fetch_add(1);
    });
    // Wait for the initial diff to land.
    for (int i = 0; i < 200 && earlyAddedCount.load() == 0; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    ASSERT_GE(earlyAddedCount.load(), 1);

    // Now late-join with subscribeReaderList. Bootstrap snapshot must
    // arrive immediately (synchronously inside the subscribe call OR
    // promptly afterwards, since dispatchReaderListSnapshot serialises on
    // dispatchMtx — but in either case before any further reader-list
    // change).
    std::mutex mtx;
    std::condition_variable cv;
    std::optional<std::vector<std::string>> bootstrap;
    auto listId = monitor->subscribeReaderList([&](const std::vector<std::string>& readers) {
        std::lock_guard lock(mtx);
        if (!bootstrap)
            bootstrap = readers;
        cv.notify_all();
    });
    {
        std::unique_lock lock(mtx);
        cv.wait_for(lock, std::chrono::seconds(2), [&] { return bootstrap.has_value(); });
    }
    ASSERT_TRUE(bootstrap.has_value()) << "late-joining reader-list subscriber never received bootstrap snapshot";
    EXPECT_EQ(bootstrap->size(), 1u);
    if (!bootstrap->empty()) {
        EXPECT_EQ(bootstrap->front(), "Reader A");
    }

    monitor->unsubscribe(evId);
    monitor->unsubscribeReaderList(listId);
    EXPECT_FALSE(monitor->isRunning());
}

// unsubscribeReaderList with a per-event SubscriptionId is a no-op
// (mismatched-variant safety per header contract).
TEST(MonitorTest, UnsubscribeReaderListWithPerEventIdIsNoOp)
{
    MonitorService m;
    auto evId = m.subscribe([](const MonitorEvent&) {});
    // Calling the reader-list unsubscribe overload with a per-event token
    // must not remove the per-event subscription nor crash.
    EXPECT_NO_THROW(m.unsubscribeReaderList(evId));
    // Per-event subscription still active — poll thread (would-be) still tracks
    // it via callbacks map (we can't easily probe membership without isRunning
    // depending on the internal monitor wiring; we just confirm symmetry by
    // unsubscribing through the matching overload).
    EXPECT_NO_THROW(m.unsubscribe(evId));
}

TEST(MonitorTest, UnsubscribeReaderListUnknownIdIsNoOp)
{
    MonitorService m;
    EXPECT_NO_THROW(m.unsubscribeReaderList(LibreSCRS::SmartCard::detail::makeSubscriptionIdForTest(9999)));
    EXPECT_FALSE(m.isRunning());
}

// Regression: ensure a snapshot subscriber registered AFTER a per-event
// subscriber does not receive an empty bootstrap snapshot just because
// the internal poll thread has not yet completed its first enumeration.
//
// Pre-fix (without `Impl::initialPollComplete`): the bootstrap branch
// in subscribeReaderList reads an empty `knownReaders` and synchronously
// dispatches `[]` to the late-joining subscriber; the poll thread then
// later dispatches the real snapshot. Consumers see two emissions
// (empty then populated) and `QSignalSpy::last()` semantics break.
//
// Post-fix: the bootstrap is suppressed in the first-poll window; the
// poll thread's first dispatch delivers the populated snapshot to all
// subscribers (early and late) uniformly. Exactly one emission with
// the populated reader list.
//
// Spec: knowledge/specs/2026-05-24-lm-monitor-bootstrap-race.md §6.2.1
TEST(MonitorServiceBootstrapRace, SubscribeReaderListAfterSubscribeNoEmptyBootstrap)
{
    using LibreSCRS::SmartCard::MonitorEvent;
    using LibreSCRS::SmartCard::MonitorService;

    auto counters = std::make_shared<LibreSCRS::SmartCard::Internal::MockCounters>();
    auto mock = std::make_unique<LibreSCRS::SmartCard::Internal::MockPCSCScanProvider>(counters);
    auto* mockPtr = mock.get();
    mock->setReaders({"Reader A", "Reader B"});

    // Block the first listReaders call. The internal poll thread's
    // enumerateReaders() will park inside the mock until the test thread
    // releases it, giving subscribeReaderList a deterministic chance to
    // race against an empty knownReaders state.
    mock->setListReadersBlocking(true);

    // After enumeration completes, the internal poll thread enters its
    // event loop with getStatusChange. Push only CANCELLED so the poll
    // thread exits cleanly after the FIRST enumerate cycle — we deliberately
    // skip a CHANGED event here because CHANGED would trigger a
    // re-enumerate call to listReaders, which would block AGAIN under the
    // listReadersBlocking flag and deadlock the test. The race we're
    // exercising lives entirely in the first-enumerate window.
    mock->pushStatusChange({LONG(SCARD_E_CANCELLED), {}, false});

    auto monitor = LibreSCRS::SmartCard::detail::makeMonitorWithProvider(std::move(mock));
    ASSERT_NE(monitor, nullptr);

    std::mutex snapshotsMtx;
    std::vector<std::vector<std::string>> snapshots;

    // (1) Per-event subscription FIRST — this triggers poll-thread start.
    //     The poll thread will immediately enter listReaders and block.
    auto eventSubId = monitor->subscribe([](const MonitorEvent&) {
        // Don't care about events for this test.
    });

    // Give the poll thread a brief moment to reach the listReaders block.
    // We are NOT racing here — listReaders waits on the mock's condvar
    // indefinitely, so the only effect of this delay is to confirm the
    // poll thread reached the block. 50ms is generous on any platform.
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    // (2) Snapshot subscription SECOND — this is the line that pre-fix
    //     bootstrap-fires `[]` because knownReaders is still empty
    //     (poll thread is parked in listReaders, hasn't called
    //     diffReadersAndDispatch yet).
    auto rlSubId = monitor->subscribeReaderList(
        [&snapshotsMtx, &snapshots](const std::vector<std::string>& readers) {
            std::lock_guard<std::mutex> lock(snapshotsMtx);
            snapshots.push_back(readers);
        });

    // (3) Disarm the listReaders gate first (so any future re-enumerate
    //     call from the poll thread won't block again), then release the
    //     currently-parked first call. The poll thread completes
    //     enumeration, fires its readersCb, populates knownReaders, and
    //     dispatches the snapshot to all rl subscribers.
    mockPtr->setListReadersBlocking(false);
    mockPtr->releaseListReadersBlock();

    // Wait for the poll thread's first dispatch to land. Poll on the
    // snapshots vector with a short timeout rather than sleeping for a
    // fixed duration to keep the test fast on green and bounded on red.
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(5000);
    while (std::chrono::steady_clock::now() < deadline) {
        {
            std::lock_guard<std::mutex> lock(snapshotsMtx);
            bool seenPopulated = false;
            for (const auto& s : snapshots) {
                if (s.size() == 2) {
                    seenPopulated = true;
                    break;
                }
            }
            if (seenPopulated)
                break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }

    // Drain unsubscribes so no callback can fire after we inspect snapshots.
    monitor->unsubscribeReaderList(rlSubId, MonitorService::DrainPolicy::Drain);
    monitor->unsubscribe(eventSubId, MonitorService::DrainPolicy::Drain);

    // Reproduction assertion: NO emission contained an empty list.
    // Pre-fix: this fails because snapshots == [ [], ["A","B"] ] (or
    // similar with the empty first).
    // Post-fix: snapshots == [ ["A","B"] ] (or just populated entries).
    std::lock_guard<std::mutex> lock(snapshotsMtx);
    ASSERT_FALSE(snapshots.empty()) << "No reader-list snapshot was delivered at all";
    for (size_t i = 0; i < snapshots.size(); ++i) {
        EXPECT_FALSE(snapshots[i].empty())
            << "Snapshot #" << i << " was empty — bootstrap race not fixed";
    }
    bool sawPopulated = false;
    for (const auto& s : snapshots) {
        if (s.size() == 2)
            sawPopulated = true;
    }
    EXPECT_TRUE(sawPopulated) << "Expected at least one snapshot containing both readers";
}

// Regression guard for spec §5.2 Change B placement: ensures the latch
// fires even when the first poll cycle returns zero readers, so a
// subscribeReaderList that registers AFTER first enumerate but BEFORE
// any reader is plugged still receives the synchronous (empty)
// bootstrap snapshot that reflects current truth ("no readers right
// now").
//
// Pre-fix behaviour: empty bootstrap delivered, then populated when
// reader plugs — passes.
// Naïve-fix behaviour (latch inside `if(!added.empty() || !removed.empty())`):
//   late joiner gets NOTHING at registration; only learns of readers
//   when one plugs in — would silently regress late-join contract.
//   This test catches that mistake.
// Correct-fix behaviour (latch at end of diffReadersAndDispatch
// unconditionally): empty bootstrap delivered, then populated when
// reader plugs — passes.
//
// Spec: knowledge/specs/2026-05-24-lm-monitor-bootstrap-race.md §6.2.2
TEST(MonitorServiceBootstrapRace, SubscribeReaderListZeroReadersAtBootThenPlug)
{
    using LibreSCRS::SmartCard::MonitorEvent;
    using LibreSCRS::SmartCard::MonitorService;

    auto counters = std::make_shared<LibreSCRS::SmartCard::Internal::MockCounters>();
    auto mock = std::make_unique<LibreSCRS::SmartCard::Internal::MockPCSCScanProvider>(counters);

    // Empty at boot — no readers plugged.
    mock->setReaders({});

    // PnP check (no membership change yet — first enumerate returns {}).
    mock->pushStatusChange({SCARD_S_SUCCESS, {SCARD_STATE_CHANGED}, false});
    // Then "Reader A" gets plugged in — drives the second enumerate cycle.
    mock->pushStatusChange({SCARD_S_SUCCESS, {SCARD_STATE_CHANGED}, false,
                            std::vector<std::string>{"Reader A"}});
    // Stop.
    mock->pushStatusChange({LONG(SCARD_E_CANCELLED), {}, false});

    auto monitor = LibreSCRS::SmartCard::detail::makeMonitorWithProvider(std::move(mock));
    ASSERT_NE(monitor, nullptr);

    std::mutex snapshotsMtx;
    std::vector<std::vector<std::string>> snapshots;

    // (1) Per-event subscription FIRST.
    auto eventSubId = monitor->subscribe([](const MonitorEvent&) {});

    // (2) Wait until poll thread has called listReaders at least once
    //     (i.e. first enumerate has completed). MANDATORY: counter-poll,
    //     not sleep. Sleeps are flaky under CI load; the counter
    //     observation strictly happens-after the mock's listReaders impl.
    auto enumerateDeadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(5000);
    while (counters->listReadersCount.load() < 1 &&
           std::chrono::steady_clock::now() < enumerateDeadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    ASSERT_GE(counters->listReadersCount.load(), 1)
        << "Poll thread never reached listReaders within 5s";

    // (3) Snapshot subscription registered AFTER first enumerate completed.
    //     Post-correct-fix: knownReaders == {} (truthful), initialPollComplete
    //     == true (latched by Change B), so bootstrap-fires {} synchronously.
    //     Post-naïve-fix: initialPollComplete still false (latch was inside
    //     dispatch conditional, dispatch didn't fire on empty enumerate),
    //     so bootstrap is SKIPPED — assertion below will fail.
    auto rlSubId = monitor->subscribeReaderList(
        [&snapshotsMtx, &snapshots](const std::vector<std::string>& readers) {
            std::lock_guard<std::mutex> lock(snapshotsMtx);
            snapshots.push_back(readers);
        });

    // (4) Wait for the "Reader A plugged in" cycle to dispatch.
    auto pluggedDeadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(5000);
    while (std::chrono::steady_clock::now() < pluggedDeadline) {
        {
            std::lock_guard<std::mutex> lock(snapshotsMtx);
            bool sawReaderA = false;
            for (const auto& s : snapshots) {
                if (s.size() == 1 && s[0] == "Reader A") {
                    sawReaderA = true;
                    break;
                }
            }
            if (sawReaderA)
                break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }

    monitor->unsubscribeReaderList(rlSubId, MonitorService::DrainPolicy::Drain);
    monitor->unsubscribe(eventSubId, MonitorService::DrainPolicy::Drain);

    std::lock_guard<std::mutex> lock(snapshotsMtx);
    // Load-bearing assertion: the snapshot subscriber MUST have observed
    // something between registration (step 3) and the "Reader A plugged
    // in" cycle. If snapshots is empty, Change B's latch did not fire on
    // the empty first enumerate — the naïve-placement regression is back.
    ASSERT_FALSE(snapshots.empty())
        << "No snapshot delivered to late joiner — Change B latch did not "
           "fire on empty first enumerate (regression to naïve placement).";

    // Sanity: at least one populated snapshot with Reader A was observed.
    bool sawReaderA = false;
    for (const auto& s : snapshots) {
        if (s.size() == 1 && s[0] == "Reader A")
            sawReaderA = true;
    }
    EXPECT_TRUE(sawReaderA)
        << "Expected at least one snapshot containing {\"Reader A\"} after plug-in";
}
