// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <LibreSCRS/SmartCard/MonitorService.h>

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

using LibreSCRS::SmartCard::MonitorEvent;
using LibreSCRS::SmartCard::MonitorService;

namespace {

// Subscribe-time auto-start of the real PC/SC poll thread can leak
// Reader{Added,Removed} and real Card{Inserted,Removed} events into the
// harness when the host machine has live readers and cards. Filter to
// synthetic events whose reader name carries the well-known harness prefix
// so coalescer expectations are independent of host hardware.
constexpr const char* kSyntheticReaderPrefix = "LRMCT/";

bool isSyntheticCardEvent(const MonitorEvent& ev) noexcept
{
    if (ev.kind != MonitorEvent::Kind::CardInserted && ev.kind != MonitorEvent::Kind::CardRemoved) {
        return false;
    }
    return ev.readerName.rfind(kSyntheticReaderPrefix, 0) == 0;
}

class CoalescerHarness : public ::testing::Test
{
protected:
    void SetUp() override
    {
        received.clear();
        service =
            std::make_unique<MonitorService>(MonitorService::Config{.coalesceWindow = std::chrono::milliseconds(250)});
        subId = service->subscribe([this](const MonitorEvent& ev) {
            if (!isSyntheticCardEvent(ev))
                return;
            std::scoped_lock lk(mtx);
            received.push_back(ev);
        });
    }

    void TearDown() override
    {
        if (service) {
            service->unsubscribe(subId);
            service.reset();
        }
    }

    void emit(MonitorEvent::Kind kind, const std::string& reader)
    {
        MonitorEvent ev{kind, std::string(kSyntheticReaderPrefix) + reader, std::nullopt, std::nullopt};
        service->publishForTest(ev); // test seam — exposes Impl::dispatch
    }

    std::vector<MonitorEvent> snapshot()
    {
        std::scoped_lock lk(mtx);
        return received;
    }

    std::unique_ptr<MonitorService> service;
    MonitorService::SubscriptionId subId{};
    std::mutex mtx;
    std::vector<MonitorEvent> received;
};

TEST_F(CoalescerHarness, SuppressesInsertedRemovedWithinWindow)
{
    emit(MonitorEvent::Kind::CardInserted, "Phantom Reader");
    emit(MonitorEvent::Kind::CardRemoved, "Phantom Reader");

    // Sleep past window to flush any pending coalescer state
    std::this_thread::sleep_for(std::chrono::milliseconds(400));

    EXPECT_EQ(snapshot().size(), 0u) << "Inserted+Removed within 250ms must be suppressed as transient";
}

TEST_F(CoalescerHarness, AllowsInsertedAloneAcrossWindow)
{
    emit(MonitorEvent::Kind::CardInserted, "Real Reader");
    std::this_thread::sleep_for(std::chrono::milliseconds(400));
    emit(MonitorEvent::Kind::CardRemoved, "Real Reader");
    std::this_thread::sleep_for(std::chrono::milliseconds(400));

    auto snap = snapshot();
    EXPECT_EQ(snap.size(), 2u) << "Inserted then Removed > 250ms apart are real card transitions";
    EXPECT_EQ(snap[0].kind, MonitorEvent::Kind::CardInserted);
    EXPECT_EQ(snap[1].kind, MonitorEvent::Kind::CardRemoved);
}

TEST_F(CoalescerHarness, IndependentReadersDoNotCoalesce)
{
    emit(MonitorEvent::Kind::CardInserted, "Reader A");
    emit(MonitorEvent::Kind::CardRemoved, "Reader B");
    std::this_thread::sleep_for(std::chrono::milliseconds(400));

    EXPECT_EQ(snapshot().size(), 2u) << "Coalescing is per-reader, not global";
}

TEST_F(CoalescerHarness, ReaderRemovedEvictsCoalesceState)
{
    // Hold a CardInserted on a soon-to-vanish reader. The held event sits
    // in coalesceState[readerName] until either the window expires or the
    // reader disappears.
    const std::string fullName = std::string(kSyntheticReaderPrefix) + "Vanishing Reader";
    emit(MonitorEvent::Kind::CardInserted, "Vanishing Reader");

    const auto beforeSize = service->coalesceStateSizeForTest();
    EXPECT_GE(beforeSize, 1u) << "CardInserted must populate coalesceState[Vanishing Reader]";

    // Drive the reader-list diff path: first announce the reader so it
    // becomes known, then announce an empty list so it is diffed out as
    // ReaderRemoved — the same path used by the real PC/SC reader-list
    // callback. The ReaderRemoved branch must erase the held entry under
    // coalesceMtx so coalesceState does not accumulate forever across
    // long-running sessions with USB reader churn.
    service->publishReaderListForTest({fullName});
    service->publishReaderListForTest({});

    EXPECT_LT(service->coalesceStateSizeForTest(), beforeSize)
        << "ReaderRemoved must evict coalesceState[Vanishing Reader]";

    // And the held CardInserted must NOT surface after the original
    // window elapses — the reader it referred to is now absent.
    std::this_thread::sleep_for(std::chrono::milliseconds(400));
    auto snap = snapshot();
    for (const auto& ev : snap) {
        EXPECT_NE(ev.readerName, fullName) << "Held CardInserted for a vanished reader must not reach subscribers";
    }
}

TEST_F(CoalescerHarness, FloodTriggersBackoffWithWarning)
{
    setenv("LIBRESCRS_MONITOR_COALESCE_MS", "0", 1);
    service->unsubscribe(subId);
    service.reset();
    service = std::make_unique<MonitorService>(MonitorService::Config{
        .coalesceWindow = std::chrono::milliseconds(0),
        .maxEventsPerSecond = 5,
        .backoffOnFlood = std::chrono::milliseconds(500),
    });
    subId = service->subscribe([this](const MonitorEvent& ev) {
        if (!isSyntheticCardEvent(ev))
            return;
        std::scoped_lock lk(mtx);
        received.push_back(ev);
    });

    // Fire 20 events as fast as possible — limit is 5/s. The first ~5
    // pass through; subsequent events in the 1s window trip the flood
    // gate and enter backoff. Allow 1 extra event of boundary tolerance.
    for (int i = 0; i < 20; ++i) {
        emit(i % 2 == 0 ? MonitorEvent::Kind::CardInserted : MonitorEvent::Kind::CardRemoved, "Flood Reader");
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    EXPECT_LE(snapshot().size(), 6u) << "Flood detection must cap dispatched events near the threshold";
    unsetenv("LIBRESCRS_MONITOR_COALESCE_MS");
}

// Regression for the OMNIKEY 5422 / dual-interface contactless race: such a
// reader emits a burst of bogus Inserted/Removed pairs when a contactless
// card lands, then SETTLES with the card PRESENT. The burst trips the flood
// gate into backoff; the genuine terminal CardInserted arrives DURING that
// backoff. It must still reach subscribers (reconciled when the backoff
// expires) — otherwise the card is physically present but stays invisible
// until a manual re-seat / agent restart.
TEST_F(CoalescerHarness, TerminalCardInsertedSurvivesFloodBackoff)
{
    service->unsubscribe(subId);
    service.reset();
    service = std::make_unique<MonitorService>(MonitorService::Config{
        .coalesceWindow = std::chrono::milliseconds(60),
        .maxEventsPerSecond = 4,
        .backoffOnFlood = std::chrono::milliseconds(120),
    });
    subId = service->subscribe([this](const MonitorEvent& ev) {
        if (!isSyntheticCardEvent(ev))
            return;
        std::scoped_lock lk(mtx);
        received.push_back(ev);
    });

    // Bogus flapping burst — >4 events in the 1s window trips the flood gate.
    for (int i = 0; i < 10; ++i) {
        emit(i % 2 == 0 ? MonitorEvent::Kind::CardInserted : MonitorEvent::Kind::CardRemoved, "Flood Reader");
    }
    // The card then settles PRESENT: the genuine terminal CardInserted arrives
    // while the reader is still inside its flood backoff.
    emit(MonitorEvent::Kind::CardInserted, "Flood Reader");

    // Wait past the backoff and any reconcile flush.
    std::this_thread::sleep_for(std::chrono::milliseconds(400));

    auto snap = snapshot();
    ASSERT_FALSE(snap.empty()) << "a card present after a flood burst was never reported to subscribers";
    EXPECT_EQ(snap.back().kind, MonitorEvent::Kind::CardInserted)
        << "the terminal CardInserted (settled card) was dropped by the flood backoff — the present card stays "
           "invisible";
}

// Regression for the cross-reader flusher-parking bug: the flusher sleeps on
// the earliest deadline it computed when it went to sleep. A flood backoff is
// a deadline SECONDS away; a healthy reader's held event created while the
// flusher sleeps is a deadline MILLISECONDS away. Every wake must recompute
// the earliest deadline — otherwise the healthy reader's genuine event is
// delivered only when the flooding reader's backoff expires (seconds late,
// during which a genuine opposite event would silently pair-cancel it).
TEST_F(CoalescerHarness, HealthyReaderEventNotDelayedByOtherReadersFloodBackoff)
{
    service->unsubscribe(subId);
    service.reset();
    service = std::make_unique<MonitorService>(MonitorService::Config{
        .coalesceWindow = std::chrono::milliseconds(60),
        .maxEventsPerSecond = 4,
        .backoffOnFlood = std::chrono::milliseconds(3000),
    });
    subId = service->subscribe([this](const MonitorEvent& ev) {
        if (!isSyntheticCardEvent(ev))
            return;
        std::scoped_lock lk(mtx);
        received.push_back(ev);
    });

    // Reader A floods into a LONG backoff: the first 4 events are accepted
    // (two opposite pairs that cancel in the coalescer), the 5th trips the
    // gate, so the flusher's earliest deadline becomes A's backoff expiry
    // ~3000ms out.
    for (int i = 0; i < 10; ++i) {
        emit(i % 2 == 0 ? MonitorEvent::Kind::CardInserted : MonitorEvent::Kind::CardRemoved, "Reader A");
    }

    // Let the burst's own 60ms hold deadlines drain so the flusher is
    // provably parked on A's backoff expiry (and nothing earlier) when B's
    // event arrives — the exact state the parking bug needs.
    std::this_thread::sleep_for(std::chrono::milliseconds(150));

    // Reader B then gets a genuine CardInserted, held for its 60ms window.
    emit(MonitorEvent::Kind::CardInserted, "Reader B");

    // B's event must flush shortly after ITS window expires — well before
    // A's backoff expiry — so wait far less than the 3000ms backoff.
    std::this_thread::sleep_for(std::chrono::milliseconds(400));

    auto snap = snapshot();
    ASSERT_EQ(snap.size(), 1u) << "reader B's genuine CardInserted was parked behind reader A's flood backoff";
    EXPECT_EQ(snap[0].kind, MonitorEvent::Kind::CardInserted);
    EXPECT_EQ(snap[0].readerName, std::string(kSyntheticReaderPrefix) + "Reader B");
}

// The reconcile is direction-symmetric: a flood that settles with the card
// ABSENT while the subscriber still believes it present must surface the
// terminal CardRemoved once the backoff expires — the mirror of the settled
// CardInserted case above.
TEST_F(CoalescerHarness, TerminalCardRemovedSurvivesFloodBackoff)
{
    service->unsubscribe(subId);
    service.reset();
    service = std::make_unique<MonitorService>(MonitorService::Config{
        .coalesceWindow = std::chrono::milliseconds(60),
        .maxEventsPerSecond = 5,
        .backoffOnFlood = std::chrono::milliseconds(120),
    });
    subId = service->subscribe([this](const MonitorEvent& ev) {
        if (!isSyntheticCardEvent(ev))
            return;
        std::scoped_lock lk(mtx);
        received.push_back(ev);
    });

    // Establish the subscriber's belief: a genuine CardInserted flushes
    // after its 60ms hold window.
    emit(MonitorEvent::Kind::CardInserted, "Flood Reader");
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    ASSERT_EQ(snapshot().size(), 1u) << "the genuine CardInserted must flush before the burst starts";

    // Bogus flapping burst: the accepted events pair-cancel in the
    // coalescer; the 5th card event inside the rolling 1s window (counting
    // the genuine CardInserted above) trips the flood gate.
    for (int i = 0; i < 10; ++i) {
        emit(i % 2 == 0 ? MonitorEvent::Kind::CardRemoved : MonitorEvent::Kind::CardInserted, "Flood Reader");
    }
    // The card settles ABSENT: the genuine terminal CardRemoved arrives
    // while the reader is still inside its flood backoff.
    emit(MonitorEvent::Kind::CardRemoved, "Flood Reader");

    // Wait past the backoff and any reconcile flush.
    std::this_thread::sleep_for(std::chrono::milliseconds(400));

    auto snap = snapshot();
    ASSERT_EQ(snap.size(), 2u) << "a card removed during a flood burst was never reconciled to subscribers";
    EXPECT_EQ(snap.back().kind, MonitorEvent::Kind::CardRemoved)
        << "the terminal CardRemoved (settled absent) was dropped by the flood backoff — a phantom card stays visible";
}

// Suppression branch: a flood that settles in the state the subscriber
// ALREADY believes must produce no reconcile event. The settled CardInserted
// below matches the belief established before the burst, so nothing further
// may surface after the backoff expires — the exact event count is pinned so
// an unconditional reconcile emit (redundant repeat, or its phantom
// Removed-with-no-prior-card mirror) cannot slip through undetected.
TEST_F(CoalescerHarness, FloodSettlingInKnownStateEmitsNothingOnReconcile)
{
    service->unsubscribe(subId);
    service.reset();
    service = std::make_unique<MonitorService>(MonitorService::Config{
        .coalesceWindow = std::chrono::milliseconds(60),
        .maxEventsPerSecond = 5,
        .backoffOnFlood = std::chrono::milliseconds(120),
    });
    subId = service->subscribe([this](const MonitorEvent& ev) {
        if (!isSyntheticCardEvent(ev))
            return;
        std::scoped_lock lk(mtx);
        received.push_back(ev);
    });

    // Establish the subscriber's belief: the card is present.
    emit(MonitorEvent::Kind::CardInserted, "Flood Reader");
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    ASSERT_EQ(snapshot().size(), 1u) << "the genuine CardInserted must flush before the burst starts";

    // Bogus flapping burst trips the flood gate (see the mirror test above),
    // then the card settles PRESENT — matching the existing belief.
    for (int i = 0; i < 10; ++i) {
        emit(i % 2 == 0 ? MonitorEvent::Kind::CardRemoved : MonitorEvent::Kind::CardInserted, "Flood Reader");
    }
    emit(MonitorEvent::Kind::CardInserted, "Flood Reader");

    // Wait past the backoff and any reconcile flush.
    std::this_thread::sleep_for(std::chrono::milliseconds(400));

    auto snap = snapshot();
    ASSERT_EQ(snap.size(), 1u) << "a flood settling in the already-known state must not emit a reconcile event";
    EXPECT_EQ(snap[0].kind, MonitorEvent::Kind::CardInserted);
}

// The reconcile ordering must hold for EVERY coalesceWindow/backoffOnFlood
// combination, including coalesceWindow > backoffOnFlood. In that
// configuration a genuine held CardInserted is still inside its hold window
// when the flood backoff expires; the reconcile must flush that older held
// event first and only then compare the suppressed terminal state against
// the subscriber's belief. Otherwise the terminal CardRemoved is compared
// against a belief that does not yet include the held CardInserted, gets
// suppressed as redundant, and the stale CardInserted flushes LAST — leaving
// the subscriber believing a phantom card is present.
TEST_F(CoalescerHarness, ReconcileOrderingHoldsWhenCoalesceWindowExceedsBackoff)
{
    service->unsubscribe(subId);
    service.reset();
    service = std::make_unique<MonitorService>(MonitorService::Config{
        .coalesceWindow = std::chrono::milliseconds(300),
        .maxEventsPerSecond = 4,
        .backoffOnFlood = std::chrono::milliseconds(120),
    });
    subId = service->subscribe([this](const MonitorEvent& ev) {
        if (!isSyntheticCardEvent(ev))
            return;
        std::scoped_lock lk(mtx);
        received.push_back(ev);
    });

    // Arm a held CardInserted via same-kind repeats (each refresh keeps the
    // hold alive without emitting); the repeats also fill the rolling 1s
    // window right up to the 4/s ceiling.
    for (int i = 0; i < 4; ++i) {
        emit(MonitorEvent::Kind::CardInserted, "Flood Reader");
    }
    // The next event trips the flood gate (120ms backoff) and becomes the
    // suppressed terminal state: the card settles ABSENT while the held
    // CardInserted's 300ms window is still running.
    emit(MonitorEvent::Kind::CardRemoved, "Flood Reader");

    // Wait past the backoff expiry, the hold window and any flush.
    std::this_thread::sleep_for(std::chrono::milliseconds(700));

    auto snap = snapshot();
    ASSERT_FALSE(snap.empty()) << "neither the held CardInserted nor the settled CardRemoved surfaced";
    EXPECT_EQ(snap.back().kind, MonitorEvent::Kind::CardRemoved)
        << "a stale held CardInserted flushed after the reconcile — the subscriber is left believing a phantom card "
           "is present";
    // Chronological order: the genuine CardInserted (older, held) precedes
    // the settled CardRemoved (newer, flood-suppressed) — never trails it.
    ASSERT_EQ(snap.size(), 2u) << "expected exactly the held CardInserted followed by the reconciled CardRemoved";
    EXPECT_EQ(snap[0].kind, MonitorEvent::Kind::CardInserted);
    EXPECT_EQ(snap[1].kind, MonitorEvent::Kind::CardRemoved);
}

TEST_F(CoalescerHarness, EnvVarZeroDisablesCoalescing)
{
    setenv("LIBRESCRS_MONITOR_COALESCE_MS", "0", 1);
    service->unsubscribe(subId);
    service.reset();
    service = std::make_unique<MonitorService>(MonitorService::Config::fromEnv());
    subId = service->subscribe([this](const MonitorEvent& ev) {
        if (!isSyntheticCardEvent(ev))
            return;
        std::scoped_lock lk(mtx);
        received.push_back(ev);
    });

    emit(MonitorEvent::Kind::CardInserted, "Phantom Reader");
    emit(MonitorEvent::Kind::CardRemoved, "Phantom Reader");
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    EXPECT_EQ(snapshot().size(), 2u) << "Env override = 0 must disable coalescing for diagnosis";
    unsetenv("LIBRESCRS_MONITOR_COALESCE_MS");
}

} // namespace
