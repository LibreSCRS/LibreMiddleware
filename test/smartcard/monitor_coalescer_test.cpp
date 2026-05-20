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
