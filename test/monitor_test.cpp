// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0 and LibreSCRS contributors

#include "mock_pcsc_scan_provider.h"
#include <monitor.h>
#include <LibreSCRS/Logging.h>
#include <gtest/gtest.h>
#include <algorithm>
#include <atomic>
#include <chrono>
#include <mutex>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

using namespace LibreSCRS::SmartCard::Internal;

class MonitorTestFixture : public ::testing::Test
{
protected:
    void SetUp() override
    {
        counters = std::make_shared<MockCounters>();
    }

    struct RunResult
    {
        std::vector<std::string> lastReaderList;
        std::vector<MonitorEvent> events;
    };

    RunResult runMonitor(std::unique_ptr<MockPCSCScanProvider> mock, int maxWaitMs = 500)
    {
        RunResult result;
        std::mutex mtx;
        {
            Monitor monitor(std::move(mock));
            monitor.subscribe(
                [&](const MonitorEvent& e) {
                    std::lock_guard lock(mtx);
                    result.events.push_back(e);
                },
                [&](const std::vector<std::string>& readers) {
                    std::lock_guard lock(mtx);
                    result.lastReaderList = readers;
                });
            std::this_thread::sleep_for(std::chrono::milliseconds(maxWaitMs));
        }
        return result;
    }

    std::shared_ptr<MockCounters> counters;
};

// --- Test 1: No readers available ---
TEST_F(MonitorTestFixture, NoReadersEmitsEmptyList)
{
    auto mock = std::make_unique<MockPCSCScanProvider>(counters);

    // PnP check: return UNKNOWN (no PnP)
    mock->pushStatusChange({SCARD_S_SUCCESS, {SCARD_STATE_UNKNOWN}, false});

    auto result = runMonitor(std::move(mock));

    EXPECT_TRUE(result.lastReaderList.empty());
    EXPECT_TRUE(result.events.empty());
    EXPECT_GE(counters->establishContextCount.load(), 1);
}

// --- Test 2: One reader, card inserted ---
TEST_F(MonitorTestFixture, CardInserted)
{
    auto mock = std::make_unique<MockPCSCScanProvider>(counters);
    mock->setReaders({"Reader A"});

    // PnP check: supported
    mock->pushStatusChange({SCARD_S_SUCCESS, {SCARD_STATE_CHANGED}, false});

    // Card present on reader, PnP unchanged
    mock->pushStatusChange(
        {SCARD_S_SUCCESS, {SCARD_STATE_PRESENT | SCARD_STATE_CHANGED, 0 /* PnP unchanged */}, false});

    // Stop
    mock->pushStatusChange({LONG(SCARD_E_CANCELLED), {}, false});

    auto result = runMonitor(std::move(mock));

    EXPECT_EQ(result.lastReaderList.size(), 1u);
    EXPECT_EQ(result.lastReaderList[0], "Reader A");
    ASSERT_EQ(result.events.size(), 1u);
    EXPECT_EQ(result.events[0].type, MonitorEvent::Type::CardInserted);
    EXPECT_EQ(result.events[0].readerName, "Reader A");
}

// --- Test 2b: Card inserted with ATR data ---
TEST_F(MonitorTestFixture, CardInsertedHasATR)
{
    auto mock = std::make_unique<MockPCSCScanProvider>(counters);
    mock->setReaders({"Reader A"});

    // PnP check: supported
    mock->pushStatusChange({SCARD_S_SUCCESS, {SCARD_STATE_CHANGED}, false});

    // Card present on reader with ATR data
    MockPCSCScanProvider::StatusChangeAction cardAction;
    cardAction.returnValue = SCARD_S_SUCCESS;
    cardAction.eventStates = {SCARD_STATE_PRESENT | SCARD_STATE_CHANGED, 0 /* PnP unchanged */};
    cardAction.atrData = {{0x3B, 0x9F, 0x95, 0x81, 0x31, 0xFE}};
    mock->pushStatusChange(std::move(cardAction));

    // Stop
    mock->pushStatusChange({LONG(SCARD_E_CANCELLED), {}, false});

    auto result = runMonitor(std::move(mock));

    ASSERT_EQ(result.events.size(), 1u);
    EXPECT_EQ(result.events[0].type, MonitorEvent::Type::CardInserted);
    EXPECT_EQ(result.events[0].readerName, "Reader A");

    std::vector<uint8_t> expectedAtr = {0x3B, 0x9F, 0x95, 0x81, 0x31, 0xFE};
    EXPECT_EQ(result.events[0].atr, expectedAtr);
}

// --- A card already seated when monitoring starts must still emit
// CardInserted, even when the same first poll also reports a PnP reader-arrival
// change. Pre-fix, the PnP "changed" branch re-enumerated before the per-reader
// card states were processed, so a card present at startup (or in a reader
// hot-plugged with a card already in it) was silently never reported until a
// physical re-seat. ---
TEST_F(MonitorTestFixture, CardPresentAtStartupWithReaderArrivalEmitsCardInserted)
{
    auto mock = std::make_unique<MockPCSCScanProvider>(counters);
    mock->setReaders({"Reader A"});

    // PnP check: supported
    mock->pushStatusChange({SCARD_S_SUCCESS, {SCARD_STATE_CHANGED}, false});

    // First poll: the card is already PRESENT AND the PnP pseudo-reader signals
    // a reader-arrival change at the same time (the real start-up / hot-plug
    // case). The card state MUST be reported before the re-enumeration.
    MockPCSCScanProvider::StatusChangeAction cardAction;
    cardAction.returnValue = SCARD_S_SUCCESS;
    cardAction.eventStates = {SCARD_STATE_PRESENT | SCARD_STATE_CHANGED, SCARD_STATE_CHANGED /* PnP arrival */};
    cardAction.atrData = {{0x3B, 0x00}};
    mock->pushStatusChange(std::move(cardAction));

    // Stop
    mock->pushStatusChange({LONG(SCARD_E_CANCELLED), {}, false});

    auto result = runMonitor(std::move(mock));

    ASSERT_FALSE(result.events.empty()) << "card present at startup was never reported";
    EXPECT_EQ(result.events[0].type, MonitorEvent::Type::CardInserted);
    EXPECT_EQ(result.events[0].readerName, "Reader A");
}

// --- Test 3: One reader, card removed ---
TEST_F(MonitorTestFixture, CardRemoved)
{
    auto mock = std::make_unique<MockPCSCScanProvider>(counters);
    mock->setReaders({"Reader A"});

    // PnP check
    mock->pushStatusChange({SCARD_S_SUCCESS, {SCARD_STATE_CHANGED}, false});

    // Card empty (removed)
    mock->pushStatusChange({SCARD_S_SUCCESS, {SCARD_STATE_EMPTY | SCARD_STATE_CHANGED, 0}, false});

    // Stop
    mock->pushStatusChange({LONG(SCARD_E_CANCELLED), {}, false});

    auto result = runMonitor(std::move(mock));

    ASSERT_EQ(result.events.size(), 1u);
    EXPECT_EQ(result.events[0].type, MonitorEvent::Type::CardRemoved);
}

// --- Test 4: Card insert then remove ---
TEST_F(MonitorTestFixture, CardInsertThenRemove)
{
    auto mock = std::make_unique<MockPCSCScanProvider>(counters);
    mock->setReaders({"Reader A"});

    // PnP check
    mock->pushStatusChange({SCARD_S_SUCCESS, {SCARD_STATE_CHANGED}, false});

    // Card inserted
    mock->pushStatusChange({SCARD_S_SUCCESS, {SCARD_STATE_PRESENT | SCARD_STATE_CHANGED, 0}, false});

    // Card removed (event counter incremented)
    mock->pushStatusChange({SCARD_S_SUCCESS, {SCARD_STATE_EMPTY | SCARD_STATE_CHANGED | (2 << 16), 0}, false});

    // Stop
    mock->pushStatusChange({LONG(SCARD_E_CANCELLED), {}, false});

    auto result = runMonitor(std::move(mock));

    ASSERT_EQ(result.events.size(), 2u);
    EXPECT_EQ(result.events[0].type, MonitorEvent::Type::CardInserted);
    EXPECT_EQ(result.events[1].type, MonitorEvent::Type::CardRemoved);
}

// --- Test 5: Card present + INUSE (first time) ---
TEST_F(MonitorTestFixture, CardPresentWithInuse)
{
    auto mock = std::make_unique<MockPCSCScanProvider>(counters);
    mock->setReaders({"Reader A"});

    // PnP check
    mock->pushStatusChange({SCARD_S_SUCCESS, {SCARD_STATE_CHANGED}, false});

    // Card present + in use (first time)
    mock->pushStatusChange(
        {SCARD_S_SUCCESS, {SCARD_STATE_PRESENT | SCARD_STATE_INUSE | SCARD_STATE_CHANGED | (1 << 16), 0}, false});

    // Stop
    mock->pushStatusChange({LONG(SCARD_E_CANCELLED), {}, false});

    auto result = runMonitor(std::move(mock));

    ASSERT_EQ(result.events.size(), 1u);
    EXPECT_EQ(result.events[0].type, MonitorEvent::Type::CardInserted);
}

// --- Test 6: INUSE toggle on already-present card — no re-emission ---
TEST_F(MonitorTestFixture, InuseToggleNoReEmission)
{
    auto mock = std::make_unique<MockPCSCScanProvider>(counters);
    mock->setReaders({"Reader A"});

    // PnP check
    mock->pushStatusChange({SCARD_S_SUCCESS, {SCARD_STATE_CHANGED}, false});

    // Card inserted (event counter = 1)
    mock->pushStatusChange({SCARD_S_SUCCESS, {SCARD_STATE_PRESENT | SCARD_STATE_CHANGED | (1 << 16), 0}, false});

    // INUSE toggled, same event counter
    mock->pushStatusChange(
        {SCARD_S_SUCCESS, {SCARD_STATE_PRESENT | SCARD_STATE_INUSE | SCARD_STATE_CHANGED | (1 << 16), 0}, false});

    // Stop
    mock->pushStatusChange({LONG(SCARD_E_CANCELLED), {}, false});

    auto result = runMonitor(std::move(mock));

    ASSERT_EQ(result.events.size(), 1u);
    EXPECT_EQ(result.events[0].type, MonitorEvent::Type::CardInserted);
}

// --- A card that stays put must not be re-announced when the reader's event
// counter moves. A contactless reader re-establishes the RF field constantly and
// PC/SC bumps the counter each time; treating that as a swap tore the card down
// and re-published it under a fresh identity, which resets every piece of
// per-card state the agent holds and fails any read in flight. The card's ATR is
// what says whether it is the same card. ---
TEST_F(MonitorTestFixture, SameCardReSeenWithBumpedEventCounterDoesNotReEmit)
{
    auto mock = std::make_unique<MockPCSCScanProvider>(counters);
    mock->setReaders({"Reader A"});

    mock->pushStatusChange({SCARD_S_SUCCESS, {SCARD_STATE_CHANGED}, false});

    MockPCSCScanProvider::StatusChangeAction first;
    first.returnValue = SCARD_S_SUCCESS;
    first.eventStates = {SCARD_STATE_PRESENT | SCARD_STATE_CHANGED | (1 << 16), 0};
    first.atrData = {{0x3B, 0x8E, 0x80, 0x01}};
    mock->pushStatusChange(std::move(first));

    // Same card, same ATR, counter moved on.
    MockPCSCScanProvider::StatusChangeAction again;
    again.returnValue = SCARD_S_SUCCESS;
    again.eventStates = {SCARD_STATE_PRESENT | SCARD_STATE_CHANGED | (2 << 16), 0};
    again.atrData = {{0x3B, 0x8E, 0x80, 0x01}};
    mock->pushStatusChange(std::move(again));

    mock->pushStatusChange({LONG(SCARD_E_CANCELLED), {}, false});

    auto result = runMonitor(std::move(mock));

    ASSERT_EQ(result.events.size(), 1u) << "the same card must be announced once, not once per RF re-read";
    EXPECT_EQ(result.events[0].type, MonitorEvent::Type::CardInserted);
}

// --- A state change that carries NO ATR is not evidence of a new card. A
// contactless reader can report PRESENT mid-transition with nothing readable;
// treating that as a swap is how the churn comes back through the side door. ---
TEST_F(MonitorTestFixture, PresentWithoutAnAtrIsNotTreatedAsASwap)
{
    auto mock = std::make_unique<MockPCSCScanProvider>(counters);
    mock->setReaders({"Reader A"});

    mock->pushStatusChange({SCARD_S_SUCCESS, {SCARD_STATE_CHANGED}, false});

    MockPCSCScanProvider::StatusChangeAction first;
    first.returnValue = SCARD_S_SUCCESS;
    first.eventStates = {SCARD_STATE_PRESENT | SCARD_STATE_CHANGED | (1 << 16), 0};
    first.atrData = {{0x3B, 0x8E, 0x80, 0x01}};
    mock->pushStatusChange(std::move(first));

    // Counter moved, still present, but the ATR came back empty this poll.
    mock->pushStatusChange({SCARD_S_SUCCESS, {SCARD_STATE_PRESENT | SCARD_STATE_CHANGED | (2 << 16), 0}, false});

    mock->pushStatusChange({LONG(SCARD_E_CANCELLED), {}, false});

    auto result = runMonitor(std::move(mock));

    ASSERT_EQ(result.events.size(), 1u) << "no ATR means no evidence, not a different card";
    EXPECT_EQ(result.events[0].type, MonitorEvent::Type::CardInserted);
}

// --- Test 7: Card swap — a DIFFERENT card, told apart by its ATR ---
TEST_F(MonitorTestFixture, CardSwap)
{
    auto mock = std::make_unique<MockPCSCScanProvider>(counters);
    mock->setReaders({"Reader A"});

    // PnP check
    mock->pushStatusChange({SCARD_S_SUCCESS, {SCARD_STATE_CHANGED}, false});

    MockPCSCScanProvider::StatusChangeAction first;
    first.returnValue = SCARD_S_SUCCESS;
    first.eventStates = {SCARD_STATE_PRESENT | SCARD_STATE_CHANGED | (1 << 16), 0};
    first.atrData = {{0x3B, 0x8E, 0x80, 0x01}};
    mock->pushStatusChange(std::move(first));

    // A genuinely different card: counter moved AND the ATR changed.
    MockPCSCScanProvider::StatusChangeAction swapped;
    swapped.returnValue = SCARD_S_SUCCESS;
    swapped.eventStates = {SCARD_STATE_PRESENT | SCARD_STATE_CHANGED | (2 << 16), 0};
    swapped.atrData = {{0x3B, 0xDE, 0x97, 0x00}};
    mock->pushStatusChange(std::move(swapped));

    // Stop
    mock->pushStatusChange({LONG(SCARD_E_CANCELLED), {}, false});

    auto result = runMonitor(std::move(mock));

    ASSERT_EQ(result.events.size(), 3u);
    EXPECT_EQ(result.events[0].type, MonitorEvent::Type::CardInserted);
    EXPECT_EQ(result.events[1].type, MonitorEvent::Type::CardRemoved);
    EXPECT_EQ(result.events[2].type, MonitorEvent::Type::CardInserted);
    EXPECT_EQ(result.events[2].atr, (std::vector<uint8_t>{0x3B, 0xDE, 0x97, 0x00}));
}

// --- Test 8: Exclusive mode — card skipped ---
TEST_F(MonitorTestFixture, ExclusiveModeSkipped)
{
    auto mock = std::make_unique<MockPCSCScanProvider>(counters);
    mock->setReaders({"Reader A"});

    // PnP check
    mock->pushStatusChange({SCARD_S_SUCCESS, {SCARD_STATE_CHANGED}, false});

    // Card in exclusive mode
    mock->pushStatusChange(
        {SCARD_S_SUCCESS, {SCARD_STATE_PRESENT | SCARD_STATE_EXCLUSIVE | SCARD_STATE_CHANGED | (1 << 16), 0}, false});

    // Stop
    mock->pushStatusChange({LONG(SCARD_E_CANCELLED), {}, false});

    auto result = runMonitor(std::move(mock));

    EXPECT_TRUE(result.events.empty());
}

// --- Test 9: Mute card is skipped ---
TEST_F(MonitorTestFixture, MuteCardSkipped)
{
    auto mock = std::make_unique<MockPCSCScanProvider>(counters);
    mock->setReaders({"Reader A"});

    // PnP check
    mock->pushStatusChange({SCARD_S_SUCCESS, {SCARD_STATE_CHANGED}, false});

    // Card present but mute
    mock->pushStatusChange(
        {SCARD_S_SUCCESS, {SCARD_STATE_PRESENT | SCARD_STATE_MUTE | SCARD_STATE_CHANGED | (1 << 16), 0}, false});

    // Stop
    mock->pushStatusChange({LONG(SCARD_E_CANCELLED), {}, false});

    auto result = runMonitor(std::move(mock));

    EXPECT_TRUE(result.events.empty());
}

// --- Test 10: UNKNOWN state triggers re-enumeration with CardRemoved ---
TEST_F(MonitorTestFixture, UnknownStateTriggersReEnumeration)
{
    auto mock = std::make_unique<MockPCSCScanProvider>(counters);
    mock->setReaders({"Reader A"});

    // PnP check
    mock->pushStatusChange({SCARD_S_SUCCESS, {SCARD_STATE_CHANGED}, false});

    // Reader goes unknown (disconnected)
    mock->pushStatusChange({SCARD_S_SUCCESS, {SCARD_STATE_UNKNOWN | SCARD_STATE_CHANGED, 0}, false});

    // After re-enumeration: cancel
    mock->pushStatusChange({LONG(SCARD_E_CANCELLED), {}, false});

    auto result = runMonitor(std::move(mock));

    ASSERT_GE(result.events.size(), 1u);
    EXPECT_EQ(result.events[0].type, MonitorEvent::Type::CardRemoved);
}

// --- Test 11: NO_SERVICE triggers cleanup and re-establish ---
TEST_F(MonitorTestFixture, NoServiceReEstablishesContext)
{
    auto mock = std::make_unique<MockPCSCScanProvider>(counters);
    mock->setReaders({"Reader A"});

    // PnP check
    mock->pushStatusChange({SCARD_S_SUCCESS, {SCARD_STATE_CHANGED}, false});

    // Card present
    mock->pushStatusChange({SCARD_S_SUCCESS, {SCARD_STATE_PRESENT | SCARD_STATE_CHANGED | (1 << 16), 0}, false});

    // PC/SC service goes down
    mock->pushStatusChange({LONG(SCARD_E_NO_SERVICE), {}, false});

    // After re-establish: cancel
    mock->pushStatusChange({LONG(SCARD_E_CANCELLED), {}, false});

    auto result = runMonitor(std::move(mock));

    ASSERT_GE(result.events.size(), 2u);
    EXPECT_EQ(result.events[0].type, MonitorEvent::Type::CardInserted);
    EXPECT_EQ(result.events[1].type, MonitorEvent::Type::CardRemoved);

    EXPECT_GE(counters->establishContextCount.load(), 2);
}

// --- Test 12: PnP reader count change triggers re-enumeration ---
TEST_F(MonitorTestFixture, PnPReaderChangeTriggersReEnumeration)
{
    auto mock = std::make_unique<MockPCSCScanProvider>(counters);
    mock->setReaders({"Reader A"});

    // PnP check: supported
    mock->pushStatusChange({SCARD_S_SUCCESS, {SCARD_STATE_CHANGED}, false});

    // PnP slot (index 1) reports change
    mock->pushStatusChange(
        {SCARD_S_SUCCESS, {0 /* reader A unchanged */, SCARD_STATE_CHANGED /* PnP changed */}, false});

    // After re-enumeration: cancel
    mock->pushStatusChange({LONG(SCARD_E_CANCELLED), {}, false});

    auto result = runMonitor(std::move(mock));

    EXPECT_FALSE(result.lastReaderList.empty());
}

// --- Test 13: Multiple readers, card in reader B ---
TEST_F(MonitorTestFixture, MultipleReaders)
{
    auto mock = std::make_unique<MockPCSCScanProvider>(counters);
    mock->setReaders({"Reader A", "Reader B"});

    // PnP check
    mock->pushStatusChange({SCARD_S_SUCCESS, {SCARD_STATE_CHANGED}, false});

    // Card in reader B (index 1)
    mock->pushStatusChange(
        {SCARD_S_SUCCESS,
         {0 /* Reader A no change */, SCARD_STATE_PRESENT | SCARD_STATE_CHANGED | (1 << 16), 0 /* PnP */},
         false});

    // Stop
    mock->pushStatusChange({LONG(SCARD_E_CANCELLED), {}, false});

    auto result = runMonitor(std::move(mock));

    EXPECT_EQ(result.lastReaderList.size(), 2u);
    ASSERT_EQ(result.events.size(), 1u);
    EXPECT_EQ(result.events[0].type, MonitorEvent::Type::CardInserted);
    EXPECT_EQ(result.events[0].readerName, "Reader B");
}

// --- Test 14: Destructor stops monitor ---
TEST_F(MonitorTestFixture, DestructorStopsMonitor)
{
    auto mock = std::make_unique<MockPCSCScanProvider>(counters);
    mock->setReaders({"Reader A"});

    // PnP check
    mock->pushStatusChange({SCARD_S_SUCCESS, {SCARD_STATE_CHANGED}, false});

    // Blocking call — will wait until cancel() is called
    mock->pushStatusChange({SCARD_S_SUCCESS, {}, true});

    {
        Monitor monitor(std::move(mock));
        monitor.subscribe([](const MonitorEvent&) {});

        // Let it start and block
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    } // destructor should call cancel

    EXPECT_GE(counters->cancelCount.load(), 1);
}

// --- Test 15: Non-PnP card inserted ---
TEST_F(MonitorTestFixture, NoPnP_CardInserted)
{
    auto mock = std::make_unique<MockPCSCScanProvider>(counters);
    mock->setReaders({"Reader A"});

    // PnP check: UNKNOWN (no PnP)
    mock->pushStatusChange({SCARD_S_SUCCESS, {SCARD_STATE_UNKNOWN}, false});

    // Card present
    mock->pushStatusChange({SCARD_S_SUCCESS, {SCARD_STATE_PRESENT | SCARD_STATE_CHANGED}, false});

    // Stop
    mock->pushStatusChange({LONG(SCARD_E_CANCELLED), {}, false});

    auto result = runMonitor(std::move(mock));

    ASSERT_EQ(result.events.size(), 1u);
    EXPECT_EQ(result.events[0].type, MonitorEvent::Type::CardInserted);
    EXPECT_EQ(result.events[0].readerName, "Reader A");
}

// --- Test 16: Non-PnP card removed ---
TEST_F(MonitorTestFixture, NoPnP_CardRemoved)
{
    auto mock = std::make_unique<MockPCSCScanProvider>(counters);
    mock->setReaders({"Reader A"});

    // PnP check: UNKNOWN (no PnP)
    mock->pushStatusChange({SCARD_S_SUCCESS, {SCARD_STATE_UNKNOWN}, false});

    // Card empty
    mock->pushStatusChange({SCARD_S_SUCCESS, {SCARD_STATE_EMPTY | SCARD_STATE_CHANGED}, false});

    // Stop
    mock->pushStatusChange({LONG(SCARD_E_CANCELLED), {}, false});

    auto result = runMonitor(std::move(mock));

    ASSERT_EQ(result.events.size(), 1u);
    EXPECT_EQ(result.events[0].type, MonitorEvent::Type::CardRemoved);
}

// --- Test 17: Non-PnP card insert then remove ---
TEST_F(MonitorTestFixture, NoPnP_CardInsertThenRemove)
{
    auto mock = std::make_unique<MockPCSCScanProvider>(counters);
    mock->setReaders({"Reader A"});

    // PnP check: UNKNOWN (no PnP)
    mock->pushStatusChange({SCARD_S_SUCCESS, {SCARD_STATE_UNKNOWN}, false});

    // Card inserted
    mock->pushStatusChange({SCARD_S_SUCCESS, {SCARD_STATE_PRESENT | SCARD_STATE_CHANGED}, false});

    // Card removed
    mock->pushStatusChange({SCARD_S_SUCCESS, {SCARD_STATE_EMPTY | SCARD_STATE_CHANGED | (2 << 16)}, false});

    // Stop
    mock->pushStatusChange({LONG(SCARD_E_CANCELLED), {}, false});

    auto result = runMonitor(std::move(mock));

    ASSERT_EQ(result.events.size(), 2u);
    EXPECT_EQ(result.events[0].type, MonitorEvent::Type::CardInserted);
    EXPECT_EQ(result.events[1].type, MonitorEvent::Type::CardRemoved);
}

// --- Test 18: Non-PnP card swap ---
TEST_F(MonitorTestFixture, NoPnP_CardSwap)
{
    auto mock = std::make_unique<MockPCSCScanProvider>(counters);
    mock->setReaders({"Reader A"});

    // PnP check: UNKNOWN (no PnP)
    mock->pushStatusChange({SCARD_S_SUCCESS, {SCARD_STATE_UNKNOWN}, false});

    MockPCSCScanProvider::StatusChangeAction first;
    first.returnValue = SCARD_S_SUCCESS;
    first.eventStates = {SCARD_STATE_PRESENT | SCARD_STATE_CHANGED | (1 << 16)};
    first.atrData = {{0x3B, 0x8E, 0x80, 0x01}};
    mock->pushStatusChange(std::move(first));

    // A genuinely different card: counter moved AND the ATR changed.
    MockPCSCScanProvider::StatusChangeAction swapped;
    swapped.returnValue = SCARD_S_SUCCESS;
    swapped.eventStates = {SCARD_STATE_PRESENT | SCARD_STATE_CHANGED | (2 << 16)};
    swapped.atrData = {{0x3B, 0xDE, 0x97, 0x00}};
    mock->pushStatusChange(std::move(swapped));

    // Stop
    mock->pushStatusChange({LONG(SCARD_E_CANCELLED), {}, false});

    auto result = runMonitor(std::move(mock));

    ASSERT_EQ(result.events.size(), 3u);
    EXPECT_EQ(result.events[0].type, MonitorEvent::Type::CardInserted);
    EXPECT_EQ(result.events[1].type, MonitorEvent::Type::CardRemoved);
    EXPECT_EQ(result.events[2].type, MonitorEvent::Type::CardInserted);
}

// --- Test 19: Non-PnP INUSE toggle — no re-emission ---
TEST_F(MonitorTestFixture, NoPnP_InuseToggleNoReEmission)
{
    auto mock = std::make_unique<MockPCSCScanProvider>(counters);
    mock->setReaders({"Reader A"});

    // PnP check: UNKNOWN (no PnP)
    mock->pushStatusChange({SCARD_S_SUCCESS, {SCARD_STATE_UNKNOWN}, false});

    // Card inserted (event counter = 1)
    mock->pushStatusChange({SCARD_S_SUCCESS, {SCARD_STATE_PRESENT | SCARD_STATE_CHANGED | (1 << 16)}, false});

    // INUSE toggled, same event counter
    mock->pushStatusChange(
        {SCARD_S_SUCCESS, {SCARD_STATE_PRESENT | SCARD_STATE_INUSE | SCARD_STATE_CHANGED | (1 << 16)}, false});

    // Stop
    mock->pushStatusChange({LONG(SCARD_E_CANCELLED), {}, false});

    auto result = runMonitor(std::move(mock));

    ASSERT_EQ(result.events.size(), 1u);
    EXPECT_EQ(result.events[0].type, MonitorEvent::Type::CardInserted);
}

// --- Test 20: Non-PnP NO_SERVICE ---
TEST_F(MonitorTestFixture, NoPnP_NoServiceReEstablishesContext)
{
    auto mock = std::make_unique<MockPCSCScanProvider>(counters);
    mock->setReaders({"Reader A"});

    // PnP check: UNKNOWN (no PnP)
    mock->pushStatusChange({SCARD_S_SUCCESS, {SCARD_STATE_UNKNOWN}, false});

    // Card present
    mock->pushStatusChange({SCARD_S_SUCCESS, {SCARD_STATE_PRESENT | SCARD_STATE_CHANGED | (1 << 16)}, false});

    // NO_SERVICE
    mock->pushStatusChange({LONG(SCARD_E_NO_SERVICE), {}, false});

    // After re-establish: cancel
    mock->pushStatusChange({LONG(SCARD_E_CANCELLED), {}, false});

    auto result = runMonitor(std::move(mock));

    ASSERT_GE(result.events.size(), 2u);
    EXPECT_EQ(result.events[0].type, MonitorEvent::Type::CardInserted);
    EXPECT_EQ(result.events[1].type, MonitorEvent::Type::CardRemoved);
    EXPECT_GE(counters->establishContextCount.load(), 2);
}

// --- Test 21: Reader unplug does not re-read surviving card ---
TEST_F(MonitorTestFixture, ReaderUnplugDoesNotReReadSurvivingCard)
{
    auto mock = std::make_unique<MockPCSCScanProvider>(counters);
    mock->setReaders({"Reader A", "Reader B"});

    // PnP check: supported
    mock->pushStatusChange({SCARD_S_SUCCESS, {SCARD_STATE_CHANGED}, false});

    // Both cards inserted
    mock->pushStatusChange({SCARD_S_SUCCESS,
                            {SCARD_STATE_PRESENT | SCARD_STATE_CHANGED | (1 << 16),
                             SCARD_STATE_PRESENT | SCARD_STATE_CHANGED | (1 << 16), 0 /* PnP */},
                            false});

    // PnP change (reader B unplugged) — triggers re-enumeration
    MockPCSCScanProvider::StatusChangeAction readerChange;
    readerChange.returnValue = SCARD_S_SUCCESS;
    readerChange.eventStates = {0, 0, SCARD_STATE_CHANGED}; // PnP slot changed
    readerChange.newReaders = std::vector<std::string>{"Reader A"};
    mock->pushStatusChange(std::move(readerChange));

    // After re-enumeration with Reader A only: cancel
    mock->pushStatusChange({LONG(SCARD_E_CANCELLED), {}, false});

    auto result = runMonitor(std::move(mock));

    // CardInserted(A), CardInserted(B) — no duplicate for A after re-enum
    ASSERT_EQ(result.events.size(), 2u);
    EXPECT_EQ(result.events[0].type, MonitorEvent::Type::CardInserted);
    EXPECT_EQ(result.events[0].readerName, "Reader A");
    EXPECT_EQ(result.events[1].type, MonitorEvent::Type::CardInserted);
    EXPECT_EQ(result.events[1].readerName, "Reader B");
}

// --- Test 22: Reader unplug then card remove from survivor ---
TEST_F(MonitorTestFixture, ReaderUnplugThenCardRemoveFromSurvivor)
{
    auto mock = std::make_unique<MockPCSCScanProvider>(counters);
    mock->setReaders({"Reader A", "Reader B"});

    // PnP check: supported
    mock->pushStatusChange({SCARD_S_SUCCESS, {SCARD_STATE_CHANGED}, false});

    // Both cards inserted
    mock->pushStatusChange({SCARD_S_SUCCESS,
                            {SCARD_STATE_PRESENT | SCARD_STATE_CHANGED | (1 << 16),
                             SCARD_STATE_PRESENT | SCARD_STATE_CHANGED | (1 << 16), 0},
                            false});

    // Reader B unplugged — triggers re-enumeration
    MockPCSCScanProvider::StatusChangeAction readerChange;
    readerChange.returnValue = SCARD_S_SUCCESS;
    readerChange.eventStates = {0, 0, SCARD_STATE_CHANGED};
    readerChange.newReaders = std::vector<std::string>{"Reader A"};
    mock->pushStatusChange(std::move(readerChange));

    // After re-enumeration: card removed from Reader A
    mock->pushStatusChange({SCARD_S_SUCCESS, {SCARD_STATE_EMPTY | SCARD_STATE_CHANGED | (2 << 16), 0}, false});

    // Stop
    mock->pushStatusChange({LONG(SCARD_E_CANCELLED), {}, false});

    auto result = runMonitor(std::move(mock));

    // CardInserted(A), CardInserted(B), then CardRemoved(A)
    ASSERT_EQ(result.events.size(), 3u);
    EXPECT_EQ(result.events[0].type, MonitorEvent::Type::CardInserted);
    EXPECT_EQ(result.events[0].readerName, "Reader A");
    EXPECT_EQ(result.events[1].type, MonitorEvent::Type::CardInserted);
    EXPECT_EQ(result.events[1].readerName, "Reader B");
    EXPECT_EQ(result.events[2].type, MonitorEvent::Type::CardRemoved);
    EXPECT_EQ(result.events[2].readerName, "Reader A");
}

// --- Test 23: MUTE card becomes usable — deferred CardInserted fires ---
TEST_F(MonitorTestFixture, MuteToUsableEmitsCardInserted)
{
    auto mock = std::make_unique<MockPCSCScanProvider>(counters);
    mock->setReaders({"Reader A"});

    // PnP check
    mock->pushStatusChange({SCARD_S_SUCCESS, {SCARD_STATE_CHANGED}, false});

    // Card present but MUTE (suppressed)
    mock->pushStatusChange(
        {SCARD_S_SUCCESS, {SCARD_STATE_PRESENT | SCARD_STATE_MUTE | SCARD_STATE_CHANGED | (1 << 16), 0}, false});

    // MUTE clears — card becomes usable (same event counter)
    mock->pushStatusChange({SCARD_S_SUCCESS, {SCARD_STATE_PRESENT | SCARD_STATE_CHANGED | (1 << 16), 0}, false});

    // Stop
    mock->pushStatusChange({LONG(SCARD_E_CANCELLED), {}, false});

    auto result = runMonitor(std::move(mock));

    ASSERT_EQ(result.events.size(), 1u);
    EXPECT_EQ(result.events[0].type, MonitorEvent::Type::CardInserted);
    EXPECT_EQ(result.events[0].readerName, "Reader A");
}

// --- Test 24: EXCLUSIVE card becomes usable — deferred CardInserted fires ---
TEST_F(MonitorTestFixture, ExclusiveToUsableEmitsCardInserted)
{
    auto mock = std::make_unique<MockPCSCScanProvider>(counters);
    mock->setReaders({"Reader A"});

    // PnP check
    mock->pushStatusChange({SCARD_S_SUCCESS, {SCARD_STATE_CHANGED}, false});

    // Card present but EXCLUSIVE (suppressed)
    mock->pushStatusChange(
        {SCARD_S_SUCCESS, {SCARD_STATE_PRESENT | SCARD_STATE_EXCLUSIVE | SCARD_STATE_CHANGED | (1 << 16), 0}, false});

    // EXCLUSIVE clears — card becomes usable (same event counter)
    mock->pushStatusChange({SCARD_S_SUCCESS, {SCARD_STATE_PRESENT | SCARD_STATE_CHANGED | (1 << 16), 0}, false});

    // Stop
    mock->pushStatusChange({LONG(SCARD_E_CANCELLED), {}, false});

    auto result = runMonitor(std::move(mock));

    ASSERT_EQ(result.events.size(), 1u);
    EXPECT_EQ(result.events[0].type, MonitorEvent::Type::CardInserted);
    EXPECT_EQ(result.events[0].readerName, "Reader A");
}

// --- Test 25: Unsubscribe stops delivery (last subscriber stops monitor) ---
TEST_F(MonitorTestFixture, UnsubscribeStopsDelivery)
{
    auto mock = std::make_unique<MockPCSCScanProvider>(counters);
    mock->setReaders({"Reader A"});

    // PnP check
    mock->pushStatusChange({SCARD_S_SUCCESS, {SCARD_STATE_CHANGED}, false});

    // Blocking call
    mock->pushStatusChange({SCARD_S_SUCCESS, {}, true});

    Monitor monitor(std::move(mock));
    auto id = monitor.subscribe([](const MonitorEvent&) {});

    // Let it start and block
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    EXPECT_EQ(counters->cancelCount.load(), 0);

    // Unsubscribe — should stop the monitor: the blocked wait is cancelled
    // and the poll thread releases its context before unsubscribe returns.
    monitor.unsubscribe(id);

    EXPECT_GE(counters->cancelCount.load(), 1);
    EXPECT_EQ(counters->releaseContextCount.load(), counters->establishContextCount.load());
}

// A source whose SCARD_E_NO_ACCESS is final (a process without the
// smart-card entitlement on macOS): the monitor reports one Error and stops
// asking.
TEST_F(MonitorTestFixture, FinalNoAccessFromEstablishIsPermanent)
{
    auto mock = std::make_unique<MockPCSCScanProvider>(counters);
    mock->setEstablishContextReturn(static_cast<LONG>(SCARD_E_NO_ACCESS));
    mock->setRefusalDetail("the source's own words");
    mock->setRefusalRetryInterval(std::chrono::milliseconds::zero());

    std::mutex mtx;
    std::vector<MonitorEvent> events;
    std::chrono::steady_clock::duration destroyTook{};
    {
        auto monitor = std::make_unique<Monitor>(std::move(mock));
        monitor->subscribe(
            [&](const MonitorEvent& e) {
                std::lock_guard lock(mtx);
                events.push_back(e);
            },
            [](const std::vector<std::string>&) {});
        std::this_thread::sleep_for(std::chrono::milliseconds(1500));
        const auto start = std::chrono::steady_clock::now();
        monitor.reset();
        destroyTook = std::chrono::steady_clock::now() - start;
    }

    EXPECT_EQ(counters->establishContextCount.load(), 1);
    ASSERT_EQ(events.size(), 1U);
    EXPECT_EQ(events[0].type, MonitorEvent::Type::Error);
    EXPECT_EQ(events[0].detail, "the source's own words");
    EXPECT_LT(destroyTook, std::chrono::milliseconds(100));
}

// A PC/SC refusal can lift (a polkit decision tied to a session that becomes
// active): it is reported once, asked again, and the monitor carries on once
// the context is granted.
TEST_F(MonitorTestFixture, PcscNoAccessIsReportedOnceAndRetried)
{
    auto mock = std::make_unique<MockPCSCScanProvider>(counters);
    auto* source = mock.get();
    mock->setEstablishContextReturn(static_cast<LONG>(SCARD_E_NO_ACCESS));
    mock->setRefusalRetryInterval(std::chrono::milliseconds(50));

    std::mutex mtx;
    std::vector<MonitorEvent> events;
    {
        auto monitor = std::make_unique<Monitor>(std::move(mock));
        monitor->subscribe(
            [&](const MonitorEvent& e) {
                std::lock_guard lock(mtx);
                events.push_back(e);
            },
            [](const std::vector<std::string>&) {});
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
        source->setEstablishContextReturn(SCARD_S_SUCCESS);
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
        monitor.reset();
    }

    EXPECT_GE(counters->establishContextCount.load(), 3) << "asked again after the refusal";
    std::lock_guard lock(mtx);
    std::size_t errors = 0;
    for (const auto& e : events)
        errors += e.type == MonitorEvent::Type::Error ? 1 : 0;
    EXPECT_EQ(errors, 1U) << "the refusal is reported once, not on every retry";
}

// Any other refusal (pcscd not running yet) is retried, silently.
TEST_F(MonitorTestFixture, NoServiceFromEstablishIsRetried)
{
    auto mock = std::make_unique<MockPCSCScanProvider>(counters);
    mock->setEstablishContextReturn(static_cast<LONG>(SCARD_E_NO_SERVICE));

    auto result = runMonitor(std::move(mock), 2500);

    EXPECT_GE(counters->establishContextCount.load(), 2);
    for (const auto& e : result.events)
        EXPECT_NE(e.type, MonitorEvent::Type::Error);
}

// A subscriber that throws does not take the scan thread down, and what it
// threw reaches the log sink the host installed, not this process's stderr.
TEST_F(MonitorTestFixture, ThrowingSubscribersReportThroughTheLogSink)
{
    // Captures first, the sink reset next, the monitor last: destruction joins
    // the scan thread before the sink, and the sink before what it captures.
    std::mutex mtx;
    std::vector<std::pair<LibreSCRS::log::Level, std::string>> lines;
    struct SinkReset
    {
        ~SinkReset()
        {
            LibreSCRS::log::resetForTest();
        }
    } sinkReset;
    LibreSCRS::log::init(
        [&](LibreSCRS::log::Level level, std::string_view line) {
            std::lock_guard lock(mtx);
            lines.emplace_back(level, std::string(line));
        },
        "test.monitor");

    auto mock = std::make_unique<MockPCSCScanProvider>(counters);
    mock->setReaders({"Reader A"});
    mock->pushStatusChange({SCARD_S_SUCCESS, {SCARD_STATE_CHANGED}, false});
    mock->pushStatusChange(
        {SCARD_S_SUCCESS, {SCARD_STATE_PRESENT | SCARD_STATE_CHANGED, 0 /* PnP unchanged */}, false});
    mock->pushStatusChange({LONG(SCARD_E_CANCELLED), {}, false});
    {
        Monitor monitor(std::move(mock));
        monitor.subscribe([](const MonitorEvent&) { throw std::runtime_error("event subscriber blew up"); },
                          [](const std::vector<std::string>&) { throw 42; });
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }

    std::lock_guard lock(mtx);
    const auto has = [&](std::string_view text) {
        return std::any_of(lines.begin(), lines.end(), [&](const auto& entry) {
            return entry.first == LibreSCRS::log::Level::Error && entry.second.find(text) != std::string::npos;
        });
    };
    EXPECT_TRUE(has("event callback threw: event subscriber blew up")) << lines.size() << " line(s) captured";
    EXPECT_TRUE(has("reader-list callback threw unknown exception")) << lines.size() << " line(s) captured";
}

// pcsc-lite ignores an SCardCancel that reaches a context not yet inside
// SCardGetStatusChange. A stop that lands between the poll loop's stop check
// and the wait must still end the poll instead of waiting out the timeout.
TEST_F(MonitorTestFixture, StopJustBeforeTheWaitSurvivesADroppedCancel)
{
    using namespace std::chrono_literals;
    auto mock = std::make_unique<MockPCSCScanProvider>(counters);
    auto* mockPtr = mock.get();
    mock->setReaders({"Reader A"});
    mock->setDropCancelOutsideWait(true);
    mock->pushStatusChange({SCARD_S_SUCCESS, {SCARD_STATE_CHANGED}, false}); // PnP check
    mock->pushStatusChange({SCARD_S_SUCCESS, {}, false});                    // initial probe
    mock->pushStatusChange({SCARD_S_SUCCESS, {}, true});                     // the long wait

    std::atomic<bool> inWindow{false};
    auto counts = counters;
    mock->setBeforeBlockingWaitHook([&inWindow, counts] {
        inWindow = true;
        // Hold the poll thread past the stop check until stop has cancelled.
        const auto until = std::chrono::steady_clock::now() + 2s;
        while (counts->cancelCount.load() == 0 && std::chrono::steady_clock::now() < until)
            std::this_thread::sleep_for(1ms);
    });

    Monitor monitor(std::move(mock));
    const auto id = monitor.subscribe([](const MonitorEvent&) {});

    const auto windowDeadline = std::chrono::steady_clock::now() + 2s;
    while (!inWindow.load() && std::chrono::steady_clock::now() < windowDeadline)
        std::this_thread::sleep_for(1ms);
    EXPECT_TRUE(inWindow.load()) << "poll thread never reached the wait";

    std::atomic<bool> stopped{false};
    std::thread stopper([&] {
        monitor.unsubscribe(id);
        stopped = true;
    });
    const auto stopDeadline = std::chrono::steady_clock::now() + 3s;
    while (!stopped.load() && std::chrono::steady_clock::now() < stopDeadline)
        std::this_thread::sleep_for(1ms);
    const bool stoppedInTime = stopped.load();
    if (!stoppedInTime)
        mockPtr->forceReleaseBlockingWait(); // let the join finish so the test fails, not hangs
    stopper.join();

    EXPECT_TRUE(stoppedInTime) << "stop lost its only cancel and the poll stayed in the wait";
    EXPECT_GE(counters->droppedCancelCount.load(), 1) << "the stop did not land in the window";
}

namespace {

template <typename Pred>
bool waitFor(Pred pred, std::chrono::milliseconds limit)
{
    const auto deadline = std::chrono::steady_clock::now() + limit;
    while (!pred()) {
        if (std::chrono::steady_clock::now() >= deadline)
            return false;
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    return true;
}

// What a subscriber's callback shares with the test. Held by shared_ptr so a
// callback stuck on a failing build outlives the test body.
struct SelfStop
{
    std::atomic<Monitor*> monitor{nullptr};
    std::atomic<Monitor::SubscriptionId> id{0};
    std::atomic<bool> idReady{false};
    std::atomic<bool> entered{false};
    std::atomic<bool> returned{false};
    std::atomic<int> secondEvents{0};
    std::atomic<int> secondReaderLists{0};
};

} // namespace

// The last subscriber drops its subscription from its own callback, on the
// poll thread. That stop cannot wait for the poll thread to return; the
// thread ends on its own without parking in the first-reader wait, and the
// next subscriber gets a running monitor again.
TEST_F(MonitorTestFixture, LastSubscriberUnsubscribesInsideItsCallback)
{
    using namespace std::chrono_literals;
    auto mock = std::make_unique<MockPCSCScanProvider>(counters);
    auto* mockPtr = mock.get();
    mock->setReaders({});
    mock->pushStatusChange({SCARD_S_SUCCESS, {SCARD_STATE_CHANGED}, false}); // PnP check

    auto shared = std::make_shared<SelfStop>();
    auto monitor = std::make_unique<Monitor>(std::move(mock));
    shared->monitor = monitor.get();
    shared->id = monitor->subscribe([](const MonitorEvent&) {},
                                    [shared](const std::vector<std::string>&) {
                                        if (shared->entered.exchange(true))
                                            return;
                                        while (!shared->idReady.load())
                                            std::this_thread::yield();
                                        shared->monitor.load()->unsubscribe(shared->id.load());
                                        shared->returned = true;
                                    });
    shared->idReady = true;

    if (!waitFor([&] { return shared->returned.load(); }, 3s)) {
        ADD_FAILURE() << "unsubscribe() from the poll thread waited for the poll thread";
        (void)monitor.release(); // its poll thread never returns; destroying it would hang the suite
        return;
    }
    EXPECT_TRUE(waitFor([&] { return counters->releaseContextCount.load() >= 1; }, 2s))
        << "the stopped poll thread did not end on its own";
    EXPECT_EQ(counters->getStatusChangeCount.load(), 1) << "the stopped poll thread entered the first-reader wait";

    mockPtr->pushStatusChange({SCARD_S_SUCCESS, {SCARD_STATE_CHANGED}, false}); // PnP check
    mockPtr->pushStatusChange({SCARD_S_SUCCESS, {}, true});                     // first-reader wait
    monitor->subscribe([](const MonitorEvent&) {},
                       [shared](const std::vector<std::string>&) { ++shared->secondReaderLists; });
    EXPECT_TRUE(waitFor([&] { return shared->secondReaderLists.load() >= 1; }, 2s))
        << "the next subscriber got no poll thread";
    monitor.reset();
    EXPECT_EQ(counters->releaseContextCount.load(), counters->establishContextCount.load());
}

// A subscriber that drops its subscription and subscribes again inside its
// callback keeps the poll thread it runs on: the new subscription gets the
// events that follow.
TEST_F(MonitorTestFixture, ResubscribeInsideTheCallbackKeepsThePollThread)
{
    using namespace std::chrono_literals;
    auto mock = std::make_unique<MockPCSCScanProvider>(counters);
    mock->setReaders({"Reader A"});
    mock->pushStatusChange({SCARD_S_SUCCESS, {SCARD_STATE_CHANGED}, false}); // PnP check
    mock->pushStatusChange(
        {SCARD_S_SUCCESS, {SCARD_STATE_PRESENT | SCARD_STATE_CHANGED, 0 /* PnP unchanged */}, false}); // probe
    mock->pushStatusChange({SCARD_S_SUCCESS, {}, true});                                               // the long wait

    auto shared = std::make_shared<SelfStop>();
    auto monitor = std::make_unique<Monitor>(std::move(mock));
    shared->monitor = monitor.get();
    shared->id = monitor->subscribe([](const MonitorEvent&) {},
                                    [shared](const std::vector<std::string>&) {
                                        if (shared->entered.exchange(true))
                                            return;
                                        while (!shared->idReady.load())
                                            std::this_thread::yield();
                                        Monitor* m = shared->monitor.load();
                                        m->unsubscribe(shared->id.load());
                                        m->subscribe([shared](const MonitorEvent& e) {
                                            if (e.type == MonitorEvent::Type::CardInserted)
                                                ++shared->secondEvents;
                                        });
                                        shared->returned = true;
                                    });
    shared->idReady = true;

    if (!waitFor([&] { return shared->returned.load(); }, 3s)) {
        ADD_FAILURE() << "unsubscribe() or subscribe() from the poll thread waited for the poll thread";
        (void)monitor.release(); // its poll thread never returns; destroying it would hang the suite
        return;
    }
    EXPECT_TRUE(waitFor([&] { return shared->secondEvents.load() == 1; }, 2s))
        << "the subscription made inside the callback got no event";
    EXPECT_EQ(counters->establishContextCount.load(), 1) << "the poll thread was replaced";
    monitor.reset();
    EXPECT_EQ(counters->releaseContextCount.load(), counters->establishContextCount.load());
}

// A release that lands before listReaders reaches its wait is kept.
TEST(MockPCSCScanProviderTest, ListReadersReleaseBeforeTheWaitIsKept)
{
    using namespace std::chrono_literals;
    auto counters = std::make_shared<MockCounters>();
    MockPCSCScanProvider mock(counters);
    mock.setReaders({"Reader A"});
    mock.setListReadersBlocking(true);
    mock.releaseListReadersBlock();

    std::atomic<bool> returned{false};
    std::thread caller([&] {
        DWORD size = 0;
        mock.listReaders(0, nullptr, nullptr, &size);
        returned = true;
    });
    const auto deadline = std::chrono::steady_clock::now() + 2s;
    while (!returned.load() && std::chrono::steady_clock::now() < deadline)
        std::this_thread::sleep_for(1ms);
    const bool returnedInTime = returned.load();
    if (!returnedInTime)
        mock.releaseListReadersBlock();
    caller.join();

    EXPECT_TRUE(returnedInTime) << "the early release was lost and listReaders blocked";
}
