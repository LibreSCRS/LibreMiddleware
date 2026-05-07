// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0 and LibreSCRS contributors

#include "mock_pcsc_scan_provider.h"
#include <LibreSCRS/Plugin/AutoReaderService.h>
#include <LibreSCRS/Plugin/CardPluginService.h>
#include <LibreSCRS/SmartCard/MonitorService.h>
#include <LibreSCRS/SmartCard/detail/MonitorInjection.h>
#include <gtest/gtest.h>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <filesystem>
#include <mutex>
#include <thread>

using namespace LibreSCRS::Plugin;

// --- Test 1: SubscribesAndUnsubscribes ---
// Create MonitorService with mock (blocking action), create AutoReaderService, verify monitor is running,
// destroy both. Expect cancel called.
TEST(AutoReaderTest, SubscribesAndUnsubscribes)
{
    auto counters = std::make_shared<smartcard::MockCounters>();
    auto mock = std::make_unique<smartcard::MockPCSCScanProvider>(counters);
    mock->setReaders({"Reader A"});

    // PnP check
    mock->pushStatusChange({SCARD_S_SUCCESS, {SCARD_STATE_CHANGED}, false});

    // Blocking call — will wait until cancel() is called
    mock->pushStatusChange({SCARD_S_SUCCESS, {}, true});

    // Empty registry for these tests — pass a nonexistent path so the
    // span-of-paths ctor reports zero outcomes and the registry stays empty.
    auto registry =
        std::make_shared<LibreSCRS::Plugin::CardPluginService>(std::filesystem::path{"/nonexistent/librescrs-tests"});

    {
        auto monitor = LibreSCRS::SmartCard::detail::makeMonitorWithProvider(std::move(mock));
        ASSERT_NE(monitor, nullptr);
        AutoReaderService autoReader(
            monitor, registry, [](const std::string&, const LibreSCRS::Plugin::CardData&) {},
            [](const std::string&, const LibreSCRS::Plugin::AutoReaderService::AutoReaderError&) {});

        // Let the monitor start and block
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        EXPECT_TRUE(monitor->isRunning());
    } // AutoReaderService destructor unsubscribes, MonitorService destructor calls cancel

    EXPECT_GE(counters->cancelCount.load(), 1);
}

// --- Test 2: CardInsertCallsErrorOnPCSCFailure ---
// MonitorService emits CardInserted for "NonExistentReader". AutoReaderService tries real PCSCConnection
// which fails. Error callback should fire.
TEST(AutoReaderTest, CardInsertCallsErrorOnPCSCFailure)
{
    auto counters = std::make_shared<smartcard::MockCounters>();
    auto mock = std::make_unique<smartcard::MockPCSCScanProvider>(counters);
    mock->setReaders({"NonExistentReader"});

    // PnP check
    mock->pushStatusChange({SCARD_S_SUCCESS, {SCARD_STATE_CHANGED}, false});

    // Card inserted on NonExistentReader
    mock->pushStatusChange(
        {SCARD_S_SUCCESS, {SCARD_STATE_PRESENT | SCARD_STATE_CHANGED | (1 << 16), 0 /* PnP */}, false});

    // Stop
    mock->pushStatusChange({LONG(SCARD_E_CANCELLED), {}, false});

    // Empty registry for these tests — pass a nonexistent path so the
    // span-of-paths ctor reports zero outcomes and the registry stays empty.
    auto registry =
        std::make_shared<LibreSCRS::Plugin::CardPluginService>(std::filesystem::path{"/nonexistent/librescrs-tests"});

    std::mutex mtx;
    std::condition_variable cv;
    bool errorReceived = false;
    std::string errorMsg;

    {
        auto monitor = LibreSCRS::SmartCard::detail::makeMonitorWithProvider(std::move(mock));
        ASSERT_NE(monitor, nullptr);
        AutoReaderService autoReader(
            monitor, registry,
            [](const std::string&, const LibreSCRS::Plugin::CardData&) { FAIL() << "Unexpected data callback"; },
            [&](const std::string&, const LibreSCRS::Plugin::AutoReaderService::AutoReaderError& error) {
                std::lock_guard lock(mtx);
                errorReceived = true;
                errorMsg = error.diagnosticDetail.value_or(std::string{});
                cv.notify_all();
            });

        // Wait for error callback (PCSCConnection will fail on fake reader)
        std::unique_lock lock(mtx);
        if (!cv.wait_for(lock, std::chrono::seconds(5), [&] { return errorReceived; })) {
            GTEST_SKIP() << "Error callback not received within 5s (pcscd may not be running)";
        }
    }

    EXPECT_TRUE(errorReceived);
    // Either "No compatible plugin found" (if connection succeeded but no plugins)
    // or "All plugins failed to read card" (if connection failed after retries)
    EXPECT_FALSE(errorMsg.empty());
}

// --- Test 3: IgnoresCardRemoved ---
// MonitorService emits only CardRemoved. Neither data nor error callback should fire.
TEST(AutoReaderTest, IgnoresCardRemoved)
{
    auto counters = std::make_shared<smartcard::MockCounters>();
    auto mock = std::make_unique<smartcard::MockPCSCScanProvider>(counters);
    mock->setReaders({"Reader A"});

    // PnP check
    mock->pushStatusChange({SCARD_S_SUCCESS, {SCARD_STATE_CHANGED}, false});

    // Card removed (empty)
    mock->pushStatusChange({SCARD_S_SUCCESS, {SCARD_STATE_EMPTY | SCARD_STATE_CHANGED, 0}, false});

    // Stop
    mock->pushStatusChange({LONG(SCARD_E_CANCELLED), {}, false});

    // Empty registry for these tests — pass a nonexistent path so the
    // span-of-paths ctor reports zero outcomes and the registry stays empty.
    auto registry =
        std::make_shared<LibreSCRS::Plugin::CardPluginService>(std::filesystem::path{"/nonexistent/librescrs-tests"});

    std::atomic<bool> dataCalled{false};
    std::atomic<bool> errorCalled{false};

    {
        auto monitor = LibreSCRS::SmartCard::detail::makeMonitorWithProvider(std::move(mock));
        ASSERT_NE(monitor, nullptr);
        AutoReaderService autoReader(
            monitor, registry, [&](const std::string&, const LibreSCRS::Plugin::CardData&) { dataCalled.store(true); },
            [&](const std::string&, const LibreSCRS::Plugin::AutoReaderService::AutoReaderError&) {
                errorCalled.store(true);
            });

        // Give monitor time to process events
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }

    EXPECT_FALSE(dataCalled.load());
    EXPECT_FALSE(errorCalled.load());
}
