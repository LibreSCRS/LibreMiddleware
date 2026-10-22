// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

// The shipped library in a process that lacks the smart-card entitlement:
// opening a card fails, says which entitlement is missing, and the process
// carries on. This binary is deliberately not signed with it.

#include <gtest/gtest.h>

#include "pcsc_connection.h"

#include <LibreSCRS/SmartCard/CardSession.h>
#include <LibreSCRS/SmartCard/MonitorService.h>

#include <chrono>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

#include <string>

TEST(CardSessionMac, UnsignedOpenNamesTheEntitlement)
{
    auto session = LibreSCRS::SmartCard::CardSession::open("LibreSCRS test: any reader");
    ASSERT_FALSE(session.has_value());
    EXPECT_EQ(session.error().kind, LibreSCRS::SmartCard::OpenError::Kind::ReaderUnavailable);
    const std::string detail = session.error().diagnosticDetail.value_or("");
    EXPECT_NE(detail.find(LibreSCRS::SmartCard::Internal::Ctk::kNoManagerDetail), std::string::npos) << detail;
    EXPECT_TRUE(LibreSCRS::SmartCard::Internal::PCSCConnection::listReaders().empty());
}

// The monitor in the same unsigned process: one Error that names the
// entitlement, no retries, and it shuts down at once.
TEST(MonitorServiceMacTest, UnsignedBinaryReportsOneErrorAndStopsCleanly)
{
    using LibreSCRS::SmartCard::MonitorEvent;
    std::mutex mtx;
    std::vector<MonitorEvent> events;
    auto monitor = std::make_unique<LibreSCRS::SmartCard::MonitorService>();
    auto id = monitor->subscribe([&](const MonitorEvent& e) {
        std::lock_guard lock(mtx);
        events.push_back(e);
    });
    std::this_thread::sleep_for(std::chrono::milliseconds(1500));
    const auto start = std::chrono::steady_clock::now();
    monitor->unsubscribe(id);
    monitor.reset();
    EXPECT_LT(std::chrono::steady_clock::now() - start, std::chrono::milliseconds(500));

    std::lock_guard lock(mtx);
    ASSERT_EQ(events.size(), 1U);
    EXPECT_EQ(events[0].kind, MonitorEvent::Kind::Error);
    // The same sentence as the open error: one definition says it.
    EXPECT_EQ(events[0].diagnosticDetail.value_or(""), LibreSCRS::SmartCard::Internal::Ctk::kNoManagerDetail);
}
