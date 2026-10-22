// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

// The shipped library in a process that lacks the smart-card entitlement:
// opening a card fails, says which entitlement is missing, and the process
// carries on. This binary is deliberately not signed with it.

#include <gtest/gtest.h>

#include "pcsc_connection.h"

#include <LibreSCRS/SmartCard/CardSession.h>

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
