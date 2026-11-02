// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

// CardSession::open reports why it failed by the PC/SC code the connection
// raised, not by matching words in a message.
//
// No reader: this executable defines the PC/SC entry points the connection
// calls. ENABLE_EXPORTS puts them in its dynamic symbol table, where the
// SmartCard library's references resolve to them (ELF flat lookup) -- Linux
// only, as macOS reaches cards through CryptoTokenKit.

#include <LibreSCRS/SmartCard/CardSession.h>

#include <gtest/gtest.h>

#include <PCSC/winscard.h>

namespace {
LONG g_connectResult = SCARD_E_NO_SMARTCARD;
} // namespace

extern "C" {

LONG SCardEstablishContext(DWORD, LPCVOID, LPCVOID, LPSCARDCONTEXT phContext)
{
    *phContext = 1;
    return SCARD_S_SUCCESS;
}

LONG SCardReleaseContext(SCARDCONTEXT)
{
    return SCARD_S_SUCCESS;
}

LONG SCardConnect(SCARDCONTEXT, LPCSTR, DWORD, DWORD, LPSCARDHANDLE, LPDWORD)
{
    return g_connectResult;
}

} // extern "C"

TEST(CardSessionOpen, AnEmptyReaderIsNoCardPresent)
{
    g_connectResult = SCARD_E_NO_SMARTCARD;
    auto opened = LibreSCRS::SmartCard::CardSession::open("Empty Reader");
    ASSERT_FALSE(opened.has_value());
    EXPECT_EQ(opened.error().kind, LibreSCRS::SmartCard::OpenError::Kind::NoCardPresent)
        << opened.error().diagnosticDetail.value_or("");
}

TEST(CardSessionOpen, AProtocolMismatchIsAProtocolError)
{
    g_connectResult = SCARD_E_PROTO_MISMATCH;
    auto opened = LibreSCRS::SmartCard::CardSession::open("Mismatched Reader");
    ASSERT_FALSE(opened.has_value());
    EXPECT_EQ(opened.error().kind, LibreSCRS::SmartCard::OpenError::Kind::ProtocolError);
}

TEST(CardSessionOpen, AnUnknownReaderIsReaderUnavailable)
{
    g_connectResult = SCARD_E_UNKNOWN_READER;
    auto opened = LibreSCRS::SmartCard::CardSession::open("Gone Reader");
    ASSERT_FALSE(opened.has_value());
    EXPECT_EQ(opened.error().kind, LibreSCRS::SmartCard::OpenError::Kind::ReaderUnavailable);
}

// A card another client holds is there and answering; the open may succeed
// once that client lets go, which neither "no card" nor "no reader" says.
TEST(CardSessionOpen, ACardHeldByAnotherClientIsSessionRefused)
{
    g_connectResult = SCARD_E_SHARING_VIOLATION;
    auto opened = LibreSCRS::SmartCard::CardSession::open("Busy Reader");
    ASSERT_FALSE(opened.has_value());
    EXPECT_EQ(opened.error().kind, LibreSCRS::SmartCard::OpenError::Kind::SessionRefused);
}
