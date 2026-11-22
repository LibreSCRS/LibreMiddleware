// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

// One PC/SC code, one kind -- the same answer to a failed open and to a failure
// in the middle of an exchange.

#include <LibreSCRS/SmartCard/TransportError.h>

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <utility>

#include "open_error.h"
#include <pcsc_classify.h>

namespace {

using LibreSCRS::SmartCard::OpenError;
using LibreSCRS::SmartCard::TransportError;
using LibreSCRS::SmartCard::Internal::classifyPcscCode;
using LibreSCRS::SmartCard::Internal::pcscFailure;
using LibreSCRS::SmartCard::Internal::toOpenError;
using Kind = TransportError::Kind;

const std::array<std::pair<LONG, Kind>, 17> kTable{{
    {SCARD_W_REMOVED_CARD, Kind::NoCardPresent},
    {SCARD_E_NO_SMARTCARD, Kind::NoCardPresent},
    {SCARD_W_RESET_CARD, Kind::CardReset},
    {SCARD_E_SHARING_VIOLATION, Kind::SessionRefused},
    {SCARD_E_PROTO_MISMATCH, Kind::ProtocolError},
    {SCARD_W_UNRESPONSIVE_CARD, Kind::ProtocolError},
    {SCARD_W_UNPOWERED_CARD, Kind::ProtocolError},
    {SCARD_F_COMM_ERROR, Kind::ProtocolError},
    {SCARD_E_NO_SERVICE, Kind::ReaderUnavailable},
    {SCARD_E_SERVICE_STOPPED, Kind::ReaderUnavailable},
    {SCARD_E_READER_UNAVAILABLE, Kind::ReaderUnavailable},
    {SCARD_E_UNKNOWN_READER, Kind::ReaderUnavailable},
    {SCARD_E_NO_READERS_AVAILABLE, Kind::ReaderUnavailable},
    {SCARD_E_INVALID_HANDLE, Kind::ReaderUnavailable},
    {SCARD_E_NO_ACCESS, Kind::ReaderUnavailable},
    {SCARD_E_UNSUPPORTED_FEATURE, Kind::ReaderUnavailable},
    {0x12345678, Kind::ReaderUnavailable},
}};

// The table the open path used before the classifier was shared; a reset was
// not a category of its own and fell into the default.
OpenError::Kind oldTable(LONG code)
{
    switch (static_cast<std::uint32_t>(code)) {
    case static_cast<std::uint32_t>(SCARD_E_NO_SMARTCARD):
    case static_cast<std::uint32_t>(SCARD_W_REMOVED_CARD):
        return OpenError::Kind::NoCardPresent;
    case static_cast<std::uint32_t>(SCARD_E_PROTO_MISMATCH):
    case static_cast<std::uint32_t>(SCARD_W_UNRESPONSIVE_CARD):
    case static_cast<std::uint32_t>(SCARD_W_UNPOWERED_CARD):
    case static_cast<std::uint32_t>(SCARD_F_COMM_ERROR):
        return OpenError::Kind::ProtocolError;
    case static_cast<std::uint32_t>(SCARD_E_SHARING_VIOLATION):
        return OpenError::Kind::SessionRefused;
    default:
        return OpenError::Kind::ReaderUnavailable;
    }
}

} // namespace

TEST(PcscClassify, EveryCodeMapsAsTheTableSays)
{
    for (const auto& [code, kind] : kTable) {
        EXPECT_EQ(classifyPcscCode(code), kind) << "code 0x" << std::hex << static_cast<std::uint32_t>(code);
        const TransportError failure = pcscFailure(code, "x");
        EXPECT_EQ(failure.kind, kind);
        EXPECT_EQ(failure.detail, "x");
    }
}

TEST(PcscClassify, OpenKeepsTheOldTable)
{
    for (const auto& [code, kind] : kTable) {
        const OpenError opened = toOpenError(pcscFailure(code, "SCardConnect failed on reader: R"));
        EXPECT_EQ(opened.kind, oldTable(code)) << "code 0x" << std::hex << static_cast<std::uint32_t>(code);
        EXPECT_EQ(opened.diagnosticDetail.value_or("<none>"),
                  "CardSession open failed: SCardConnect failed on reader: R");
    }
}
