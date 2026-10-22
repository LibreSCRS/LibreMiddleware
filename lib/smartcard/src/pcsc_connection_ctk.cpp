// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

// The members of PCSCConnection that reach a card, over one exclusive
// CryptoTokenKit session held for the life of the connection. The shared
// transmit loop, the wire flow around exchangeWire, tracing, the detached
// seams and the diagnostic opener stay in pcsc_connection.cpp. Errors carry the PC/SC codes the rest of the library
// already classifies.

#include "pcsc_connection.h"
#include "pcsc_trace.h"

#include <chrono>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace LibreSCRS::SmartCard::Internal {

using namespace detail;

namespace {

// How long open and reconnect wait for another client to release the card;
// after it they fail with SCARD_E_SHARING_VIOLATION.
constexpr std::chrono::seconds kSessionGrantDeadline{10};

[[noreturn]] void throwFailure(const Ctk::CtkFailure& failure, const std::string& readerName)
{
    using Ctk::CtkStatus;
    switch (failure.status) {
    case CtkStatus::NoManager:
        throw PCSCError(Ctk::kNoManagerDetail, SCARD_E_NO_ACCESS);
    case CtkStatus::UnknownSlot:
        throw PCSCError("unknown reader: " + readerName, SCARD_E_UNKNOWN_READER);
    case CtkStatus::NoCard:
        throw PCSCError("no smartcard in reader: " + readerName, SCARD_E_NO_SMARTCARD);
    case CtkStatus::Mute:
        throw PCSCError("card does not answer (mute)", SCARD_W_UNRESPONSIVE_CARD);
    case CtkStatus::SessionRefused:
        throw PCSCError("exclusive session refused or still held by another client", SCARD_E_SHARING_VIOLATION);
    case CtkStatus::SessionLost:
        throw PCSCError("session lost (another client or the system took the card)", SCARD_W_RESET_CARD);
    case CtkStatus::CardGone:
        throw PCSCError("card removed", SCARD_W_REMOVED_CARD);
    case CtkStatus::Ok:
    case CtkStatus::CommError:
        break;
    }
    throw PCSCError("transmit failed: " + failure.detail, SCARD_F_COMM_ERROR);
}

DWORD protocolOf(const Ctk::CtkCard& card)
{
    return card.protocol() == Ctk::CtkProtocol::T0 ? SCARD_PROTOCOL_T0 : SCARD_PROTOCOL_T1;
}

} // namespace

PCSCConnection::PCSCConnection(const std::string& readerName) : storedReaderName(readerName)
{
    auto opened = Ctk::CtkCard::open(readerName, kSessionGrantDeadline);
    if (!opened) {
        throwFailure(opened.error(), readerName);
    }
    ctk = std::move(*opened);
    activeProtocol = protocolOf(*ctk);

    if (pcscTraceEnabled()) {
        emitPcscTraceEvent("connect", readerName, this);
    }
}

PCSCConnection::~PCSCConnection() = default;

void PCSCConnection::reconnect()
{
    if (!ctk) {
        throw PCSCError("SCardReconnect failed", SCARD_E_INVALID_HANDLE);
    }
    if (ctk->alive()) {
        return;
    }
    if (pcscTraceEnabled()) {
        emitPcscTraceEvent("reconnect", readerName(), this);
    }
    if (ctk->lossKind() == Ctk::CtkStatus::CardGone) {
        throw PCSCError("card removed", SCARD_W_REMOVED_CARD);
    }
    if (auto reopened = ctk->reopen(kSessionGrantDeadline); !reopened) {
        throwFailure(reopened.error(), readerName());
    }
    activeProtocol = protocolOf(*ctk);
}

void PCSCConnection::reconnectWithReset()
{
    if (!ctk) {
        throw PCSCError("SCardReconnect (reset) failed", SCARD_E_INVALID_HANDLE);
    }
    throw PCSCError("a card reset is not supported through CryptoTokenKit", SCARD_E_UNSUPPORTED_FEATURE);
}

bool PCSCConnection::detached() const noexcept
{
    return !ctk;
}

std::optional<std::vector<std::uint8_t>> PCSCConnection::exchangeWire(std::span<const std::uint8_t> command)
{
    if (!ctk) {
        throw PCSCError("SCardTransmit failed", SCARD_E_INVALID_HANDLE);
    }
    auto reply = ctk->exchange(command);
    if (reply) {
        return std::move(*reply);
    }
    if (reply.error().status == Ctk::CtkStatus::SessionLost) {
        // The card stayed; another client or the system took the session.
        return std::nullopt;
    }
    throwFailure(reply.error(), readerName());
}

void PCSCConnection::beginOnCard()
{
    // The held session is already exclusive; a transaction only has to find it
    // alive, and asks the card nothing.
    if (!ctk->alive()) {
        reconnect();
    }
}

void PCSCConnection::endOnCard() noexcept {}

std::vector<uint8_t> PCSCConnection::atrFromCard() const
{
    if (!ctk) {
        throw PCSCError("SCardStatus failed", SCARD_E_INVALID_HANDLE);
    }
    auto atr = ctk->atr();
    if (atr.empty()) {
        throw PCSCError("SCardStatus failed", SCARD_E_NO_SMARTCARD);
    }
    return atr;
}

std::vector<std::string> PCSCConnection::listReaders()
{
    return Ctk::slotNames();
}

} // namespace LibreSCRS::SmartCard::Internal
