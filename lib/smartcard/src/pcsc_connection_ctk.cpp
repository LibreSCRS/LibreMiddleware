// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

// The members of PCSCConnection that reach a card, over one exclusive
// CryptoTokenKit session held for the life of the connection. The shared
// transmit loop, the wire flow around exchangeWire, tracing, the detached
// seams and the diagnostic opener stay in pcsc_connection.cpp. Errors carry the PC/SC codes the rest of the library
// already classifies.

#include "pcsc_connection.h"
#include "pcsc_classify.h"
#include "pcsc_trace.h"

#include <chrono>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace LibreSCRS::SmartCard::Internal {

using namespace detail;

namespace {

// How long open and reconnect wait for another client to release the card;
// after it they fail with SCARD_E_SHARING_VIOLATION.
constexpr std::chrono::seconds kSessionGrantDeadline{10};

TransportError failureOf(const Ctk::CtkFailure& failure, const std::string& readerName)
{
    using Ctk::CtkStatus;
    switch (failure.status) {
    case CtkStatus::NoManager:
        return pcscFailure(SCARD_E_NO_ACCESS, Ctk::kNoManagerDetail);
    case CtkStatus::UnknownSlot:
        return pcscFailure(SCARD_E_UNKNOWN_READER, "unknown reader: " + readerName);
    case CtkStatus::NoCard:
        return pcscFailure(SCARD_E_NO_SMARTCARD, "no smartcard in reader: " + readerName);
    case CtkStatus::Mute:
        return pcscFailure(SCARD_W_UNRESPONSIVE_CARD, "card does not answer (mute)");
    case CtkStatus::SessionRefused:
        return pcscFailure(SCARD_E_SHARING_VIOLATION, "exclusive session refused or still held by another client");
    case CtkStatus::SessionLost:
        return pcscFailure(SCARD_W_RESET_CARD, "session lost (another client or the system took the card)");
    case CtkStatus::CardGone:
        return pcscFailure(SCARD_W_REMOVED_CARD, "card removed");
    case CtkStatus::Ok:
    case CtkStatus::CommError:
        break;
    }
    return pcscFailure(SCARD_F_COMM_ERROR, "transmit failed: " + failure.detail);
}

DWORD protocolOf(const Ctk::CtkCard& card)
{
    return card.protocol() == Ctk::CtkProtocol::T0 ? SCARD_PROTOCOL_T0 : SCARD_PROTOCOL_T1;
}

} // namespace

PCSCConnection::PCSCConnection(const std::string& readerName) : storedReaderName(readerName) {}

std::expected<void, TransportError> PCSCConnection::connect()
{
    auto opened = Ctk::CtkCard::open(storedReaderName, kSessionGrantDeadline);
    if (!opened) {
        return std::unexpected(failureOf(opened.error(), storedReaderName));
    }
    ctk = std::move(*opened);
    activeProtocol = protocolOf(*ctk);

    if (pcscTraceEnabled()) {
        emitPcscTraceEvent("connect", storedReaderName, this);
    }
    return {};
}

PCSCConnection::~PCSCConnection() = default;

std::expected<void, TransportError> PCSCConnection::reconnect()
{
    if (!ctk) {
        return std::unexpected(pcscFailure(SCARD_E_INVALID_HANDLE, "SCardReconnect failed"));
    }
    if (ctk->alive()) {
        return {};
    }
    if (pcscTraceEnabled()) {
        emitPcscTraceEvent("reconnect", readerName(), this);
    }
    if (ctk->lossKind() == Ctk::CtkStatus::CardGone) {
        return std::unexpected(pcscFailure(SCARD_W_REMOVED_CARD, "card removed"));
    }
    if (auto reopened = ctk->reopen(kSessionGrantDeadline); !reopened) {
        return std::unexpected(failureOf(reopened.error(), readerName()));
    }
    activeProtocol = protocolOf(*ctk);
    return {};
}

std::expected<void, TransportError> PCSCConnection::reconnectWithReset()
{
    if (!ctk) {
        return std::unexpected(pcscFailure(SCARD_E_INVALID_HANDLE, "SCardReconnect (reset) failed"));
    }
    return std::unexpected(
        pcscFailure(SCARD_E_UNSUPPORTED_FEATURE, "a card reset is not supported through CryptoTokenKit"));
}

bool PCSCConnection::detached() const noexcept
{
    return !ctk;
}

std::expected<std::vector<std::uint8_t>, TransportError>
PCSCConnection::exchangeWire(std::span<const std::uint8_t> command)
{
    if (!ctk) {
        return std::unexpected(pcscFailure(SCARD_E_INVALID_HANDLE, "SCardTransmit failed"));
    }
    auto reply = ctk->exchange(command);
    if (reply) {
        return std::move(*reply);
    }
    // SessionLost (the card stayed; another client or the system took the
    // session) classifies to CardReset, which the transmit loop reconnects on.
    return std::unexpected(failureOf(reply.error(), readerName()));
}

std::expected<void, TransportError> PCSCConnection::beginOnCard()
{
    // The held session is already exclusive; a transaction only has to find it
    // alive, and asks the card nothing.
    if (!ctk->alive()) {
        return reconnect();
    }
    return {};
}

void PCSCConnection::endOnCard() noexcept {}

std::expected<std::vector<uint8_t>, TransportError> PCSCConnection::atrFromCard() const
{
    if (!ctk) {
        return std::unexpected(pcscFailure(SCARD_E_INVALID_HANDLE, "SCardStatus failed"));
    }
    auto atr = ctk->atr();
    if (atr.empty()) {
        return std::unexpected(pcscFailure(SCARD_E_NO_SMARTCARD, "SCardStatus failed"));
    }
    return atr;
}

std::expected<std::vector<std::string>, TransportError> PCSCConnection::listReaders()
{
    return Ctk::slotNames();
}

} // namespace LibreSCRS::SmartCard::Internal
