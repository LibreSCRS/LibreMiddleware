// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

// The members of PCSCConnection that talk to PC/SC. The shared transmit
// loop, the wire flow around exchangeWire, tracing, the detached seams and the
// diagnostic opener stay in pcsc_connection.cpp.

#include "pcsc_connection.h"
#include "pcsc_classify.h"
#include "pcsc_trace.h"
#include <smartcard/secure_wipe.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <format>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace LibreSCRS::SmartCard::Internal {

using namespace detail;

PCSCConnection::PCSCConnection(const std::string& readerName) : storedReaderName(readerName) {}

std::expected<void, TransportError> PCSCConnection::connect()
{
    const std::string& readerName = storedReaderName;
    LONG rv = SCardEstablishContext(SCARD_SCOPE_SYSTEM, nullptr, nullptr, &context);
    if (rv != SCARD_S_SUCCESS) {
        context = 0;
        return std::unexpected(pcscFailure(rv, "SCardEstablishContext failed"));
    }

    // Prefer T=1: natively supports arbitrary-length APDUs (no 255-byte Lc limit).
    // Fall back to T=0 for readers/cards that only support T=0 (e.g. older cards).
    rv = SCardConnect(context, readerName.c_str(), SCARD_SHARE_SHARED, SCARD_PROTOCOL_T1, &card, &activeProtocol);
    if (rv != SCARD_S_SUCCESS) {
        rv = SCardConnect(context, readerName.c_str(), SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0, &card, &activeProtocol);
    }
    if (rv != SCARD_S_SUCCESS) {
        SCardReleaseContext(context);
        context = 0;
        card = 0;
        return std::unexpected(pcscFailure(rv, "SCardConnect failed on reader: " + readerName));
    }

    // One event per handle, emitted after the protocol fallback has settled:
    // the tracer reported reconnects and transmits but never the open itself,
    // so a census of the handles a process holds could not be taken from a
    // trace. The T=1-then-T=0 retry above is one open, and this is where it is
    // known to have succeeded.
    if (pcscTraceEnabled()) {
        emitPcscTraceEvent("connect", readerName, this);
    }
    // Connecting sends no command: a card that still holds a secure-messaging
    // session from another process would lose it to a plain one. Case 2E has no
    // TPDU of its own on T=0, and no card has been measured taking extended
    // there, so T=0 reads short; a T=1 card stays Untested until
    // learnReadLengthBeforeSm() or the first long READ BINARY decides.
    if (activeProtocol == SCARD_PROTOCOL_T0) {
        lengthPolicy.learn(ReadLengthState::Short);
    }
    return {};
}

PCSCConnection::~PCSCConnection()
{
    if (card) {
        SCardDisconnect(card, SCARD_LEAVE_CARD);
    }
    if (context) {
        SCardReleaseContext(context);
    }
}

std::expected<void, TransportError> PCSCConnection::reconnect()
{
    if (pcscTraceEnabled()) {
        // Lifecycle event — no APDU. Captured stack frame pinpoints
        // which higher layer (PCSCWorker, applet hot-swap, RESET_CARD
        // recovery, etc.) triggered the reconnect.
        emitPcscTraceEvent("reconnect", readerName(), this);
    }

    // Use SCARD_LEAVE_CARD (not SCARD_RESET_CARD) to avoid physically resetting
    // the card and invalidating other SCARD_SHARE_SHARED connections (e.g. Firefox
    // PKCS#11 holding its own connection while LibreCelik retries a read).
    LONG rv = SCardReconnect(card, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T1, SCARD_LEAVE_CARD, &activeProtocol);
    if (rv != SCARD_S_SUCCESS) {
        rv = SCardReconnect(card, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0, SCARD_LEAVE_CARD, &activeProtocol);
    }
    if (rv != SCARD_S_SUCCESS) {
        return std::unexpected(pcscFailure(rv, "SCardReconnect failed"));
    }
    return {};
}

std::expected<void, TransportError> PCSCConnection::reconnectWithReset()
{
    if (pcscTraceEnabled()) {
        emitPcscTraceEvent("reconnect-reset", readerName(), this);
    }

    LONG rv = SCardReconnect(card, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T1, SCARD_RESET_CARD, &activeProtocol);
    if (rv != SCARD_S_SUCCESS) {
        rv = SCardReconnect(card, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0, SCARD_RESET_CARD, &activeProtocol);
    }
    if (rv != SCARD_S_SUCCESS) {
        return std::unexpected(pcscFailure(rv, "SCardReconnect (reset) failed"));
    }
    return {};
}

bool PCSCConnection::detached() const noexcept
{
    return card == 0;
}

std::expected<std::vector<std::uint8_t>, TransportError>
PCSCConnection::exchangeWire(std::span<const std::uint8_t> command)
{
    const auto* cmdBytes = command.data();
    const auto cmdLen = static_cast<DWORD>(command.size());

    const SCARD_IO_REQUEST* pioSendPci = (activeProtocol == SCARD_PROTOCOL_T0) ? SCARD_PCI_T0 : SCARD_PCI_T1;

    // 65538 = max extended APDU response (65536 data + 2 SW bytes)
    static thread_local std::vector<uint8_t> recvBuffer(65538);
    DWORD recvLength = static_cast<DWORD>(recvBuffer.size());

    LONG rv = SCardTransmit(card, pioSendPci, cmdBytes, cmdLen, nullptr, recvBuffer.data(), &recvLength);
    if (rv == static_cast<LONG>(SCARD_W_RESET_CARD)) {
        // Card was reset (e.g. hot-swap or external reset).
        if (pcscTraceEnabled())
            emitPcscTraceLine("[PCSC_TRACE] SCardTransmit: card was reset");
        return std::unexpected(pcscFailure(rv, "SCardTransmit failed"));
    }
    if (rv != SCARD_S_SUCCESS) {
        if (pcscTraceEnabled())
            emitPcscTraceLine(
                std::format("[PCSC_TRACE] SCardTransmit failed rv=0x{:08X}", static_cast<std::uint32_t>(rv)));
        return std::unexpected(pcscFailure(rv, "SCardTransmit failed"));
    }

    std::vector<std::uint8_t> reply(recvBuffer.begin(), recvBuffer.begin() + static_cast<ptrdiff_t>(recvLength));
    // The thread's receive buffer outlives this call: what the card answered
    // (a decrypted block, a personal record) is not left in it.
    secureWipe(recvBuffer.data(), recvLength);
    return reply;
}

std::expected<void, TransportError> PCSCConnection::beginOnCard()
{
    LONG rv = SCardBeginTransaction(card);
    if (rv == static_cast<LONG>(SCARD_W_RESET_CARD)) {
        // Card was reset externally (reader firmware, or prior SCARD_RESET_CARD by another
        // process). Re-establish our handle without resetting the card (SCARD_LEAVE_CARD),
        // then retry. The caller's subsequent applet SELECT restores card context.
        if (auto reconnected = reconnect();
            !reconnected) // SCARD_LEAVE_CARD — safe for other SCARD_SHARE_SHARED connections
            return reconnected;
        rv = SCardBeginTransaction(card);
    }
    if (rv != SCARD_S_SUCCESS)
        return std::unexpected(pcscFailure(rv, "SCardBeginTransaction failed"));
    return {};
}

void PCSCConnection::endOnCard() noexcept
{
    SCardEndTransaction(card, SCARD_LEAVE_CARD);
}

std::expected<std::vector<uint8_t>, TransportError> PCSCConnection::atrFromCard() const
{
    // A detached connection (card == 0) gets here too and fails in
    // SCardStatus, as it always has.
    DWORD readerLen = 0;
    DWORD state = 0;
    DWORD protocol = 0;
    BYTE atr[MAX_ATR_SIZE];
    DWORD atrLen = sizeof(atr);

    LONG rv = SCardStatus(card, nullptr, &readerLen, &state, &protocol, atr, &atrLen);
    if (rv != SCARD_S_SUCCESS) {
        return std::unexpected(pcscFailure(rv, "SCardStatus failed"));
    }

    return std::vector<uint8_t>(atr, atr + atrLen);
}

// RAII wrapper for an SCARDCONTEXT established via SCardEstablishContext.
// Pairs the call with SCardReleaseContext on scope exit so any throwable
// allocation between (e.g. std::vector<char> buffer(readersLen) on
// bad_alloc) does not leak the PC/SC context handle.
//
// Non-copyable, non-movable on purpose: the listReaders use is a single
// scoped owner; broader use would have to wrap the SCARDCONTEXT in a
// std::optional or convert to move-only and is outside this scope.
namespace {

class PCSCContextHandle
{
public:
    PCSCContextHandle() noexcept : context{}, established{false}, rv{SCARD_S_SUCCESS}
    {
        rv = SCardEstablishContext(SCARD_SCOPE_SYSTEM, nullptr, nullptr, &context);
        established = (rv == SCARD_S_SUCCESS);
    }

    ~PCSCContextHandle() noexcept
    {
        if (established) {
            SCardReleaseContext(context);
        }
    }

    PCSCContextHandle(const PCSCContextHandle&) = delete;
    PCSCContextHandle& operator=(const PCSCContextHandle&) = delete;
    PCSCContextHandle(PCSCContextHandle&&) = delete;
    PCSCContextHandle& operator=(PCSCContextHandle&&) = delete;

    [[nodiscard]] bool ok() const noexcept
    {
        return established;
    }

    [[nodiscard]] LONG status() const noexcept
    {
        return rv;
    }

    [[nodiscard]] SCARDCONTEXT get() const noexcept
    {
        return context;
    }

private:
    SCARDCONTEXT context;
    bool established;
    LONG rv;
};

} // namespace

std::expected<std::vector<std::string>, TransportError> PCSCConnection::listReaders()
{
    PCSCContextHandle ctx;
    if (!ctx.ok())
        return std::unexpected(pcscFailure(ctx.status(), "SCardEstablishContext failed"));

    DWORD readersLen = 0;
    LONG rv = SCardListReaders(ctx.get(), nullptr, nullptr, &readersLen);
    // No reader attached is an empty list, not a failure.
    if (static_cast<std::uint32_t>(rv) == static_cast<std::uint32_t>(SCARD_E_NO_READERS_AVAILABLE))
        return std::vector<std::string>{};
    if (rv != SCARD_S_SUCCESS)
        return std::unexpected(pcscFailure(rv, "SCardListReaders failed"));

    // vector<char> buffer(readersLen) may throw std::bad_alloc on a card
    // with a multi-string-larger-than-available-memory; PCSCContextHandle's
    // dtor handles SCardReleaseContext on unwind.
    std::vector<char> buffer(readersLen);
    rv = SCardListReaders(ctx.get(), nullptr, buffer.data(), &readersLen);
    if (static_cast<std::uint32_t>(rv) == static_cast<std::uint32_t>(SCARD_E_NO_READERS_AVAILABLE))
        return std::vector<std::string>{};
    if (rv != SCARD_S_SUCCESS)
        return std::unexpected(pcscFailure(rv, "SCardListReaders failed"));

    // Parse multi-string (null-separated, double-null terminated)
    std::vector<std::string> readers;
    const char* ptr = buffer.data();
    while (ptr < buffer.data() + readersLen && *ptr != '\0') {
        readers.emplace_back(ptr);
        ptr += readers.back().size() + 1;
    }
    return readers;
}

} // namespace LibreSCRS::SmartCard::Internal
