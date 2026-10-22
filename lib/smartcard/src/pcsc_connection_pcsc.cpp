// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

// The nine members of PCSCConnection that talk to PC/SC. The shared transmit
// loop, tracing and the diagnostic opener stay in pcsc_connection.cpp.

#include "pcsc_connection.h"
#include "pcsc_trace.h"

#include <cstring>
#include <iomanip>
#include <iostream>
#include <memory>
#include <span>
#include <string>
#include <vector>

namespace LibreSCRS::SmartCard::Internal {

using namespace detail;

PCSCConnection::PCSCConnection(const std::string& readerName) : storedReaderName(readerName)
{
    LONG rv = SCardEstablishContext(SCARD_SCOPE_SYSTEM, nullptr, nullptr, &context);
    if (rv != SCARD_S_SUCCESS) {
        throw PCSCError("SCardEstablishContext failed", rv);
    }

    // Prefer T=1: natively supports arbitrary-length APDUs (no 255-byte Lc limit).
    // Fall back to T=0 for readers/cards that only support T=0 (e.g. older Apollo cards).
    rv = SCardConnect(context, readerName.c_str(), SCARD_SHARE_SHARED, SCARD_PROTOCOL_T1, &card, &activeProtocol);
    if (rv != SCARD_S_SUCCESS) {
        rv = SCardConnect(context, readerName.c_str(), SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0, &card, &activeProtocol);
    }
    if (rv != SCARD_S_SUCCESS) {
        SCardReleaseContext(context);
        throw PCSCError("SCardConnect failed on reader: " + readerName, rv);
    }

    // One event per handle, emitted after the protocol fallback has settled:
    // the tracer reported reconnects and transmits but never the open itself,
    // so a census of the handles a process holds could not be taken from a
    // trace. The T=1-then-T=0 retry above is one open, and this is where it is
    // known to have succeeded.
    if (pcscTraceEnabled()) {
        emitPcscTraceEvent("connect", readerName, this);
    }
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

void PCSCConnection::reconnect()
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
        throw PCSCError("SCardReconnect failed", rv);
    }
#ifndef NDEBUG
    std::cerr << "[PCSC] Reconnected, protocol=" << (activeProtocol == SCARD_PROTOCOL_T0 ? "T=0" : "T=1") << std::endl;
#endif
}

void PCSCConnection::reconnectWithReset()
{
    if (pcscTraceEnabled()) {
        emitPcscTraceEvent("reconnect-reset", readerName(), this);
    }

    LONG rv = SCardReconnect(card, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T1, SCARD_RESET_CARD, &activeProtocol);
    if (rv != SCARD_S_SUCCESS) {
        rv = SCardReconnect(card, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0, SCARD_RESET_CARD, &activeProtocol);
    }
    if (rv != SCARD_S_SUCCESS) {
        throw PCSCError("SCardReconnect (reset) failed", rv);
    }
}

APDUResponse PCSCConnection::transmitRaw(const uint8_t* cmdBytes, DWORD cmdLen)
{
    // Detached test seam: play the card side of a live SM tunnel. Taken ONLY
    // by a detached connection (card == 0, no PC/SC handle) with a responder
    // installed via setDetachedRawResponder — a production connection has
    // card != 0 so this branch is unreachable and the wire path below is
    // byte-identical; a detached connection with no responder falls through to
    // the (handle-less) SCardTransmit path exactly as before.
    if (card == 0 && detachedRawResponder) {
        return detachedRawResponder(std::span<const std::uint8_t>(cmdBytes, cmdLen));
    }

    // PCSC_TRACE hook is installed on this lowest-level overload because
    // every wire APDU passes through here regardless of which higher-level
    // caller produced it — including Secure-Messaging wrappers which
    // assemble a wrapped byte vector directly and skip the APDUCommand-
    // typed transmit() overload. Hooking here therefore captures plain
    // and SM-wrapped APDUs from a single point, and also picks up the
    // chained GET-RESPONSE / 6Cxx-retry follow-ups that transmit() emits.
    if (pcscTraceEnabled()) {
        emitPcscTraceWire("transmit", readerName(), this, cmdBytes, cmdLen);
    }

#ifndef NDEBUG
    // Log sent APDU — mask data for INSes whose payload carries PIN /
    // PUK / new-PIN bytes:
    //   0x20 VERIFY
    //   0x24 CHANGE REFERENCE DATA
    //   0x2C RESET RETRY COUNTER (PUK + new PIN in P1=0x00/0x02 forms)
    bool isSensitive = cmdLen >= 2 && isSensitiveIns(cmdBytes[1]);
    std::cerr << "[PCSC] TX (" << cmdLen << " bytes,"
              << " protocol=" << (activeProtocol == SCARD_PROTOCOL_T0 ? "T=0" : "T=1") << "):";
    DWORD headerLen = std::min(cmdLen, static_cast<DWORD>(isSensitive ? 5 : cmdLen));
    for (DWORD i = 0; i < headerLen; i++)
        std::cerr << " " << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(cmdBytes[i]);
    if (isSensitive && cmdLen > 5)
        std::cerr << " [" << (cmdLen - 5) << " bytes masked]";
    else
        for (DWORD i = headerLen; i < cmdLen; i++)
            std::cerr << " " << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(cmdBytes[i]);
    std::cerr << std::dec << std::endl;
#endif

    const SCARD_IO_REQUEST* pioSendPci = (activeProtocol == SCARD_PROTOCOL_T0) ? SCARD_PCI_T0 : SCARD_PCI_T1;

    // 65538 = max extended APDU response (65536 data + 2 SW bytes)
    static thread_local std::vector<uint8_t> recvBuffer(65538);
    DWORD recvLength = static_cast<DWORD>(recvBuffer.size());

    LONG rv = SCardTransmit(card, pioSendPci, cmdBytes, cmdLen, nullptr, recvBuffer.data(), &recvLength);
    if (rv == static_cast<LONG>(SCARD_W_RESET_CARD)) {
        // Card was reset (e.g. hot-swap or external reset). Re-establish the
        // handle without physically resetting the card, then retry once --
        // unless the command carries a PIN: resent, it could spend a try on a
        // card whose verified state the reset cleared, or on another card.
#ifndef NDEBUG
        std::cerr << "[PCSC] SCardTransmit got RESET_CARD, reconnecting..." << std::endl;
#endif
        reconnect();
        if (cmdLen >= 2 && isSensitiveIns(cmdBytes[1])) {
            throw PCSCError("SCardTransmit failed", rv);
        }
        pioSendPci = (activeProtocol == SCARD_PROTOCOL_T0) ? SCARD_PCI_T0 : SCARD_PCI_T1;
        recvLength = static_cast<DWORD>(recvBuffer.size());
        rv = SCardTransmit(card, pioSendPci, cmdBytes, cmdLen, nullptr, recvBuffer.data(), &recvLength);
    }
    if (rv != SCARD_S_SUCCESS) {
#ifndef NDEBUG
        std::cerr << "[PCSC] SCardTransmit FAILED, rv=0x" << std::hex << rv << std::dec << std::endl;
#endif
        throw PCSCError("SCardTransmit failed", rv);
    }

#ifndef NDEBUG
    // Log received response
    std::cerr << "[PCSC] RX (" << recvLength << " bytes):";
    for (DWORD i = 0; i < recvLength; i++)
        std::cerr << " " << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(recvBuffer[i]);
    std::cerr << std::dec << std::endl;
#endif

    if (recvLength < 2)
        throw PCSCError("SCardTransmit: response too short (" + std::to_string(recvLength) + " bytes)",
                        SCARD_F_COMM_ERROR);

    APDUResponse response;
    response.sw1 = recvBuffer[recvLength - 2];
    response.sw2 = recvBuffer[recvLength - 1];
    if (recvLength > 2) {
        response.data.assign(recvBuffer.begin(), recvBuffer.begin() + static_cast<ptrdiff_t>(recvLength - 2));
    }

#ifndef NDEBUG
    std::cerr << "[PCSC] SW=0x" << std::hex << std::setfill('0') << std::setw(4) << response.statusWord() << std::dec
              << ", data=" << response.data.size() << " bytes" << std::endl;
#endif

    return response;
}

void PCSCConnection::beginTransaction()
{
    // Detached test connection (DetachedTag ctor): no card handle, no PC/SC
    // I/O. Treat the transaction as held without touching the (null) handle
    // so test-only holder acquisition through the CardTransaction RAII
    // wrapper works without a live reader.
    if (card == 0) {
        // ...unless a test armed a failure through the detached seam: this is
        // the only way to reach the throw below without hardware.
        if (detachedTransactionRv != SCARD_S_SUCCESS)
            throw PCSCError("SCardBeginTransaction failed", detachedTransactionRv);
        return;
    }
    LONG rv = SCardBeginTransaction(card);
    if (rv == static_cast<LONG>(SCARD_W_RESET_CARD)) {
        // Card was reset externally (reader firmware, or prior SCARD_RESET_CARD by another
        // process). Re-establish our handle without resetting the card (SCARD_LEAVE_CARD),
        // then retry. The caller's subsequent applet SELECT restores card context.
        reconnect(); // SCARD_LEAVE_CARD — safe for other SCARD_SHARE_SHARED connections
        rv = SCardBeginTransaction(card);
    }
    if (rv != SCARD_S_SUCCESS)
        throw PCSCError("SCardBeginTransaction failed", rv);
}

void PCSCConnection::endTransaction() noexcept
{
    // Detached test connection: no card handle to release (see beginTransaction).
    if (card == 0) {
        // ...but a test may be watching for the moment of release, which is
        // the only point at which the release ORDER is observable; see
        // setDetachedTransactionReleaseObserver. The call is contained because
        // this function is noexcept and the observer is arbitrary test code.
        if (detachedReleaseObserver) {
            try {
                detachedReleaseObserver();
            } catch (...) {
            }
        }
        return;
    }
    SCardEndTransaction(card, SCARD_LEAVE_CARD);
}

std::vector<uint8_t> PCSCConnection::getATR() const
{
    // Detached test connection WITH an ATR installed via setDetachedAtr:
    // hand those bytes back instead of querying the (handle-less)
    // SCardStatus. Mirrors the transmitRaw seam above (card == 0 &&
    // detachedRawResponder): only a detached connection that opted in by
    // installing a responder/ATR gets the synthetic answer. A detached
    // connection with no ATR installed falls through to SCardStatus(0, ...)
    // exactly as before setDetachedAtr existed, which fails (throws) --
    // e.g. eidcard::EIdCard::detectCardType() reached via
    // CardPlugin::canHandleConnection() on an un-rigged detached session
    // must keep seeing that failure, not a silent {} that would route it
    // into the AID-probing SELECT fallback and generate APDUs a passive
    // detached rig never expects.
    if (card == 0 && !detachedAtr.empty()) {
        return detachedAtr;
    }

    DWORD readerLen = 0;
    DWORD state = 0;
    DWORD protocol = 0;
    BYTE atr[MAX_ATR_SIZE];
    DWORD atrLen = sizeof(atr);

    LONG rv = SCardStatus(card, nullptr, &readerLen, &state, &protocol, atr, &atrLen);
    if (rv != SCARD_S_SUCCESS) {
        throw PCSCError("SCardStatus failed", rv);
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
    PCSCContextHandle() noexcept : context{}, established{false}
    {
        const LONG rv = SCardEstablishContext(SCARD_SCOPE_SYSTEM, nullptr, nullptr, &context);
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

    [[nodiscard]] SCARDCONTEXT get() const noexcept
    {
        return context;
    }

private:
    SCARDCONTEXT context;
    bool established;
};

} // namespace

std::vector<std::string> PCSCConnection::listReaders()
{
    PCSCContextHandle ctx;
    if (!ctx.ok())
        return {};

    DWORD readersLen = 0;
    LONG rv = SCardListReaders(ctx.get(), nullptr, nullptr, &readersLen);
    if (rv != SCARD_S_SUCCESS)
        return {};

    // vector<char> buffer(readersLen) may throw std::bad_alloc on a card
    // with a multi-string-larger-than-available-memory; PCSCContextHandle's
    // dtor handles SCardReleaseContext on unwind.
    std::vector<char> buffer(readersLen);
    rv = SCardListReaders(ctx.get(), nullptr, buffer.data(), &readersLen);
    if (rv != SCARD_S_SUCCESS)
        return {};

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
