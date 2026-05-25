// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "pcsc_connection.h"
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <execinfo.h>
#include <functional>
#include <iomanip>
#include <iostream>
#include <span>
#include <thread>
#include <unistd.h>

namespace {

constexpr int kStackDepth = 12;
constexpr std::size_t kMaxDataPrintBytes = 16;

// INSes whose payload carries PIN / PUK / new-PIN bytes (kept consistent
// with transmitRaw's masking precedent below):
//   0x20 VERIFY
//   0x24 CHANGE REFERENCE DATA
//   0x2C RESET RETRY COUNTER (PUK + new PIN in P1=0x00/0x02 forms)
[[nodiscard]] constexpr bool isSensitiveIns(std::uint8_t ins) noexcept
{
    return ins == 0x20 || ins == 0x24 || ins == 0x2C;
}

// Env-var-gated tracer for diagnosing cross-reader / cross-applet PC/SC
// handle reuse (e.g. applet-A's Secure-Messaging channel still being fed
// APDUs after the connection was repurposed for applet-B). Emits one
// [PCSC_TRACE] block per wire APDU (PCSCConnection::transmitRaw) when
// LIBRESCRS_PCSC_TRACE is set to a value other than "0". The captured
// stack frames let an offline reviewer walk back from the transmitRaw
// callsite via addr2line to the originating higher-level caller.
[[nodiscard]] bool pcscTraceEnabled()
{
    // Cache env-var lookup once on first call. Per-call cost on the hot
    // path when disabled is a single function-local-static load.
    static const bool enabled = []() {
        const char* v = std::getenv("LIBRESCRS_PCSC_TRACE");
        return v != nullptr && std::strcmp(v, "0") != 0 && v[0] != '\0';
    }();
    return enabled;
}

// Shared trace-block prefix: "[PCSC_TRACE] t=... tid=... phase=... reader=... conn=...".
// Caller writes any phase-specific tail (e.g. " apdu=..." for transmit) and the
// closing newline.
void writePcscTracePrefix(const char* phase, const std::string& readerName, const void* connAddr)
{
    using namespace std::chrono;
    const auto now = steady_clock::now().time_since_epoch();
    const auto micros = duration_cast<microseconds>(now).count();

    std::fprintf(stderr, "[PCSC_TRACE] t=%lld tid=%zx phase=%s reader=%s conn=%p", static_cast<long long>(micros),
                 std::hash<std::thread::id>{}(std::this_thread::get_id()), phase, readerName.c_str(), connAddr);
}

// Capture and dump the current call stack to stderr in the [PCSC_TRACE] block
// format. Symbol resolution happens offline (addr2line) during trace analysis.
void emitPcscStackFrames()
{
    void* frames[kStackDepth];
    int frameCount = ::backtrace(frames, kStackDepth);
    std::fprintf(stderr, "[PCSC_TRACE]   stack(%d frames):\n", frameCount);
    ::backtrace_symbols_fd(frames, frameCount, STDERR_FILENO);
    std::fprintf(stderr, "[PCSC_TRACE]   /stack\n");
}

// Emit a single [PCSC_TRACE] block for a transmit event. Takes the APDU pieces
// structurally (header, data span, optional Le) so the printer never has to
// guess where Le lives or trade off Lc-data bytes against Le visibility.
//
// PIN/PUK redaction: when `dataRedacted` is true the data field is
// printed as a sentinel ("<redacted N bytes>") instead of hex.
void emitPcscTrace(const char* phase, const std::string& readerName, const void* connAddr,
                   std::span<const std::uint8_t, 5> header, std::span<const std::uint8_t> data, bool dataRedacted,
                   bool hasLe, std::uint8_t le)
{
    writePcscTracePrefix(phase, readerName, connAddr);
    std::fprintf(stderr, " apdu=");

    // Header: CLA INS P1 P2 Lc — always printed.
    for (std::uint8_t b : header) {
        std::fprintf(stderr, "%02X", b);
    }

    // Data: redacted for sensitive INS; otherwise first kMaxDataPrintBytes
    // bytes, with an explicit "...(N more bytes)" tail when truncated.
    if (dataRedacted) {
        std::fprintf(stderr, "<redacted %zu bytes>", data.size());
    } else {
        const std::size_t printBytes = std::min(data.size(), kMaxDataPrintBytes);
        for (std::size_t i = 0; i < printBytes; ++i) {
            std::fprintf(stderr, "%02X", data[i]);
        }
        if (data.size() > kMaxDataPrintBytes) {
            std::fprintf(stderr, "...(%zu more bytes)", data.size() - kMaxDataPrintBytes);
        }
    }

    // Le: printed last when present. For sensitive INS we still suppress
    // it (PIN-VERIFY APDUs are typically Le-less anyway, but be explicit).
    if (hasLe && !dataRedacted) {
        std::fprintf(stderr, "%02X", le);
    } else if (hasLe && dataRedacted) {
        std::fprintf(stderr, "<le redacted>");
    }
    std::fprintf(stderr, "\n");

    emitPcscStackFrames();
}

// Emit a single [PCSC_TRACE] block for a non-transmit lifecycle event
// (e.g. reconnect). No `apdu=` field — just the prefix + stack frames.
void emitPcscTraceEvent(const char* phase, const std::string& readerName, const void* connAddr)
{
    writePcscTracePrefix(phase, readerName, connAddr);
    std::fprintf(stderr, "\n");
    emitPcscStackFrames();
}

// Parse wire-format APDU bytes (cmdBytes, cmdLen) into the structured
// pieces emitPcscTrace expects, then emit one trace block. This is the
// single hook point we install on PCSCConnection::transmitRaw(uint8_t*,
// DWORD) so that every actual on-wire APDU is captured — including those
// produced by Secure-Messaging wrappers (PaceChannel) which bypass the
// APDUCommand-typed transmit() overload.
//
// Wire-format cases (short APDU only — extended-length is rare on SM
// channels and printed best-effort as header-only):
//   - Case 1:  CLA INS P1 P2                (4 bytes, no Lc/data/Le)
//   - Case 2s: CLA INS P1 P2 Le             (5 bytes, Le-only; ISO 7816-4
//                                            disambiguates 5-byte APDUs
//                                            as Case 2)
//   - Case 3s: CLA INS P1 P2 Lc data[Lc]    (5+Lc bytes, no Le)
//   - Case 4s: CLA INS P1 P2 Lc data[Lc] Le (6+Lc bytes, with Le)
void emitPcscTraceWire(const char* phase, const std::string& readerName, const void* connAddr,
                       const std::uint8_t* cmdBytes, DWORD cmdLen)
{
    // Build the 5-byte header that emitPcscTrace prints. For sub-5-byte
    // wire APDUs (Case 1, or malformed) header bytes beyond cmdLen are
    // zero-padded — the printed hex therefore stays a constant 10 nibbles,
    // matching the structured-call path's trace format.
    std::array<std::uint8_t, 5> header{};
    const std::size_t headerLen = std::min(static_cast<std::size_t>(cmdLen), header.size());
    for (std::size_t i = 0; i < headerLen; ++i) {
        header[i] = cmdBytes[i];
    }

    std::span<const std::uint8_t> data;
    bool hasLe = false;
    std::uint8_t leByte = 0;

    if (cmdLen == 5) {
        // Case 2s: Le-only. Byte at offset 4 is Le, not Lc. Keep it in
        // header[4] for consistency with the 5-byte hex layout, and also
        // flag it as Le so the helper's tail prints it. The redundancy
        // is intentional: the header layout is a fixed wire-prefix view,
        // and the Le tail is the semantic value.
        hasLe = true;
        leByte = cmdBytes[4];
    } else if (cmdLen > 5) {
        // Case 3s / Case 4s: byte at offset 4 is Lc.
        const std::uint8_t lc = cmdBytes[4];
        const std::size_t dataEnd = static_cast<std::size_t>(5) + lc;
        if (dataEnd <= cmdLen) {
            if (lc > 0) {
                data = std::span<const std::uint8_t>(cmdBytes + 5, lc);
            }
            if (cmdLen > dataEnd) {
                hasLe = true;
                leByte = cmdBytes[dataEnd];
            }
        }
        // If dataEnd > cmdLen the APDU is malformed (Lc claims more bytes
        // than were sent). Fall through with empty data + no Le — the
        // header alone is still useful for the trace consumer.
    }
    // cmdLen == 4 (Case 1) and cmdLen < 4 (malformed) both fall through
    // with empty data + no Le.

    const std::uint8_t ins = (cmdLen >= 2) ? cmdBytes[1] : std::uint8_t{0};
    emitPcscTrace(phase, readerName, connAddr, std::span<const std::uint8_t, 5>(header), data, isSensitiveIns(ins),
                  hasLe, leByte);
}

} // anonymous namespace

namespace LibreSCRS::SmartCard::Internal {

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
}

// Test-only ctor: no PC/SC calls, no context, no card. Used by CardSession
// injection paths to produce a connection object whose address can be used
// as a key while keeping readerName() functional.
PCSCConnection::PCSCConnection(DetachedTag, const std::string& readerName) : storedReaderName(readerName) {}

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

APDUResponse PCSCConnection::transmitRaw(const uint8_t* cmdBytes, DWORD cmdLen)
{
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
    bool isSensitive = cmdLen >= 2 && (cmdBytes[1] == 0x20 || cmdBytes[1] == 0x24 || cmdBytes[1] == 0x2C);
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
        // handle without physically resetting the card, then retry once.
#ifndef NDEBUG
        std::cerr << "[PCSC] SCardTransmit got RESET_CARD, reconnecting..." << std::endl;
#endif
        reconnect();
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

void PCSCConnection::setTransmitFilter(TransmitFilter filter)
{
    transmitFilter = std::move(filter);
}

void PCSCConnection::clearTransmitFilter()
{
    transmitFilter = nullptr;
}

APDUResponse PCSCConnection::transmitRaw(const APDUCommand& cmd)
{
    auto bytes = cmd.toBytes();
    return transmitRaw(bytes.data(), static_cast<DWORD>(bytes.size()));
}

APDUResponse PCSCConnection::transmitRaw(std::span<const std::uint8_t> cmdBytes)
{
    return transmitRaw(cmdBytes.data(), static_cast<DWORD>(cmdBytes.size()));
}

APDUResponse PCSCConnection::transmit(const APDUCommand& cmd)
{
    if (transmitFilter)
        return transmitFilter(cmd);

    auto cmdBytes = cmd.toBytes();
    auto response = transmitRaw(cmdBytes.data(), static_cast<DWORD>(cmdBytes.size()));

    // SW1=61: response data available — send GET RESPONSE to retrieve it.
    // This is an ISO 7816-4 mechanism used by both T=0 and T=1 protocols.
    // Loop to handle chained responses (card may send multiple 61xx).
    //
    // Defensive caps: a buggy or hostile card can in principle return 61xx
    // indefinitely, which would grow `accumulated` without bound. 256
    // iterations × 256 bytes = 64 KiB is well above any legitimate APDU
    // response chain (eMRTD DG files cap well below this; EF.CERT payloads
    // similarly). Break on exceed — caller sees truncated data + last SW.
    constexpr size_t kMaxGetResponseIters = 256;
    constexpr size_t kMaxGetResponseBytes = 65536;
    size_t getRespIters = 0;
    size_t totalBytes = response.data.size();
    while (response.sw1 == 0x61) {
        if (++getRespIters > kMaxGetResponseIters)
            break;
        auto accumulated = std::move(response.data);
        uint8_t le = response.sw2; // 0x00 = 256 bytes
        uint8_t getResponse[] = {0x00, 0xC0, 0x00, 0x00, le};
        response = transmitRaw(getResponse, sizeof(getResponse));
        totalBytes += response.data.size();
        if (totalBytes > kMaxGetResponseBytes) {
            response.data = std::move(accumulated);
            break;
        }
        if (!accumulated.empty()) {
            accumulated.insert(accumulated.end(), response.data.begin(), response.data.end());
            response.data = std::move(accumulated);
        }
    }

    // SW1=6C: wrong Le — resend command with corrected Le (T=0 specific)
    if (activeProtocol == SCARD_PROTOCOL_T0 && response.sw1 == 0x6C) {
        cmdBytes.back() = response.sw2;
        response = transmitRaw(cmdBytes.data(), static_cast<DWORD>(cmdBytes.size()));
    }

    return response;
}

void PCSCConnection::beginTransaction()
{
    // Detached test connection (DetachedTag ctor): no card handle, no PC/SC
    // I/O. Treat the transaction as held without touching the (null) handle
    // so test-only holder acquisition through the CardTransaction RAII
    // wrapper works without a live reader.
    if (card == 0) {
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
        return;
    }
    SCardEndTransaction(card, SCARD_LEAVE_CARD);
}

void PCSCConnection::cancel()
{
    SCardCancel(context);
}

std::vector<uint8_t> PCSCConnection::getATR() const
{
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
