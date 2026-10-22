// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "pcsc_connection.h"
#include "pcsc_trace.h"
#include <smartcard/secure_buffer.h>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <execinfo.h>
#include <functional>
#include <iomanip>
#include <iostream>
#include <memory>
#include <span>
#include <thread>
#include <unistd.h>

namespace {

constexpr int kStackDepth = 12;
constexpr std::size_t kMaxDataPrintBytes = 16;

} // anonymous namespace

namespace LibreSCRS::SmartCard::Internal::detail {

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

} // namespace LibreSCRS::SmartCard::Internal::detail

namespace {

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

} // anonymous namespace

namespace LibreSCRS::SmartCard::Internal::detail {

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

} // namespace LibreSCRS::SmartCard::Internal::detail

namespace LibreSCRS::SmartCard::Internal {

using namespace detail;

// Diagnostic-only escape hatch (see header): opens a real PC/SC connection
// for the CLI tools / hardware-probe tests under tools/ and test/. A static
// member can reach the private reader-name ctor; production code cannot.
std::unique_ptr<PCSCConnection> PCSCConnection::openRawDiagnostic(const std::string& readerName)
{
    return std::unique_ptr<PCSCConnection>(new PCSCConnection(readerName));
}

// Test-only ctor: no PC/SC calls, no context, no card. Used by CardSession
// injection paths to produce a connection object whose address can be used
// as a key while keeping readerName() functional.
PCSCConnection::PCSCConnection(DetachedTag, const std::string& readerName) : storedReaderName(readerName) {}

// The four members that ARM a PCSCConnection test seam --
// setTransmitFilter, clearTransmitFilter, setDetachedRawResponder and
// setDetachedAtr -- are deliberately NOT defined here. Their bodies live in
// the build-tree-only LibreSCRS_SmartCard_TestHelpers archive
// (lib/LibreSCRS/SmartCard/test_helpers/pcsc_connection_test_helpers.cpp),
// so no shipped library carries a definition -- and therefore no dynamic
// export -- for any way to arm a seam. The members they write
// (transmitFilter, detachedRawResponder, detachedAtr) and the branches that
// read them stay in the production class: the branches are inert until a
// test arms one, and moving the members would change the class layout.
//
// A definition placed here would not stay private: this TU is compiled into
// libLibreSCRS_SmartCard, the class is LIBRESCRS_PUBLIC_API, and both export
// filters (the `*LibreSCRS::*` glob in cmake/librescrs-public-exports.map,
// the `__ZN9LibreSCRS*` prefixes on Darwin) admit every member. Being a
// dynamic export also roots the section, so --gc-sections cannot drop it
// either -- which is why moving the definition out, rather than annotating
// the declaration, is what removes it.

APDUResponse PCSCConnection::transmitRaw(const APDUCommand& cmd)
{
    // SecureBuffer adoption: the serialization may carry PIN/PUK bytes
    // (PIN verbs), so the wire copy is cleansed on every exit path.
    SecureBuffer bytes(cmd.toBytes());
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

    // SecureBuffer adoption: the serialization may carry PIN/PUK bytes
    // (PIN verbs), so the wire copy is cleansed on every exit path.
    SecureBuffer cmdBytes(cmd.toBytes());
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
            // Grow then copy, rather than a range insert. Same bytes, same
            // order -- but GCC 13 cannot see the bound through
            // vector::_M_range_insert here and reports -Wstringop-overflow,
            // which this build turns fatal. Newer GCC does not, so the local
            // toolchain never shows it and only CI does.
            if (!response.data.empty()) {
                const size_t joined = accumulated.size();
                accumulated.resize(joined + response.data.size());
                std::memcpy(accumulated.data() + joined, response.data.data(), response.data.size());
            }
            response.data = std::move(accumulated);
        }
    }

    // SW1=6C: wrong Le — resend command with corrected Le (T=0 specific).
    // ISO 7816-4 defines this only for commands that carry an Le byte; an
    // Le-less command (case 1 / case 3 — every PIN verb) has DATA (or P2)
    // as its last serialized byte, so it must never be rewritten. For those
    // the status word is surfaced to the caller unchanged. The retry is
    // rebuilt from the APDU model rather than patched into the serialized
    // buffer so extended-Le encodings are corrected as a whole.
    if (activeProtocol == SCARD_PROTOCOL_T0 && response.sw1 == 0x6C && cmd.hasLe) {
        APDUCommand retry = cmd;
        retry.le = response.sw2; // exact length announced by the card (0x00 = 256)
        const SecureBuffer retryBytes(retry.toBytes());
        response = transmitRaw(retryBytes.data(), static_cast<DWORD>(retryBytes.size()));
    }

    return response;
}

} // namespace LibreSCRS::SmartCard::Internal
