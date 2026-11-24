// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "pcsc_connection.h"
#include "pcsc_classify.h"
#include "pcsc_trace.h"
#include <smartcard/read_length_policy.h>
#include <smartcard/secure_buffer.h>

#include <LibreSCRS/Logging.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdlib>
#include <execinfo.h>
#include <format>
#include <functional>
#include <iterator>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <thread>
#include <vector>

namespace {

constexpr int kStackDepth = 12;
constexpr std::size_t kMaxDataPrintBytes = 16;

} // anonymous namespace

namespace LibreSCRS::SmartCard::Internal::detail {

// Tracer for diagnosing cross-reader / cross-applet PC/SC handle reuse (e.g.
// applet-A's Secure-Messaging channel still being fed APDUs after the
// connection was repurposed for applet-B). Emits one trace block per wire
// APDU (PCSCConnection::transmitRaw) on the Pcsc channel of the logging
// facade, which LIBRESCRS_PCSC_TRACE switches on. The captured stack frames
// let an offline reviewer walk back from the transmitRaw callsite via
// addr2line to the originating higher-level caller.
bool pcscTraceEnabled()
{
    return LibreSCRS::log::traceEnabled(LibreSCRS::log::TraceChannel::Pcsc);
}

void emitPcscTraceLine(std::string_view line)
{
    LibreSCRS::log::trace(LibreSCRS::log::TraceChannel::Pcsc, line);
}

} // namespace LibreSCRS::SmartCard::Internal::detail

namespace {

using LibreSCRS::SmartCard::Internal::detail::emitPcscTraceLine;

// Shared trace-block prefix: "[PCSC_TRACE] t=... tid=... phase=... reader=... conn=...".
// The caller appends any phase-specific tail (e.g. " apdu=..." for transmit).
std::string pcscTracePrefix(const char* phase, const std::string& readerName, const void* connAddr)
{
    using namespace std::chrono;
    const auto now = steady_clock::now().time_since_epoch();
    const auto micros = duration_cast<microseconds>(now).count();

    return std::format("[PCSC_TRACE] t={} tid={:x} phase={} reader={} conn={}", static_cast<long long>(micros),
                       std::hash<std::thread::id>{}(std::this_thread::get_id()), phase, readerName, connAddr);
}

// Capture the current call stack as trace lines. Symbol resolution happens
// offline (addr2line) during trace analysis.
void emitPcscStackFrames()
{
    void* frames[kStackDepth];
    const int frameCount = ::backtrace(frames, kStackDepth);
    emitPcscTraceLine(std::format("[PCSC_TRACE]   stack({} frames):", frameCount));
    std::unique_ptr<char*, decltype(&std::free)> symbols(::backtrace_symbols(frames, frameCount), &std::free);
    for (int i = 0; i < frameCount; ++i)
        emitPcscTraceLine(symbols ? std::string_view{symbols.get()[i]} : std::string_view{"?"});
    emitPcscTraceLine("[PCSC_TRACE]   /stack");
}

void appendHex(std::string& out, std::span<const std::uint8_t> bytes)
{
    for (std::uint8_t b : bytes)
        std::format_to(std::back_inserter(out), "{:02X}", b);
}

// Emit a single [PCSC_TRACE] block for a transmit event. Takes the APDU pieces
// structurally (header, data span, optional Le) so the printer never has to
// guess where Le lives or trade off Lc-data bytes against Le visibility.
//
// PIN/PUK redaction: when `dataRedacted` is true the data field is
// printed as a sentinel ("<redacted N bytes>") instead of hex.
void emitPcscTrace(const char* phase, const std::string& readerName, const void* connAddr,
                   std::span<const std::uint8_t, 5> header, std::span<const std::uint8_t> data, bool dataRedacted,
                   bool hasLe, std::uint16_t le, bool extendedLe, std::optional<std::uint16_t> extendedLc)
{
    std::string line = pcscTracePrefix(phase, readerName, connAddr);
    line += " apdu=";

    // Header: CLA INS P1 P2 Lc — always printed.
    appendHex(line, header);

    // An extended Lc follows the 00 marker the header ends with.
    if (extendedLc)
        std::format_to(std::back_inserter(line), "{:04X}", *extendedLc);

    // Data: redacted for sensitive INS; otherwise first kMaxDataPrintBytes
    // bytes, with an explicit "...(N more bytes)" tail when truncated.
    if (dataRedacted) {
        std::format_to(std::back_inserter(line), "<redacted {} bytes>", data.size());
    } else {
        appendHex(line, data.first(std::min(data.size(), kMaxDataPrintBytes)));
        if (data.size() > kMaxDataPrintBytes)
            std::format_to(std::back_inserter(line), "...({} more bytes)", data.size() - kMaxDataPrintBytes);
    }

    // Le: printed last when present. For sensitive INS we still suppress
    // it (PIN-VERIFY APDUs are typically Le-less anyway, but be explicit).
    if (hasLe && !dataRedacted) {
        if (extendedLe)
            std::format_to(std::back_inserter(line), "{:04X}", le);
        else
            std::format_to(std::back_inserter(line), "{:02X}", le);
    } else if (hasLe && dataRedacted)
        line += "<le redacted>";
    emitPcscTraceLine(line);

    emitPcscStackFrames();
}

} // anonymous namespace

namespace LibreSCRS::SmartCard::Internal::detail {

// Emit a single [PCSC_TRACE] block for a non-transmit lifecycle event
// (e.g. reconnect). No `apdu=` field — just the prefix + stack frames.
void emitPcscTraceEvent(const char* phase, const std::string& readerName, const void* connAddr)
{
    emitPcscTraceLine(pcscTracePrefix(phase, readerName, connAddr));
    emitPcscStackFrames();
}

// A card's answer is traced as its length and status word only: the data
// field can be a certificate, a personal record or decrypted key material.
void emitPcscTraceResponse(const std::string& readerName, const void* connAddr, std::size_t length,
                           std::uint16_t statusWord)
{
    emitPcscTraceLine(
        std::format("{} rx={} bytes sw={:04X}", pcscTracePrefix("receive", readerName, connAddr), length, statusWord));
}

// Parse wire-format APDU bytes (cmdBytes, cmdLen) into the structured
// pieces emitPcscTrace expects, then emit one trace block. This is the
// single hook point we install on PCSCConnection::transmitRaw(uint8_t*,
// DWORD) so that every actual on-wire APDU is captured — including those
// produced by Secure-Messaging wrappers (PaceChannel) which bypass the
// APDUCommand-typed transmit() overload.
//
// Wire-format cases:
//   - Case 1:  CLA INS P1 P2                (4 bytes, no Lc/data/Le)
//   - Case 2s: CLA INS P1 P2 Le             (5 bytes, Le-only; ISO 7816-4
//                                            disambiguates 5-byte APDUs
//                                            as Case 2)
//   - Case 3s: CLA INS P1 P2 Lc data[Lc]    (5+Lc bytes, no Le)
//   - Case 4s: CLA INS P1 P2 Lc data[Lc] Le (6+Lc bytes, with Le)
//   - Case 2e: CLA INS P1 P2 00 Le Le       (7 bytes, two-byte Le)
//   - Case 3e: CLA INS P1 P2 00 Lc Lc data  (7+Lc bytes, two-byte Lc)
//   - Case 4e: as 3e followed by a two-byte Le (9+Lc bytes)
// Extended reads are common now (READ BINARY is fitted to the card, under
// secure messaging too), so they are decoded in full.
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
    bool extendedLe = false;
    std::uint16_t leValue = 0;
    std::optional<std::uint16_t> extendedLc;

    if (cmdLen == 5) {
        // Case 2s: Le-only. Byte at offset 4 is Le, not Lc. Keep it in
        // header[4] for consistency with the 5-byte hex layout, and also
        // flag it as Le so the helper's tail prints it. The redundancy
        // is intentional: the header layout is a fixed wire-prefix view,
        // and the Le tail is the semantic value.
        hasLe = true;
        leValue = cmdBytes[4];
    } else if (cmdLen > 5 && cmdBytes[4] == 0 && cmdLen >= 7) {
        // A short case-3 APDU never has Lc 0, so byte 4 == 0 with 7+ bytes is extended.
        // Extended: 00 marker, then a two-byte Lc (with data) or a two-byte Le.
        if (cmdLen == 7) {
            hasLe = true;
            extendedLe = true;
            leValue = static_cast<std::uint16_t>((cmdBytes[5] << 8) | cmdBytes[6]);
        } else {
            const std::size_t lc = (static_cast<std::size_t>(cmdBytes[5]) << 8) | cmdBytes[6];
            const std::size_t dataEnd = 7 + lc;
            if (dataEnd <= cmdLen) {
                extendedLc = static_cast<std::uint16_t>(lc);
                data = std::span<const std::uint8_t>(cmdBytes + 7, lc);
                if (cmdLen == dataEnd + 2) {
                    hasLe = true;
                    extendedLe = true;
                    leValue = static_cast<std::uint16_t>((cmdBytes[dataEnd] << 8) | cmdBytes[dataEnd + 1]);
                }
            }
        }
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
                leValue = cmdBytes[dataEnd];
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
                  hasLe, leValue, extendedLe, extendedLc);
}

} // namespace LibreSCRS::SmartCard::Internal::detail

namespace LibreSCRS::SmartCard::Internal {

using namespace detail;

// Test-only ctor: no card I/O, no handle, no card. Used by CardSession
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
// Keeping the definitions out of this TU keeps the seams out of the shipped
// library altogether: libLibreSCRS_SmartCard compiles it, and a seam left
// here would be one LIBRESCRS_PUBLIC_API away from a dynamic export, which
// --gc-sections cannot drop either.

std::expected<std::unique_ptr<PCSCConnection>, TransportError> PCSCConnection::open(const std::string& readerName)
{
    // The constructor is private; std::make_unique cannot reach it.
    std::unique_ptr<PCSCConnection> conn(new PCSCConnection(readerName));
    if (auto connected = conn->connect(); !connected) {
        return std::unexpected(std::move(connected.error()));
    }
    return conn;
}

std::expected<APDUResponse, TransportError> PCSCConnection::transmitRaw(const uint8_t* cmdBytes, DWORD cmdLen)
{
    // Detached test seam: play the card side of a live SM tunnel. Taken ONLY
    // by a detached connection with a responder installed via
    // setDetachedRawResponder; a connection to a card never takes it, and a
    // detached connection with no responder goes on to the body's handle-less
    // wire path exactly as before.
    if (detached() && detachedRawResponder) {
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

    const std::span<const std::uint8_t> command(cmdBytes, cmdLen);
    auto reply = exchangeWire(command);
    if (!reply && reply.error().kind == TransportError::Kind::CardReset) {
        // The card was reset, or its session lost with the card still in the
        // reader. Re-establish the handle without resetting the card, then
        // send the command once more -- unless it carries a PIN: resent, it
        // could spend a try on a card whose verified state the reset cleared,
        // or on another card.
        if (auto reconnected = reconnect(); !reconnected) {
            return std::unexpected(std::move(reconnected.error()));
        }
        // A secure-messaging command (CLA b3-b4 set) is never resent either:
        // the reset ended the card's SM session, so the resend would be
        // answered as an unknown wrapped command at best, and its MAC counter
        // is already spent.
        if (cmdLen >= 2 && (isSensitiveIns(cmdBytes[1]) || (cmdBytes[0] & 0x0C) != 0)) {
            return std::unexpected(std::move(reply.error()));
        }
        reply = exchangeWire(command);
    }
    if (!reply) {
        return std::unexpected(std::move(reply.error()));
    }

    if (reply->size() < 2) {
        return std::unexpected(pcscFailure(SCARD_F_COMM_ERROR, "SCardTransmit: response too short (" +
                                                                   std::to_string(reply->size()) + " bytes)"));
    }
    APDUResponse response;
    response.sw1 = (*reply)[reply->size() - 2];
    response.sw2 = (*reply)[reply->size() - 1];
    reply->resize(reply->size() - 2);
    response.data = std::move(*reply);
    if (pcscTraceEnabled()) {
        emitPcscTraceResponse(readerName(), this, response.data.size() + 2, response.statusWord());
    }
    return response;
}

std::expected<void, TransportError> PCSCConnection::beginTransaction()
{
    // Detached test connection: no card. Treat the transaction as held so
    // test-only holder acquisition through the CardTransaction RAII wrapper
    // works without a live reader -- unless a test armed a failure through the
    // detached seam, the only way to reach a begin failure without hardware.
    if (detached()) {
        if (detachedTransactionRv != SCARD_S_SUCCESS)
            return std::unexpected(pcscFailure(detachedTransactionRv, "SCardBeginTransaction failed"));
        callerHoldsTransaction = true;
        return {};
    }
    if (auto began = beginOnCard(); !began) {
        return began;
    }
    callerHoldsTransaction = true;
    return {};
}

void PCSCConnection::endTransaction() noexcept
{
    callerHoldsTransaction = false;
    // Detached test connection: nothing to release, but a test may be
    // watching for the moment of release, the only point at which the release
    // ORDER is observable; see setDetachedTransactionReleaseObserver. The call
    // is contained because this function is noexcept and the observer is
    // arbitrary test code.
    if (detached()) {
        if (detachedReleaseObserver) {
            try {
                detachedReleaseObserver();
            } catch (...) {
            }
        }
        return;
    }
    endOnCard();
}

std::expected<std::vector<uint8_t>, TransportError> PCSCConnection::getATR() const
{
    // Detached test connection WITH an ATR installed via setDetachedAtr: hand
    // those bytes back. A detached connection with no ATR installed goes on to
    // the body, which fails (throws) as before setDetachedAtr existed --
    // e.g. eidcard::EIdCard::detectCardType() reached via
    // CardPlugin::canHandleConnection() on an un-rigged detached session must
    // keep seeing that failure, not a silent {} that would route it into the
    // AID-probing SELECT fallback and generate APDUs a passive detached rig
    // never expects.
    if (detached() && !detachedAtr.empty()) {
        return detachedAtr;
    }
    return atrFromCard();
}

std::expected<APDUResponse, TransportError> PCSCConnection::transmitRaw(const APDUCommand& cmd)
{
    // SecureBuffer adoption: the serialization may carry PIN/PUK bytes
    // (PIN verbs), so the wire copy is cleansed on every exit path.
    SecureBuffer bytes(cmd.toBytes());
    return transmitRaw(bytes.data(), static_cast<DWORD>(bytes.size()));
}

std::expected<APDUResponse, TransportError> PCSCConnection::transmitRaw(std::span<const std::uint8_t> cmdBytes)
{
    return transmitRaw(cmdBytes.data(), static_cast<DWORD>(cmdBytes.size()));
}

void PCSCConnection::learnReadLengthBeforeSm()
{
    // Only a card that has not settled the question is asked: Declared and
    // Short are answers already.
    const ReadLengthState before = lengthPolicy.state();
    if (before != ReadLengthState::Untested && before != ReadLengthState::Accepted) {
        return;
    }
    // The caller holds the transaction. A failure to carry the command leaves
    // the card reading short; it never reaches the caller.
    const auto [state, declared] = classifyLearnAnswer(exchangeUnfitted(learnReadLengthCommand()), before);
    lengthPolicy.learn(state, declared);
}

std::expected<APDUResponse, TransportError> PCSCConnection::transmit(const APDUCommand& cmd)
{
    if (transmitFilter)
        return transmitFilter(cmd);
    if (!isReadBinary(cmd))
        return exchangeUnfitted(cmd);

    // Never more than the caller asked for, never more than the card accepts.
    const std::size_t allowed = lengthPolicy.allowedLe(0);
    const std::size_t asked = requestedLe(cmd);
    const std::size_t fitted = std::min(asked, allowed);
    APDUCommand sent = cmd;
    if (fitted != asked)
        sent.le = static_cast<std::uint16_t>(fitted);
    if (fitted <= kShortLe)
        return exchangeUnfitted(sent);

    const bool untested = lengthPolicy.state() == ReadLengthState::Untested;
    auto answer = exchangeUnfitted(sent);
    // A transport failure drops to short in every state. A wrong-length answer
    // drops only a card that has not yet shown it takes extended; once it has
    // (or announced it) the same answer means this file, not the encoding.
    const bool wrongLength = answer && answer->sw1 == 0x67;
    if (!answer || wrongLength) {
        if (!answer || untested)
            lengthPolicy.demoteToShort();
        sent.le = kShortLe;
        return exchangeUnfitted(sent);
    }
    if (untested && isReadSuccess(*answer))
        lengthPolicy.markAccepted();
    return answer;
}

std::expected<APDUResponse, TransportError> PCSCConnection::exchangeUnfitted(const APDUCommand& cmd)
{
    // SecureBuffer adoption: the serialization may carry PIN/PUK bytes
    // (PIN verbs), so the wire copy is cleansed on every exit path.
    SecureBuffer cmdBytes(cmd.toBytes());
    auto first = transmitRaw(cmdBytes.data(), static_cast<DWORD>(cmdBytes.size()));
    if (!first)
        return first;
    auto response = std::move(*first);

    // SW1=61: response data available — send GET RESPONSE to retrieve it.
    // This is an ISO 7816-4 mechanism used by both T=0 and T=1 protocols.
    // Loop to handle chained responses (card may send multiple 61xx).
    //
    // Defensive caps: a buggy or hostile card can in principle return 61xx
    // indefinitely, which would grow `accumulated` without bound. 256
    // iterations × 256 bytes = 64 KiB is well above any legitimate APDU
    // response chain (eMRTD DG files cap well below this; EF.CERT payloads
    // similarly). Past either cap the card broke the protocol: a protocol
    // error, never a truncated body under a success status word and never a
    // status word the card did not send.
    constexpr size_t kMaxGetResponseIters = 256;
    constexpr size_t kMaxGetResponseBytes = 65536;
    size_t getRespIters = 0;
    size_t totalBytes = response.data.size();
    while (response.sw1 == 0x61) {
        if (++getRespIters > kMaxGetResponseIters)
            return std::unexpected(pcscFailure(SCARD_F_COMM_ERROR, "GET RESPONSE chain exceeds the iteration cap"));
        auto accumulated = std::move(response.data);
        uint8_t le = response.sw2; // 0x00 = 256 bytes
        uint8_t getResponse[] = {0x00, 0xC0, 0x00, 0x00, le};
        // A chain broken midway is the error, never the part already read.
        auto next = transmitRaw(getResponse, sizeof(getResponse));
        if (!next)
            return next;
        response = std::move(*next);
        totalBytes += response.data.size();
        if (totalBytes > kMaxGetResponseBytes)
            return std::unexpected(pcscFailure(SCARD_F_COMM_ERROR, "GET RESPONSE chain exceeds the size cap"));
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
        auto retried = transmitRaw(retryBytes.data(), static_cast<DWORD>(retryBytes.size()));
        if (!retried)
            return retried;
        response = std::move(*retried);
    }

    return response;
}

} // namespace LibreSCRS::SmartCard::Internal
