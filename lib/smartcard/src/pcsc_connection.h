// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>
#include <expected>

#ifdef __APPLE__
#include <PCSC/winscard.h>
#include <PCSC/wintypes.h>
#else
#include <winscard.h>
#endif

#if defined(__APPLE__) || defined(LIBRESCRS_SMARTCARD_CTK_FAKE)
#include "ctk_smartcard.h"
#endif

#if defined(LIBRESCRS_SMARTCARD_CTK_FAKE) && defined(LIBRESCRS_BUILDING)
#error "the scripted CryptoTokenKit facade is test-only and must never reach a shipped library"
#endif

#include "apdu.h"
#include <LibreSCRS/Export.h>
#include <smartcard/card_connection.h>
#include <smartcard/read_length_policy.h>
#include <LibreSCRS/SmartCard/TransportError.h>

namespace LibreSCRS::SmartCard {
// The single sanctioned opener of a real PC/SC connection (CardSession::open).
// Friended below so PCSCConnection's reader-name ctor can stay private — that
// is the type-level enforcement of the one-session-per-reader invariant.
class CardSession;
} // namespace LibreSCRS::SmartCard

namespace LibreSCRS::SmartCard::Internal {

// Hidden, every member and its typeinfo. Shipped images reach a connection
// only through CardConnection (card plugins: transmit, transactions, the ATR,
// reconnect) or not at all (the installed test archive, whose detached
// sessions CardSession builds), so no image needs any of it -- in a plain
// build or in a sanitizer build, where -fsanitize=vptr makes every member call
// through this class reference its typeinfo. Probes, tools and tests that
// name the class compile it themselves (LibreSCRS_SmartCard_RawDiagnostic).
class PCSCConnection : public CardConnection
{
public:
    /// Tag type used to construct a "detached" PCSCConnection that performs
    /// no PC/SC calls. Intended exclusively for test-only injection paths
    /// where a CardSession needs to be keyed by a real PCSCConnection address
    /// (matching the plugins' per-session map shape) but no hardware is
    /// available. Any transmit() call on a detached connection returns an
    /// empty APDUResponse. Public because a detached connection opens NO path
    /// to a card, so it is outside the one-session-per-reader invariant.
    struct DetachedTag
    {};
    PCSCConnection(DetachedTag, const std::string& readerName);

    ~PCSCConnection();

    PCSCConnection(const PCSCConnection&) = delete;
    PCSCConnection& operator=(const PCSCConnection&) = delete;

    // Sends the command, fitting a READ BINARY's Le to what the card accepts.
    [[nodiscard]] std::expected<APDUResponse, TransportError> transmit(const APDUCommand& cmd) override;

    [[nodiscard]] ReadLengthPolicy* readLengthPolicy() noexcept override
    {
        return &lengthPolicy;
    }

    // Asks the card what Le it accepts, with one plain command, when the state is
    // Untested or Accepted; otherwise sends nothing. For the caller to use just
    // before secure messaging starts, inside its transaction: connecting sends no
    // command, because a plain one would end a secure-messaging session the card
    // may still hold. A command that cannot be carried leaves the card reading
    // short; nothing is thrown.
    void learnReadLengthBeforeSm();

    // Every setter below that ARMS a seam -- setTransmitFilter,
    // clearTransmitFilter, setDetachedRawResponder, setDetachedAtr -- is
    // DEFINED ONLY in the build-tree-only test copies of this class
    // (LibreSCRS_SmartCard_RawDiagnostic and its siblings, from
    // lib/LibreSCRS/SmartCard/test_helpers/pcsc_connection_test_helpers.cpp),
    // never in pcsc_connection.cpp, so no shipped LibreSCRS_*.so holds a way
    // to arm one. A target that arms a
    // seam links such a copy (the build-tree card_mapper tool does, for its
    // wire-logging filter). The members written here and the branches that
    // read them stay in the production class, so the class layout is
    // identical either way.
    using TransmitFilter = std::function<std::expected<APDUResponse, TransportError>(const APDUCommand&)>;
    void setTransmitFilter(TransmitFilter filter);
    void clearTransmitFilter();

    // Test-only raw-byte responder for DETACHED connections. The SM layer
    // ships already-wrapped APDUs through transmitRaw(), which deliberately
    // bypasses the TransmitFilter (setTransmitFilter only intercepts the typed
    // transmit()). On a detached connection there is no card handle for those
    // bytes to reach, so — and ONLY when detached() AND a responder has been
    // installed — transmitRaw() hands the raw bytes here instead. This lets a
    // test play the card side of a live SM tunnel (e.g. the BAC downgrade-guard
    // oracle). A production connection has a card, so the branch is never
    // taken and the wire path stays byte-identical; a detached connection with
    // no responder installed falls through to the body's handle-less wire
    // path exactly as before.
    using RawResponder = std::function<std::expected<APDUResponse, TransportError>(std::span<const std::uint8_t>)>;
    void setDetachedRawResponder(RawResponder responder);

    // Test-only ATR override for DETACHED connections. getATR() calls
    // SCardStatus() directly — a lower-level primitive than transmit(), so it
    // is never touched by the TransmitFilter installed via setTransmitFilter().
    // A detached connection has no handle for SCardStatus() to
    // query, so a caller that identifies the card type from its ATR (e.g.
    // eidcard::EIdCard::detectCardType()) has no other way to be handed a
    // synthetic ATR. Mirrors the transmitRaw seam below (detached() &&
    // detachedRawResponder): getATR() only returns this override when
    // detached() AND a non-empty ATR was installed here. A production
    // connection's getATR() path is untouched; a detached connection with
    // no ATR installed keeps failing exactly as before this seam existed
    // (SCardStatus(0, ...) fails) instead of silently returning {} --
    // callers like CardPlugin::canHandleConnection() depend on that failure
    // to short-circuit before any APDU reaches an un-rigged detached rig.
    void setDetachedAtr(std::vector<uint8_t> atr);

    // Test-only transaction failure for DETACHED connections. beginTransaction()
    // short-circuits on a detached connection and returns without
    // touching the null handle, so the failing branch it takes on real
    // hardware -- removed card, reset card, reader unavailable, sharing
    // violation -- is unreachable from any test, and a caller whose duty is to
    // CONTAIN that failure has no way to prove that it does. Armed with a
    // non-zero PC/SC status, a detached beginTransaction() returns the
    // TransportError that status classifies to instead of succeeding. A production connection has a card,
    // so the branch is never taken and the transaction path stays identical.
    void setDetachedTransactionFailure(LONG rv);

    // Test-only release observation for DETACHED connections. WHETHER a
    // transaction is held is readable at any time through isTransactionHeld();
    // WHEN it was released is not. An owner that holds one a statement too
    // long -- across its caller's teardown, say -- looks identical afterwards,
    // because the transaction is gone by the time the call returns either way,
    // so an assertion made after the fact certifies nothing about the order.
    // This runs the observer at the moment a detached endTransaction() takes
    // effect, which is where the order can actually be sampled. A production
    // connection has a card and never reaches it.
    void setDetachedTransactionReleaseObserver(std::function<void()> observer);

    // Low-level transmit that bypasses the TransmitFilter.
    // Used by SM layer to send already-wrapped APDUs without recursive filtering.
    [[nodiscard]] std::expected<APDUResponse, TransportError> transmitRaw(const uint8_t* cmdBytes, DWORD cmdLen);
    [[nodiscard]] std::expected<APDUResponse, TransportError> transmitRaw(const APDUCommand& cmd);

    // IConnection override — forwards to the byte-pointer transmitRaw above.
    [[nodiscard]] std::expected<APDUResponse, TransportError>
    transmitRaw(std::span<const std::uint8_t> cmdBytes) override;

    [[nodiscard]] std::expected<void, TransportError> reconnect() override; // prefers T=1, falls back to T=0

    // SCardReconnect with SCARD_RESET_CARD: a cold restart of the card
    // session. Some platforms answer 6A86 to every SELECT once a non-file-
    // system applet was current, and only a reset clears that. This tears
    // down other SCARD_SHARE_SHARED sessions' state, so it is for
    // diagnostic tools that own the bench — production code keeps using
    // reconnect() (SCARD_LEAVE_CARD).
    [[nodiscard]] std::expected<void, TransportError> reconnectWithReset();
    [[nodiscard]] std::expected<std::vector<uint8_t>, TransportError> getATR() const override;
    const std::string& readerName() const
    {
        return storedReaderName;
    }

    // Acquire / release an exclusive PC/SC transaction on the card.
    // While a transaction is held, other connections' SCardTransmit calls block.
    // endTransaction() never fails; it is safe to call even after reconnect().
    //
    // beginTransaction() records the transaction as held once it is taken,
    // endTransaction() clears the record before releasing it. Call sites use
    // the RAII CardTransaction wrapper (smartcard/card_connection.h).
    [[nodiscard]] std::expected<void, TransportError> beginTransaction() override;
    void endTransaction() noexcept override;

    /// @brief True iff at least one live `CardTransaction` (or a balanced
    ///        beginTransaction/endTransaction pair) currently holds an
    ///        exclusive PC/SC transaction on this connection. Higher-level
    ///        owners (e.g. `ActiveChannelHolder`) consult this to confirm
    ///        their cross-process atomicity invariant before issuing the
    ///        first wrapped APDU.
    [[nodiscard]] bool isTransactionHeld() const noexcept override
    {
        return callerHoldsTransaction;
    }

    [[nodiscard]] static std::expected<std::vector<std::string>, TransportError> listReaders();

private:
    // Opens a live PC/SC handle. Private so the only production opener is
    // CardSession (the single-session keystone).
    // Hardware probes and diagnostic tools reach it through
    // openRawDiagnostic(), friended below: that function is declared in
    // raw_diagnostic/pcsc_raw_diagnostic.h and defined only in the
    // build-tree-only LibreSCRS_SmartCard_RawDiagnostic archive, so a library
    // source can neither name it from this header nor link it.
    [[nodiscard]] static std::expected<std::unique_ptr<PCSCConnection>, TransportError>
    open(const std::string& readerName);

    // Names the reader and holds no handle yet; connect() takes it.
    explicit PCSCConnection(const std::string& readerName);

    // The body of the platform (pcsc_connection_pcsc.cpp or
    // pcsc_connection_ctk.cpp) defines these; the shared members in
    // pcsc_connection.cpp, including the detached seams, call them.

    // A DetachedTag connection: no handle, no card.
    LIBRESCRS_INTERNAL bool detached() const noexcept;
    // Takes the handle for storedReaderName.
    LIBRESCRS_INTERNAL std::expected<void, TransportError> connect();
    // One command on the wire; the reply including its status word. No value:
    // the card was reset, or its session lost with the card still in the
    // reader, and the command was not answered (a CardReset error); any other
    // failure is its own error.
    LIBRESCRS_INTERNAL std::expected<std::vector<std::uint8_t>, TransportError>
    exchangeWire(std::span<const std::uint8_t> command);
    // One command as given, with the 61xx / 6Cxx follow-ups, and no Le fitting.
    LIBRESCRS_INTERNAL std::expected<APDUResponse, TransportError> exchangeUnfitted(const APDUCommand& cmd);
    LIBRESCRS_INTERNAL std::expected<void, TransportError> beginOnCard();
    LIBRESCRS_INTERNAL void endOnCard() noexcept;
    LIBRESCRS_INTERNAL std::expected<std::vector<uint8_t>, TransportError> atrFromCard() const;

    TransmitFilter transmitFilter;
    RawResponder detachedRawResponder;
    std::vector<uint8_t> detachedAtr;
    std::string storedReaderName;
#if defined(__APPLE__) || defined(LIBRESCRS_SMARTCARD_CTK_FAKE)
    std::unique_ptr<Ctk::CtkCard> ctk; // the one held exclusive CryptoTokenKit session; null = detached
#else
    SCARDCONTEXT context = 0;
    SCARDHANDLE card = 0;
#endif
    DWORD activeProtocol = 0;
    bool callerHoldsTransaction = false;
    // New members, test-only or not, go at the TAIL. This class is not
    // installed, but it is opted into by include path from several
    // separately-packaged shared objects, and isTransactionHeld() and the whole
    // of CardTransaction are header-inline, so every one of them compiles these
    // offsets in for itself. Appending keeps a new member additive: the class
    // grows, no existing offset moves, and objects built against either
    // revision agree about where the production state lives.
    LONG detachedTransactionRv = SCARD_S_SUCCESS;
    std::function<void()> detachedReleaseObserver;
    ReadLengthPolicy lengthPolicy;
    friend class ::LibreSCRS::SmartCard::CardSession;
    friend std::expected<std::unique_ptr<PCSCConnection>, TransportError>
    openRawDiagnostic(const std::string& readerName);
};

} // namespace LibreSCRS::SmartCard::Internal
