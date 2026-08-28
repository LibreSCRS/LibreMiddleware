// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

#include <functional>
#include <memory>
#include <string>
#include <vector>
#include <stdexcept>

#ifdef __APPLE__
#include <PCSC/winscard.h>
#include <PCSC/wintypes.h>
#else
#include <winscard.h>
#endif

#include "apdu.h"
#include <smartcard/i_connection.h>

namespace LibreSCRS::SmartCard {
// The single sanctioned opener of a real PC/SC connection (CardSession::open).
// Friended below so PCSCConnection's reader-name ctor can stay private — that
// is the type-level enforcement of the one-session-per-reader invariant.
class CardSession;
} // namespace LibreSCRS::SmartCard

namespace LibreSCRS::SmartCard::Internal {

class PCSCError : public std::runtime_error
{
public:
    PCSCError(const std::string& msg, LONG code) : std::runtime_error(msg), errorCode(code) {}
    LONG code() const
    {
        return errorCode;
    }

private:
    LONG errorCode;
};

class PCSCConnection : public IConnection
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

    /// @brief Open a real PC/SC connection OUTSIDE the CardSession single-
    ///        session machinery. The ONLY sanctioned callers are the
    ///        diagnostic CLI tools (tools/) and hardware-probe tests (test/);
    ///        production libraries MUST open through CardSession::open so the
    ///        one-session-per-reader invariant holds. ci/scripts/
    ///        check-raw-pcsc-open.sh fails the build if any lib/ source names
    ///        this factory, and the reader-name ctor below is private +
    ///        friended to CardSession so it cannot be reached another way.
    [[nodiscard]] static std::unique_ptr<PCSCConnection> openRawDiagnostic(const std::string& readerName);

    ~PCSCConnection();

    PCSCConnection(const PCSCConnection&) = delete;
    PCSCConnection& operator=(const PCSCConnection&) = delete;

    APDUResponse transmit(const APDUCommand& cmd) override;

    using TransmitFilter = std::function<APDUResponse(const APDUCommand&)>;
    void setTransmitFilter(TransmitFilter filter);
    void clearTransmitFilter();

    // Test-only raw-byte responder for DETACHED connections. The SM layer
    // ships already-wrapped APDUs through transmitRaw(), which deliberately
    // bypasses the TransmitFilter (setTransmitFilter only intercepts the typed
    // transmit()). On a detached connection there is no card handle for those
    // bytes to reach, so — and ONLY when card == 0 AND a responder has been
    // installed — transmitRaw() hands the raw bytes here instead. This lets a
    // test play the card side of a live SM tunnel (e.g. the BAC downgrade-guard
    // oracle). A production connection has card != 0, so the branch is never
    // taken and the wire path stays byte-identical; a detached connection with
    // no responder installed falls through to the (handle-less) SCardTransmit
    // path exactly as before.
    using RawResponder = std::function<APDUResponse(std::span<const std::uint8_t>)>;
    void setDetachedRawResponder(RawResponder responder);

    // Test-only ATR override for DETACHED connections. getATR() calls
    // SCardStatus() directly — a lower-level primitive than transmit(), so it
    // is never touched by the TransmitFilter installed via setTransmitFilter().
    // A detached connection (card == 0) has no handle for SCardStatus() to
    // query, so a caller that identifies the card type from its ATR (e.g.
    // eidcard::EIdCard::detectCardType()) has no other way to be handed a
    // synthetic ATR. Mirrors the transmitRaw seam below (card == 0 &&
    // detachedRawResponder): getATR() only returns this override when
    // card == 0 AND a non-empty ATR was installed here. A production
    // connection's getATR() path is untouched; a detached connection with
    // no ATR installed keeps failing exactly as before this seam existed
    // (SCardStatus(0, ...) throws) instead of silently returning {} --
    // callers like CardPlugin::canHandleConnection() depend on that failure
    // to short-circuit before any APDU reaches an un-rigged detached rig.
    //
    // DEFINED ONLY in the build-tree-only LibreSCRS_SmartCard_TestHelpers
    // archive (lib/LibreSCRS/SmartCard/test_helpers/
    // pcsc_connection_test_helpers.cpp), never in pcsc_connection.cpp, so no
    // shipped LibreSCRS_*.so exports a way to arm the seam -- see the note at
    // the former definition site for why a visibility attribute would not
    // have been enough. Targets that need it link that archive alongside
    // SmartCard_Impl; the member and the getATR() branch below stay in the
    // production class, so the class layout is identical either way.
    void setDetachedAtr(std::vector<uint8_t> atr);

    // Low-level transmit that bypasses the TransmitFilter.
    // Used by SM layer to send already-wrapped APDUs without recursive filtering.
    APDUResponse transmitRaw(const uint8_t* cmdBytes, DWORD cmdLen);
    APDUResponse transmitRaw(const APDUCommand& cmd);

    // IConnection override — forwards to the byte-pointer transmitRaw above.
    APDUResponse transmitRaw(std::span<const std::uint8_t> cmdBytes) override;

    void reconnect(); // prefers T=1, falls back to T=0

    // SCardReconnect with SCARD_RESET_CARD: a cold restart of the card
    // session. Some platforms answer 6A86 to every SELECT once a non-file-
    // system applet was current, and only a reset clears that. This tears
    // down other SCARD_SHARE_SHARED sessions' state, so it is for
    // diagnostic tools that own the bench — production code keeps using
    // reconnect() (SCARD_LEAVE_CARD).
    void reconnectWithReset();
    std::vector<uint8_t> getATR() const;
    const std::string& readerName() const
    {
        return storedReaderName;
    }

    // Acquire / release an exclusive PC/SC transaction on the card.
    // While a transaction is held, other connections' SCardTransmit calls block.
    // endTransaction() never throws; it is safe to call even after reconnect().
    //
    // These primitives are public for backwards compatibility but new call
    // sites SHOULD use the RAII CardTransaction wrapper below — it preserves
    // pairing and feeds the `callerHoldsTransaction` flag consulted by
    // higher-level holders.
    void beginTransaction();
    void endTransaction() noexcept;

    /// @brief True iff at least one live `CardTransaction` (or a balanced
    ///        beginTransaction/endTransaction pair) currently holds an
    ///        exclusive PC/SC transaction on this connection. Higher-level
    ///        owners (e.g. `ActiveChannelHolder`) consult this to confirm
    ///        their cross-process atomicity invariant before issuing the
    ///        first wrapped APDU.
    [[nodiscard]] bool isTransactionHeld() const noexcept
    {
        return callerHoldsTransaction;
    }

    // Abort any pending blocking PC/SC operation (SCardTransmit, etc.) on this
    // connection's context. Thread-safe: can be called from any thread.
    void cancel();

    static std::vector<std::string> listReaders();

private:
    // Real reader-name ctor: opens a live PC/SC handle. Private so the only
    // production opener is CardSession (the single-session keystone); the
    // diagnostic tools/tests reach it via the openRawDiagnostic() factory.
    explicit PCSCConnection(const std::string& readerName);

    TransmitFilter transmitFilter;
    RawResponder detachedRawResponder;
    std::vector<uint8_t> detachedAtr;
    std::string storedReaderName;
    SCARDCONTEXT context = 0;
    SCARDHANDLE card = 0;
    DWORD activeProtocol = 0;
    bool callerHoldsTransaction = false;
    friend class CardTransaction;
    friend class ::LibreSCRS::SmartCard::CardSession;
};

// RAII wrapper: begins a PC/SC transaction on construction, ends it on destruction.
// Prevents APDU interleaving when multiple processes share the same card
// (e.g., LibreCelik + Firefox PKCS#11 both using SCARD_SHARE_SHARED).
//
// Move-only with explicit release() — enables transferring transaction
// ownership into longer-lived holders (e.g. ActiveChannelHolder) while
// preserving full RAII unwind on error paths. After release(), the
// transaction is no longer ended by this object's destructor; the caller
// guarantees some other live owner will end it eventually.
class CardTransaction
{
public:
    explicit CardTransaction(PCSCConnection& c) : conn(&c)
    {
        conn->beginTransaction();
        conn->callerHoldsTransaction = true;
    }
    ~CardTransaction()
    {
        if (conn) {
            conn->callerHoldsTransaction = false;
            conn->endTransaction();
        }
    }

    CardTransaction(const CardTransaction&) = delete;
    CardTransaction& operator=(const CardTransaction&) = delete;

    CardTransaction(CardTransaction&& other) noexcept : conn(other.conn)
    {
        other.conn = nullptr;
    }

    CardTransaction& operator=(CardTransaction&& other) noexcept
    {
        if (this != &other) {
            if (conn) {
                conn->callerHoldsTransaction = false;
                conn->endTransaction();
            }
            conn = other.conn;
            other.conn = nullptr;
        }
        return *this;
    }

    /// @brief Release ownership without ending the transaction. After this
    ///        call, the destructor is a no-op. The transaction remains
    ///        live on the underlying PCSCConnection; the caller assumes
    ///        responsibility for ending it through some other live owner
    ///        (typically a moved-to CardTransaction held by
    ///        ActiveChannelHolder, whose own destructor ends it).
    void release() noexcept
    {
        conn = nullptr;
    }

    /// @brief True while this object still owns the transaction.
    [[nodiscard]] bool owns() const noexcept
    {
        return conn != nullptr;
    }

private:
    PCSCConnection* conn;
};

} // namespace LibreSCRS::SmartCard::Internal
