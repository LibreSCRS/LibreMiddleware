// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "smartcard/card_connection.h is internal to LibreMiddleware"
#endif

#include <smartcard/i_connection.h>

#include <cstdint>
#include <vector>

namespace LibreSCRS::SmartCard {

/// What a card library needs of the card beyond the transmit seam: exclusive
/// use of it, its ATR and a reconnect.
///
/// The PC/SC connection implements it inside libLibreSCRS_SmartCard. Code in
/// another image reaches the connection through this interface only: like
/// IConnection it has an inline destructor and no out-of-line virtual, so
/// every image that uses it carries its own typeinfo, and nothing outside the
/// shared library ever names the connection's own class -- whose typeinfo the
/// library keeps hidden, and which a sanitizer build (-fsanitize=vptr) would
/// otherwise reference from every member call.
class CardConnection : public IConnection
{
public:
    /// Begins an exclusive PC/SC transaction and records it as held. Each
    /// call needs its own endTransaction(): the reader counts them.
    virtual void beginTransaction() = 0;
    /// Ends the transaction, clearing the record first. Never throws.
    virtual void endTransaction() noexcept = 0;
    /// The last of beginTransaction() and endTransaction() was a begin; not
    /// a count.
    [[nodiscard]] virtual bool isTransactionHeld() const noexcept = 0;
    [[nodiscard]] virtual std::vector<std::uint8_t> getATR() const = 0;
    /// Re-establishes the connection without resetting the card.
    virtual void reconnect() = 0;
};

namespace Internal {

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
    explicit CardTransaction(CardConnection& c) : conn(&c)
    {
        conn->beginTransaction();
    }
    ~CardTransaction()
    {
        if (conn) {
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
                conn->endTransaction();
            }
            conn = other.conn;
            other.conn = nullptr;
        }
        return *this;
    }

    /// @brief Release ownership without ending the transaction. After this
    ///        call, the destructor is a no-op. The transaction remains
    ///        live on the underlying connection; the caller assumes
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
    CardConnection* conn;
};

} // namespace Internal

} // namespace LibreSCRS::SmartCard
