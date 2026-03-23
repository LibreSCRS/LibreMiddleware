// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright hirashix0@proton.me

#ifndef SMARTCARD_PCSC_CONNECTION_H
#define SMARTCARD_PCSC_CONNECTION_H

#include <functional>
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

namespace smartcard {

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

class PCSCConnection
{
public:
    explicit PCSCConnection(const std::string& readerName);
    ~PCSCConnection();

    PCSCConnection(const PCSCConnection&) = delete;
    PCSCConnection& operator=(const PCSCConnection&) = delete;

    APDUResponse transmit(const APDUCommand& cmd);

    using TransmitFilter = std::function<APDUResponse(const APDUCommand&)>;
    void setTransmitFilter(TransmitFilter filter);
    void clearTransmitFilter();

    // Low-level transmit that bypasses the TransmitFilter.
    // Used by SM layer to send already-wrapped APDUs without recursive filtering.
    APDUResponse transmitRaw(const uint8_t* cmdBytes, DWORD cmdLen);
    APDUResponse transmitRaw(const APDUCommand& cmd);

    void reconnect(); // prefers T=1, falls back to T=0
    std::vector<uint8_t> getATR() const;
    const std::string& readerName() const
    {
        return storedReaderName;
    }

    // Acquire / release an exclusive PC/SC transaction on the card.
    // While a transaction is held, other connections' SCardTransmit calls block.
    // endTransaction() never throws; it is safe to call even after reconnect().
    void beginTransaction();
    void endTransaction() noexcept;

    static std::vector<std::string> listReaders();

private:
    TransmitFilter transmitFilter;
    std::string storedReaderName;
    SCARDCONTEXT context = 0;
    SCARDHANDLE card = 0;
    DWORD activeProtocol = 0;
};

// RAII wrapper: begins a PC/SC transaction on construction, ends it on destruction.
// Prevents APDU interleaving when multiple processes share the same card
// (e.g., LibreCelik + Firefox PKCS#11 both using SCARD_SHARE_SHARED).
class CardTransaction
{
public:
    explicit CardTransaction(PCSCConnection& conn) : conn(conn)
    {
        conn.beginTransaction();
    }
    ~CardTransaction()
    {
        conn.endTransaction();
    }

    CardTransaction(const CardTransaction&) = delete;
    CardTransaction& operator=(const CardTransaction&) = delete;

private:
    PCSCConnection& conn;
};

} // namespace smartcard

#endif // SMARTCARD_PCSC_CONNECTION_H
