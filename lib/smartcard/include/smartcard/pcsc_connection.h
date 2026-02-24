// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright hirashix0@proton.me

#ifndef SMARTCARD_PCSC_CONNECTION_H
#define SMARTCARD_PCSC_CONNECTION_H

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

class PCSCError : public std::runtime_error {
public:
    PCSCError(const std::string& msg, LONG code)
        : std::runtime_error(msg), errorCode(code) {}
    LONG code() const { return errorCode; }
private:
    LONG errorCode;
};

class PCSCConnection {
public:
    explicit PCSCConnection(const std::string& readerName);
    ~PCSCConnection();

    PCSCConnection(const PCSCConnection&) = delete;
    PCSCConnection& operator=(const PCSCConnection&) = delete;

    APDUResponse transmit(const APDUCommand& cmd);
    void reconnect(DWORD preferredProtocols = SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1);
    std::vector<uint8_t> getATR() const;
    DWORD getActiveProtocol() const { return activeProtocol; }

private:
    APDUResponse transmitRaw(const uint8_t* cmdBytes, DWORD cmdLen);

    SCARDCONTEXT context = 0;
    SCARDHANDLE card = 0;
    DWORD activeProtocol = 0;
};

} // namespace smartcard

#endif // SMARTCARD_PCSC_CONNECTION_H
