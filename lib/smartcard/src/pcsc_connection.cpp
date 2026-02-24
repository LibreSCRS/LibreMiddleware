// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright hirashix0@proton.me

#include "smartcard/pcsc_connection.h"
#include <cstring>
#include <iomanip>
#include <iostream>

namespace smartcard {

PCSCConnection::PCSCConnection(const std::string& readerName)
{
    LONG rv = SCardEstablishContext(SCARD_SCOPE_SYSTEM, nullptr, nullptr, &context);
    if (rv != SCARD_S_SUCCESS) {
        throw PCSCError("SCardEstablishContext failed", rv);
    }

    rv = SCardConnect(context,
                      readerName.c_str(),
                      SCARD_SHARE_SHARED,
                      SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1,
                      &card,
                      &activeProtocol);
    if (rv != SCARD_S_SUCCESS) {
        SCardReleaseContext(context);
        throw PCSCError("SCardConnect failed on reader: " + readerName, rv);
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

void PCSCConnection::reconnect(DWORD preferredProtocols)
{
    LONG rv = SCardReconnect(card,
                             SCARD_SHARE_SHARED,
                             preferredProtocols,
                             SCARD_RESET_CARD,
                             &activeProtocol);
    if (rv != SCARD_S_SUCCESS) {
        throw PCSCError("SCardReconnect failed", rv);
    }
    std::cerr << "[PCSC] Reconnected, protocol="
              << (activeProtocol == SCARD_PROTOCOL_T0 ? "T=0" : "T=1") << std::endl;
}

APDUResponse PCSCConnection::transmitRaw(const uint8_t* cmdBytes, DWORD cmdLen)
{
    // Log sent APDU
    std::cerr << "[PCSC] TX (" << cmdLen << " bytes,"
              << " protocol=" << (activeProtocol == SCARD_PROTOCOL_T0 ? "T=0" : "T=1") << "):";
    for (DWORD i = 0; i < cmdLen; i++)
        std::cerr << " " << std::hex << std::setfill('0') << std::setw(2)
                  << static_cast<int>(cmdBytes[i]);
    std::cerr << std::dec << std::endl;

    const SCARD_IO_REQUEST* pioSendPci =
        (activeProtocol == SCARD_PROTOCOL_T0) ? SCARD_PCI_T0 : SCARD_PCI_T1;

    uint8_t recvBuffer[258];
    DWORD recvLength = sizeof(recvBuffer);

    LONG rv = SCardTransmit(card,
                            pioSendPci,
                            cmdBytes,
                            cmdLen,
                            nullptr,
                            recvBuffer,
                            &recvLength);
    if (rv != SCARD_S_SUCCESS) {
        std::cerr << "[PCSC] SCardTransmit FAILED, rv=0x" << std::hex << rv << std::dec << std::endl;
        throw PCSCError("SCardTransmit failed", rv);
    }

    // Log received response
    std::cerr << "[PCSC] RX (" << recvLength << " bytes):";
    for (DWORD i = 0; i < recvLength; i++)
        std::cerr << " " << std::hex << std::setfill('0') << std::setw(2)
                  << static_cast<int>(recvBuffer[i]);
    std::cerr << std::dec << std::endl;

    APDUResponse response;
    if (recvLength >= 2) {
        response.sw1 = recvBuffer[recvLength - 2];
        response.sw2 = recvBuffer[recvLength - 1];
        if (recvLength > 2) {
            response.data.assign(recvBuffer, recvBuffer + recvLength - 2);
        }
    }

    std::cerr << "[PCSC] SW=0x" << std::hex << std::setfill('0') << std::setw(4)
              << response.statusWord() << std::dec
              << ", data=" << response.data.size() << " bytes" << std::endl;

    return response;
}

APDUResponse PCSCConnection::transmit(const APDUCommand& cmd)
{
    auto cmdBytes = cmd.toBytes();
    auto response = transmitRaw(cmdBytes.data(), static_cast<DWORD>(cmdBytes.size()));

    // T=0 protocol handling
    if (activeProtocol == SCARD_PROTOCOL_T0) {
        // SW1=61: response data available — send GET RESPONSE to retrieve it
        if (response.sw1 == 0x61) {
            uint8_t getResponse[] = {0x00, 0xC0, 0x00, 0x00, response.sw2};
            response = transmitRaw(getResponse, sizeof(getResponse));
        }
        // SW1=6C: wrong Le — resend command with corrected Le
        else if (response.sw1 == 0x6C) {
            cmdBytes.back() = response.sw2;  // replace Le with correct value
            response = transmitRaw(cmdBytes.data(), static_cast<DWORD>(cmdBytes.size()));
        }
    }

    return response;
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

} // namespace smartcard
