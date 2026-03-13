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
    std::cerr << "[PCSC] Reconnected, protocol=" << (activeProtocol == SCARD_PROTOCOL_T0 ? "T=0" : "T=1") << std::endl;
}

APDUResponse PCSCConnection::transmitRaw(const uint8_t* cmdBytes, DWORD cmdLen)
{
    // Log sent APDU
    std::cerr << "[PCSC] TX (" << cmdLen << " bytes,"
              << " protocol=" << (activeProtocol == SCARD_PROTOCOL_T0 ? "T=0" : "T=1") << "):";
    for (DWORD i = 0; i < cmdLen; i++)
        std::cerr << " " << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(cmdBytes[i]);
    std::cerr << std::dec << std::endl;

    const SCARD_IO_REQUEST* pioSendPci = (activeProtocol == SCARD_PROTOCOL_T0) ? SCARD_PCI_T0 : SCARD_PCI_T1;

    uint8_t recvBuffer[258];
    DWORD recvLength = sizeof(recvBuffer);

    LONG rv = SCardTransmit(card, pioSendPci, cmdBytes, cmdLen, nullptr, recvBuffer, &recvLength);
    if (rv != SCARD_S_SUCCESS) {
        std::cerr << "[PCSC] SCardTransmit FAILED, rv=0x" << std::hex << rv << std::dec << std::endl;
        throw PCSCError("SCardTransmit failed", rv);
    }

    // Log received response
    std::cerr << "[PCSC] RX (" << recvLength << " bytes):";
    for (DWORD i = 0; i < recvLength; i++)
        std::cerr << " " << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(recvBuffer[i]);
    std::cerr << std::dec << std::endl;

    APDUResponse response;
    if (recvLength >= 2) {
        response.sw1 = recvBuffer[recvLength - 2];
        response.sw2 = recvBuffer[recvLength - 1];
        if (recvLength > 2) {
            response.data.assign(recvBuffer, recvBuffer + recvLength - 2);
        }
    }

    std::cerr << "[PCSC] SW=0x" << std::hex << std::setfill('0') << std::setw(4) << response.statusWord() << std::dec
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
            cmdBytes.back() = response.sw2; // replace Le with correct value
            response = transmitRaw(cmdBytes.data(), static_cast<DWORD>(cmdBytes.size()));
        }
    }

    return response;
}

void PCSCConnection::beginTransaction()
{
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
    SCardEndTransaction(card, SCARD_LEAVE_CARD);
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

std::vector<std::string> PCSCConnection::listReaders()
{
    SCARDCONTEXT ctx;
    LONG rv = SCardEstablishContext(SCARD_SCOPE_SYSTEM, nullptr, nullptr, &ctx);
    if (rv != SCARD_S_SUCCESS)
        return {};

    DWORD readersLen = 0;
    rv = SCardListReaders(ctx, nullptr, nullptr, &readersLen);
    if (rv != SCARD_S_SUCCESS) {
        SCardReleaseContext(ctx);
        return {};
    }

    std::vector<char> buffer(readersLen);
    rv = SCardListReaders(ctx, nullptr, buffer.data(), &readersLen);
    SCardReleaseContext(ctx);
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

} // namespace smartcard
