// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "smartcard/pcsc_connection.h"
#include <cstring>
#include <iomanip>
#include <iostream>

namespace smartcard {

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
#ifndef NDEBUG
    std::cerr << "[PCSC] Reconnected, protocol=" << (activeProtocol == SCARD_PROTOCOL_T0 ? "T=0" : "T=1") << std::endl;
#endif
}

APDUResponse PCSCConnection::transmitRaw(const uint8_t* cmdBytes, DWORD cmdLen)
{
#ifndef NDEBUG
    // Log sent APDU — mask data for VERIFY (0x20) and CHANGE REFERENCE DATA (0x24) to avoid PIN exposure
    bool isSensitive = cmdLen >= 2 && (cmdBytes[1] == 0x20 || cmdBytes[1] == 0x24);
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

APDUResponse PCSCConnection::transmit(const APDUCommand& cmd)
{
    if (transmitFilter)
        return transmitFilter(cmd);

    auto cmdBytes = cmd.toBytes();
    auto response = transmitRaw(cmdBytes.data(), static_cast<DWORD>(cmdBytes.size()));

    // SW1=61: response data available — send GET RESPONSE to retrieve it.
    // This is an ISO 7816-4 mechanism used by both T=0 and T=1 protocols.
    // Loop to handle chained responses (card may send multiple 61xx).
    while (response.sw1 == 0x61) {
        auto accumulated = std::move(response.data);
        uint8_t le = response.sw2; // 0x00 = 256 bytes
        uint8_t getResponse[] = {0x00, 0xC0, 0x00, 0x00, le};
        response = transmitRaw(getResponse, sizeof(getResponse));
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
