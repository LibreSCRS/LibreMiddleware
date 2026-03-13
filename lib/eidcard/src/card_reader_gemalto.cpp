// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright hirashix0@proton.me

#include "card_reader_gemalto.h"
#include "card_protocol.h"
#include "smartcard/apdu.h"
#include "smartcard/pcsc_connection.h"
#include <stdexcept>

namespace eidcard {

CardType CardReaderGemalto::selectApplication(smartcard::PCSCConnection& conn)
{
    // Try SERID (citizen ID) first
    auto resp = conn.transmit(smartcard::selectByAID(protocol::AID_SERID));
    if (resp.isSuccess()) {
        return CardType::Gemalto2014;
    }

    // Try SERIF (foreigner ID)
    resp = conn.transmit(smartcard::selectByAID(protocol::AID_SERIF));
    if (resp.isSuccess()) {
        return CardType::ForeignerIF2020;
    }

    // Try SERRP (alternate AID for foreigner eID, same card family as SERIF)
    resp = conn.transmit(smartcard::selectByAID(protocol::AID_SERRP));
    if (resp.isSuccess()) {
        return CardType::ForeignerIF2020;
    }

    return CardType::Unknown;
}

// SELECT file and read its 4-byte header.
// On failure, retries with application re-selection and reconnect.
static smartcard::APDUResponse selectAndReadHeader(smartcard::PCSCConnection& conn, uint8_t fileId1, uint8_t fileId2)
{
    auto selectResp = conn.transmit(smartcard::selectByPath(fileId1, fileId2, 4));
    if (selectResp.isSuccess()) {
        auto headerResp = conn.transmit(smartcard::readBinary(0, 4));
        if (headerResp.isSuccess() && headerResp.data.size() >= 4)
            return headerResp;
    }

    // Retry: re-select application (context may have been lost)
    CardReaderGemalto::selectApplication(conn);
    selectResp = conn.transmit(smartcard::selectByPath(fileId1, fileId2, 4));
    if (selectResp.isSuccess()) {
        auto headerResp = conn.transmit(smartcard::readBinary(0, 4));
        if (headerResp.isSuccess() && headerResp.data.size() >= 4)
            return headerResp;
    }

    // Last resort: reconnect to the card and try once more
    conn.reconnect();
    CardReaderGemalto::selectApplication(conn);
    selectResp = conn.transmit(smartcard::selectByPath(fileId1, fileId2, 4));
    if (!selectResp.isSuccess()) {
        throw std::runtime_error("Gemalto: SELECT file failed, SW=" + std::to_string(selectResp.statusWord()));
    }
    auto headerResp = conn.transmit(smartcard::readBinary(0, 4));
    if (!headerResp.isSuccess() || headerResp.data.size() < 4) {
        throw std::runtime_error("Gemalto: Cannot read file header");
    }
    return headerResp;
}

// READ BINARY with retry: re-select app + file, then reconnect + re-select.
static smartcard::APDUResponse readBinaryWithRetry(smartcard::PCSCConnection& conn, uint16_t offset, uint8_t length,
                                                   uint8_t fileId1, uint8_t fileId2)
{
    auto readResp = conn.transmit(smartcard::readBinary(offset, length));
    if (readResp.isSuccess())
        return readResp;

    // Retry 1: re-select application + file, then read
    CardReaderGemalto::selectApplication(conn);
    conn.transmit(smartcard::selectByPath(fileId1, fileId2, 4));
    readResp = conn.transmit(smartcard::readBinary(offset, length));
    if (readResp.isSuccess())
        return readResp;

    // Retry 2: reconnect + re-select application + file, then read
    conn.reconnect();
    CardReaderGemalto::selectApplication(conn);
    conn.transmit(smartcard::selectByPath(fileId1, fileId2, 4));
    readResp = conn.transmit(smartcard::readBinary(offset, length));
    return readResp;
}

std::vector<uint8_t> CardReaderGemalto::readFile(smartcard::PCSCConnection& conn, uint8_t fileId1, uint8_t fileId2)
{
    auto headerResp = selectAndReadHeader(conn, fileId1, fileId2);

    // File data length is at header bytes 2-3 in LITTLE-ENDIAN format
    uint32_t dataLength = static_cast<uint32_t>(headerResp.data[2]) | (static_cast<uint32_t>(headerResp.data[3]) << 8);

    if (dataLength == 0) {
        return {};
    }

    // Read file data starting after the 4-byte header
    std::vector<uint8_t> fileData;
    fileData.reserve(dataLength);
    uint16_t offset = 4;

    while (fileData.size() < dataLength) {
        uint8_t chunkSize = static_cast<uint8_t>(std::min(static_cast<uint32_t>(protocol::READ_CHUNK_SIZE),
                                                          dataLength - static_cast<uint32_t>(fileData.size())));

        auto readResp = readBinaryWithRetry(conn, offset, chunkSize, fileId1, fileId2);
        if (!readResp.isSuccess()) {
            throw std::runtime_error("Gemalto: READ BINARY failed at offset " + std::to_string(offset));
        }

        if (readResp.data.empty()) {
            break;
        }

        fileData.insert(fileData.end(), readResp.data.begin(), readResp.data.end());
        offset += static_cast<uint16_t>(readResp.data.size());
    }

    return fileData;
}

std::vector<uint8_t> CardReaderGemalto::readFileRaw(smartcard::PCSCConnection& conn, uint8_t fileId1, uint8_t fileId2)
{
    auto headerResp = selectAndReadHeader(conn, fileId1, fileId2);

    // File data length is at header bytes 2-3 in LITTLE-ENDIAN format
    uint32_t dataLength = static_cast<uint32_t>(headerResp.data[2]) | (static_cast<uint32_t>(headerResp.data[3]) << 8);

    // Build result starting with the 4-byte header
    uint32_t totalLength = 4 + dataLength;
    std::vector<uint8_t> fileData;
    fileData.reserve(totalLength);
    fileData.insert(fileData.end(), headerResp.data.begin(), headerResp.data.begin() + 4);

    if (dataLength == 0) {
        return fileData;
    }

    // Read remaining data starting after the header
    uint16_t offset = 4;

    while (fileData.size() < totalLength) {
        uint8_t chunkSize = static_cast<uint8_t>(std::min(static_cast<uint32_t>(protocol::READ_CHUNK_SIZE),
                                                          totalLength - static_cast<uint32_t>(fileData.size())));

        auto readResp = readBinaryWithRetry(conn, offset, chunkSize, fileId1, fileId2);
        if (!readResp.isSuccess()) {
            throw std::runtime_error("Gemalto: READ BINARY failed at offset " + std::to_string(offset));
        }

        if (readResp.data.empty()) {
            break;
        }

        fileData.insert(fileData.end(), readResp.data.begin(), readResp.data.end());
        offset += static_cast<uint16_t>(readResp.data.size());
    }

    return fileData;
}

} // namespace eidcard
