// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "card_reader_apollo.h"
#include "card_protocol.h"
#include "smartcard/apdu.h"
#include "smartcard/pcsc_connection.h"
#include <stdexcept>

namespace eidcard {

std::vector<uint8_t> CardReaderApollo::readFile(smartcard::PCSCConnection& conn, uint8_t fileId1, uint8_t fileId2)
{
    // Apollo cards: SELECT by file ID (P1=0x00)
    auto selectResp = conn.transmit(smartcard::selectByFileId(fileId1, fileId2));
    // Apollo may return 0x61XX (more data available) or 0x9000
    if (selectResp.sw1 != 0x90 && selectResp.sw1 != 0x61) {
        throw std::runtime_error("Apollo: SELECT file failed, SW=" + std::to_string(selectResp.statusWord()));
    }

    // Read 6-byte header to get total file length
    auto headerResp = conn.transmit(smartcard::readBinary(0, 6));
    if (!headerResp.isSuccess() || headerResp.data.size() < 6) {
        throw std::runtime_error("Apollo: Cannot read file header");
    }

    // Check for empty file marker (0xFF at offset 4)
    if (headerResp.data[4] == 0xFF) {
        return {};
    }

    // File data length from header bytes 4-5 in LITTLE-ENDIAN format
    uint32_t dataLength = static_cast<uint32_t>(headerResp.data[4]) | (static_cast<uint32_t>(headerResp.data[5]) << 8);

    constexpr uint32_t maxFileSize = 64 * 1024; // 64KB reasonable max for eID files
    if (dataLength > maxFileSize)
        throw std::runtime_error("Apollo: file size exceeds maximum (" + std::to_string(dataLength) + " bytes)");

    if (dataLength == 0) {
        return {};
    }

    // Read file data starting after the 6-byte header
    std::vector<uint8_t> fileData;
    fileData.reserve(dataLength);
    uint16_t offset = 6;

    while (fileData.size() < dataLength) {
        uint8_t chunkSize = static_cast<uint8_t>(std::min(static_cast<uint32_t>(protocol::READ_CHUNK_SIZE),
                                                          dataLength - static_cast<uint32_t>(fileData.size())));

        auto readResp = conn.transmit(smartcard::readBinary(offset, chunkSize));
        if (!readResp.isSuccess()) {
            throw std::runtime_error("Apollo: READ BINARY failed at offset " + std::to_string(offset));
        }

        fileData.insert(fileData.end(), readResp.data.begin(), readResp.data.end());
        offset += static_cast<uint16_t>(readResp.data.size());

        if (readResp.data.empty()) {
            break;
        }
    }

    return fileData;
}

std::vector<uint8_t> CardReaderApollo::readFileRaw(smartcard::PCSCConnection& conn, uint8_t fileId1, uint8_t fileId2)
{
    // Apollo cards: SELECT by file ID (P1=0x00)
    auto selectResp = conn.transmit(smartcard::selectByFileId(fileId1, fileId2));
    if (selectResp.sw1 != 0x90 && selectResp.sw1 != 0x61) {
        throw std::runtime_error("Apollo: SELECT file failed, SW=" + std::to_string(selectResp.statusWord()));
    }

    // Read 6-byte header
    auto headerResp = conn.transmit(smartcard::readBinary(0, 6));
    if (!headerResp.isSuccess() || headerResp.data.size() < 6) {
        throw std::runtime_error("Apollo: Cannot read file header");
    }

    if (headerResp.data[4] == 0xFF) {
        return {};
    }

    uint32_t dataLength = static_cast<uint32_t>(headerResp.data[4]) | (static_cast<uint32_t>(headerResp.data[5]) << 8);

    constexpr uint32_t maxFileSize = 64 * 1024;
    if (dataLength > maxFileSize)
        throw std::runtime_error("Apollo: file size exceeds maximum (" + std::to_string(dataLength) + " bytes)");

    // Build result starting with the 6-byte header
    uint32_t totalLength = 6 + dataLength;
    std::vector<uint8_t> fileData;
    fileData.reserve(totalLength);
    fileData.insert(fileData.end(), headerResp.data.begin(), headerResp.data.begin() + 6);

    if (dataLength == 0) {
        return fileData;
    }

    uint16_t offset = 6;

    while (fileData.size() < totalLength) {
        uint8_t chunkSize = static_cast<uint8_t>(std::min(static_cast<uint32_t>(protocol::READ_CHUNK_SIZE),
                                                          totalLength - static_cast<uint32_t>(fileData.size())));

        auto readResp = conn.transmit(smartcard::readBinary(offset, chunkSize));
        if (!readResp.isSuccess()) {
            throw std::runtime_error("Apollo: READ BINARY failed at offset " + std::to_string(offset));
        }

        fileData.insert(fileData.end(), readResp.data.begin(), readResp.data.end());
        offset += static_cast<uint16_t>(readResp.data.size());

        if (readResp.data.empty()) {
            break;
        }
    }

    return fileData;
}

} // namespace eidcard
