// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "card_reader_gemalto.h"
#include "card_protocol.h"
#include "apdu.h"
#include <smartcard/card_connection.h>
#include <smartcard/chunked_read.h>
#include <smartcard/or_throw.h>
#include <stdexcept>

namespace eidcard {

CardType CardReaderGemalto::selectApplication(LibreSCRS::SmartCard::CardConnection& conn)
{
    // Try SERID (citizen ID) first
    auto resp = LibreSCRS::SmartCard::Internal::orThrow(
        conn.transmit(LibreSCRS::SmartCard::Internal::selectByAID(protocol::AID_SERID)));
    if (resp.isSuccess()) {
        return CardType::Gemalto2014;
    }

    // Try SERIF (foreigner ID)
    resp = LibreSCRS::SmartCard::Internal::orThrow(
        conn.transmit(LibreSCRS::SmartCard::Internal::selectByAID(protocol::AID_SERIF)));
    if (resp.isSuccess()) {
        return CardType::ForeignerIF2020;
    }

    // Try SERRP (alternate AID for foreigner eID, same card family as SERIF)
    resp = LibreSCRS::SmartCard::Internal::orThrow(
        conn.transmit(LibreSCRS::SmartCard::Internal::selectByAID(protocol::AID_SERRP)));
    if (resp.isSuccess()) {
        return CardType::ForeignerIF2020;
    }

    return CardType::Unknown;
}

namespace {

// SELECT file and read its 4-byte header.
// On failure, retries with application re-selection and reconnect.
LibreSCRS::SmartCard::Internal::APDUResponse selectAndReadHeader(LibreSCRS::SmartCard::CardConnection& conn,
                                                                 uint8_t fileId1, uint8_t fileId2)
{
    auto selectResp = LibreSCRS::SmartCard::Internal::orThrow(
        conn.transmit(LibreSCRS::SmartCard::Internal::selectByPath(fileId1, fileId2, 4)));
    if (selectResp.isSuccess()) {
        auto headerResp =
            LibreSCRS::SmartCard::Internal::orThrow(conn.transmit(LibreSCRS::SmartCard::Internal::readBinary(0, 4)));
        if (headerResp.isSuccess() && headerResp.data.size() >= 4)
            return headerResp;
    }

    // Retry: re-select application (context may have been lost)
    CardReaderGemalto::selectApplication(conn);
    selectResp = LibreSCRS::SmartCard::Internal::orThrow(
        conn.transmit(LibreSCRS::SmartCard::Internal::selectByPath(fileId1, fileId2, 4)));
    if (selectResp.isSuccess()) {
        auto headerResp =
            LibreSCRS::SmartCard::Internal::orThrow(conn.transmit(LibreSCRS::SmartCard::Internal::readBinary(0, 4)));
        if (headerResp.isSuccess() && headerResp.data.size() >= 4)
            return headerResp;
    }

    // Last resort: reconnect to the card and try once more
    LibreSCRS::SmartCard::Internal::orThrow(conn.reconnect());
    CardReaderGemalto::selectApplication(conn);
    selectResp = LibreSCRS::SmartCard::Internal::orThrow(
        conn.transmit(LibreSCRS::SmartCard::Internal::selectByPath(fileId1, fileId2, 4)));
    if (!selectResp.isSuccess()) {
        throw std::runtime_error("Gemalto: SELECT file failed, SW=" + std::to_string(selectResp.statusWord()));
    }
    auto headerResp =
        LibreSCRS::SmartCard::Internal::orThrow(conn.transmit(LibreSCRS::SmartCard::Internal::readBinary(0, 4)));
    if (!headerResp.isSuccess() || headerResp.data.size() < 4) {
        throw std::runtime_error("Gemalto: Cannot read file header");
    }
    return headerResp;
}

// READ BINARY with retry: re-select app + file, then reconnect + re-select.
LibreSCRS::SmartCard::Internal::APDUResponse readBinaryWithRetry(LibreSCRS::SmartCard::CardConnection& conn,
                                                                 uint16_t offset, uint8_t length, uint8_t fileId1,
                                                                 uint8_t fileId2)
{
    auto readResp = LibreSCRS::SmartCard::Internal::orThrow(
        conn.transmit(LibreSCRS::SmartCard::Internal::readBinary(offset, length)));
    if (readResp.isSuccess())
        return readResp;

    // Retry 1: re-select application + file, then read
    CardReaderGemalto::selectApplication(conn);
    static_cast<void>(LibreSCRS::SmartCard::Internal::orThrow(
        conn.transmit(LibreSCRS::SmartCard::Internal::selectByPath(fileId1, fileId2, 4))));
    readResp = LibreSCRS::SmartCard::Internal::orThrow(
        conn.transmit(LibreSCRS::SmartCard::Internal::readBinary(offset, length)));
    if (readResp.isSuccess())
        return readResp;

    // Retry 2: reconnect + re-select application + file, then read
    LibreSCRS::SmartCard::Internal::orThrow(conn.reconnect());
    CardReaderGemalto::selectApplication(conn);
    static_cast<void>(LibreSCRS::SmartCard::Internal::orThrow(
        conn.transmit(LibreSCRS::SmartCard::Internal::selectByPath(fileId1, fileId2, 4))));
    readResp = LibreSCRS::SmartCard::Internal::orThrow(
        conn.transmit(LibreSCRS::SmartCard::Internal::readBinary(offset, length)));
    return readResp;
}

// Shared Gemalto file read: 4-byte header, LE u16 content length at offset 2,
// 64 KB sanity cap, per-chunk re-select retry policy.
std::vector<uint8_t> readGemaltoFile(LibreSCRS::SmartCard::CardConnection& conn, uint8_t fileId1, uint8_t fileId2,
                                     bool includeHeader)
{
    auto headerResp = selectAndReadHeader(conn, fileId1, fileId2);

    LibreSCRS::SmartCard::Internal::ChunkedReadOptions opts;
    opts.headerSpec.headerSize = 4;
    opts.headerSpec.lengthOffset = 2;
    opts.headerSpec.lengthBytes = 2;
    opts.maxTotalBytes = 65535;
    opts.includeHeaderInResult = includeHeader;
    opts.chunkSize = protocol::READ_CHUNK_SIZE;
    opts.errorPrefix = "Gemalto";
    opts.headerOverride = std::move(headerResp.data);
    opts.readChunk = [&conn, fileId1, fileId2](uint16_t offset, uint8_t length) {
        return readBinaryWithRetry(conn, offset, length, fileId1, fileId2);
    };

    return LibreSCRS::SmartCard::Internal::readChunkedFile(conn, opts);
}

} // namespace

std::vector<uint8_t> CardReaderGemalto::readFile(LibreSCRS::SmartCard::CardConnection& conn, uint8_t fileId1,
                                                 uint8_t fileId2)
{
    return readGemaltoFile(conn, fileId1, fileId2, /*includeHeader=*/false);
}

std::vector<uint8_t> CardReaderGemalto::readFileRaw(LibreSCRS::SmartCard::CardConnection& conn, uint8_t fileId1,
                                                    uint8_t fileId2)
{
    return readGemaltoFile(conn, fileId1, fileId2, /*includeHeader=*/true);
}

} // namespace eidcard
