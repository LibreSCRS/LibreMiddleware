// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "card_reader_apollo.h"
#include "card_protocol.h"
#include "apdu.h"
#include <pcsc_connection.h>
#include <smartcard/chunked_read.h>
#include <stdexcept>

namespace eidcard {

namespace {

// Shared Apollo file read: 6-byte header, LE u16 content length at offset 4,
// 0xFF marker at offset 4 = empty file, 64 KB sanity cap.
std::vector<uint8_t> readApolloFile(LibreSCRS::SmartCard::Internal::PCSCConnection& conn, uint8_t fileId1,
                                    uint8_t fileId2, bool includeHeader)
{
    // Apollo cards: SELECT by file ID (P1=0x00). Apollo may return
    // 0x61XX (more data available) or 0x9000; both indicate SELECT OK.
    auto selectResp = conn.transmit(LibreSCRS::SmartCard::Internal::selectByFileId(fileId1, fileId2));
    if (selectResp.sw1 != 0x90 && selectResp.sw1 != 0x61) {
        throw std::runtime_error("Apollo: SELECT file failed, SW=" + std::to_string(selectResp.statusWord()));
    }

    LibreSCRS::SmartCard::Internal::ChunkedReadOptions opts;
    opts.headerSpec.headerSize = 6;
    opts.headerSpec.lengthOffset = 4;
    opts.headerSpec.lengthBytes = 2;
    opts.headerSpec.hasEmptyMarker = true;
    opts.headerSpec.emptyMarkerOffset = 4;
    opts.headerSpec.emptyMarkerValue = 0xFF;
    opts.headerSpec.maxContentLength = 64 * 1024; // 64KB reasonable max for eID files
    opts.includeHeaderInResult = includeHeader;
    opts.chunkSize = protocol::READ_CHUNK_SIZE;
    opts.errorPrefix = "Apollo";

    return LibreSCRS::SmartCard::Internal::readChunkedFile(conn, opts);
}

} // namespace

std::vector<uint8_t> CardReaderApollo::readFile(LibreSCRS::SmartCard::Internal::PCSCConnection& conn, uint8_t fileId1,
                                                uint8_t fileId2)
{
    return readApolloFile(conn, fileId1, fileId2, /*includeHeader=*/false);
}

std::vector<uint8_t> CardReaderApollo::readFileRaw(LibreSCRS::SmartCard::Internal::PCSCConnection& conn,
                                                   uint8_t fileId1, uint8_t fileId2)
{
    return readApolloFile(conn, fileId1, fileId2, /*includeHeader=*/true);
}

} // namespace eidcard
