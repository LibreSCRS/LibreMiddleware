// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// CardReaderApollo unit tests.
//
// Approach: drive the production reader through a real PCSCConnection
// constructed via the DetachedTag (no PC/SC handle opened) plus a
// TransmitFilter that intercepts every APDU. This exercises the actual
// readChunkedFile() helper wired up in Wave 3, the SELECT-by-file-id
// semantics specific to Apollo cards, and the 0xFF empty-marker handling.

#include <gtest/gtest.h>

#include "apdu.h"
#include "card_protocol.h"
#include "card_reader_apollo.h"
#include "pcsc_connection.h"

#include <cstdint>
#include <stdexcept>
#include <vector>

using LibreSCRS::SmartCard::Internal::APDUCommand;
using LibreSCRS::SmartCard::Internal::APDUResponse;
using LibreSCRS::SmartCard::Internal::PCSCConnection;

namespace {

// Helper: build a default-OK response (SW=9000) with optional data
APDUResponse ok(std::vector<uint8_t> data = {})
{
    APDUResponse r;
    r.data = std::move(data);
    r.sw1 = 0x90;
    r.sw2 = 0x00;
    return r;
}

APDUResponse err(uint8_t sw1, uint8_t sw2)
{
    APDUResponse r;
    r.sw1 = sw1;
    r.sw2 = sw2;
    return r;
}

// Apollo header layout: 6 bytes total. Marker at offset 4 (0xFF = empty),
// content length is little-endian uint16 at offset 4..5 otherwise.
// We use offset 0..3 for arbitrary bytes (caller copies through includeHeader).
std::vector<uint8_t> apolloHeader(uint16_t contentLen, bool empty = false)
{
    std::vector<uint8_t> hdr = {0xA1, 0xA2, 0xA3, 0xA4, 0x00, 0x00};
    if (empty) {
        hdr[4] = 0xFF;
    } else {
        hdr[4] = static_cast<uint8_t>(contentLen & 0xFF);
        hdr[5] = static_cast<uint8_t>((contentLen >> 8) & 0xFF);
    }
    return hdr;
}

} // namespace

// SELECT + read-header + body bytes for a small file.
TEST(CardReaderApolloTest, ReadFileBodyOnlySmallPayload)
{
    PCSCConnection conn(PCSCConnection::DetachedTag{}, "fake-apollo");

    const std::vector<uint8_t> bodyExpected = {'h', 'e', 'l', 'l', 'o'};
    auto header = apolloHeader(static_cast<uint16_t>(bodyExpected.size()));

    int callIdx = 0;
    conn.setTransmitFilter([&](const APDUCommand& cmd) -> APDUResponse {
        ++callIdx;
        if (callIdx == 1) {
            // First call is SELECT (CLA=0x00, INS=0xA4, P1=0x00)
            EXPECT_EQ(cmd.cla, 0x00);
            EXPECT_EQ(cmd.ins, 0xA4);
            EXPECT_EQ(cmd.p1, 0x00); // selectByFileId
            return ok();
        }
        if (callIdx == 2) {
            // Header read: READ BINARY offset=0, len=6
            EXPECT_EQ(cmd.ins, 0xB0);
            EXPECT_EQ(cmd.p1, 0x00);
            EXPECT_EQ(cmd.p2, 0x00);
            EXPECT_EQ(cmd.le, 6u);
            return ok(header);
        }
        if (callIdx == 3) {
            // Body read: READ BINARY offset=6, len=bodyExpected.size()
            EXPECT_EQ(cmd.ins, 0xB0);
            EXPECT_EQ(cmd.p1, 0x00);
            EXPECT_EQ(cmd.p2, 6u);
            return ok(bodyExpected);
        }
        return ok();
    });

    eidcard::CardReaderApollo reader;
    auto result = reader.readFile(conn, 0x0F, 0x02);
    EXPECT_EQ(result, bodyExpected);
}

TEST(CardReaderApolloTest, ReadFileRawIncludesHeader)
{
    PCSCConnection conn(PCSCConnection::DetachedTag{}, "fake-apollo");

    const std::vector<uint8_t> body = {0xDE, 0xAD, 0xBE, 0xEF};
    auto header = apolloHeader(static_cast<uint16_t>(body.size()));

    int callIdx = 0;
    conn.setTransmitFilter([&](const APDUCommand&) -> APDUResponse {
        ++callIdx;
        if (callIdx == 1)
            return ok();
        if (callIdx == 2)
            return ok(header);
        return ok(body);
    });

    eidcard::CardReaderApollo reader;
    auto result = reader.readFileRaw(conn, 0x0F, 0x08);
    // Raw result = full header (6 bytes) followed by body
    ASSERT_GE(result.size(), header.size());
    EXPECT_EQ(std::vector<uint8_t>(result.begin(), result.begin() + 6), header);
    EXPECT_EQ(std::vector<uint8_t>(result.begin() + 6, result.end()), body);
}

TEST(CardReaderApolloTest, EmptyMarkerReturnsEmptyResult)
{
    PCSCConnection conn(PCSCConnection::DetachedTag{}, "fake-apollo");

    auto header = apolloHeader(0, /*empty=*/true);

    int callIdx = 0;
    conn.setTransmitFilter([&](const APDUCommand&) -> APDUResponse {
        ++callIdx;
        if (callIdx == 1)
            return ok();
        if (callIdx == 2)
            return ok(header);
        // Should never get to a body read
        ADD_FAILURE() << "Empty marker should short-circuit body reads";
        return ok();
    });

    eidcard::CardReaderApollo reader;
    auto result = reader.readFile(conn, 0x0F, 0x99);
    EXPECT_TRUE(result.empty());
}

TEST(CardReaderApolloTest, SelectAccepts61xxStatusWord)
{
    // Apollo cards may return SW=61xx (more data available) after SELECT;
    // the reader treats this as a successful SELECT.
    PCSCConnection conn(PCSCConnection::DetachedTag{}, "fake-apollo");

    const std::vector<uint8_t> body = {0x01};
    auto header = apolloHeader(static_cast<uint16_t>(body.size()));

    int callIdx = 0;
    conn.setTransmitFilter([&](const APDUCommand&) -> APDUResponse {
        ++callIdx;
        if (callIdx == 1) {
            // SELECT returns SW1=0x61 (more data) — should be accepted.
            // Note: PCSCConnection::transmit auto-chains GET RESPONSE; the
            // simulated response here returns immediately so the filter only
            // sees one call.
            return err(0x61, 0x10);
        }
        if (callIdx == 2)
            return ok(header);
        return ok(body);
    });

    eidcard::CardReaderApollo reader;
    EXPECT_NO_THROW({
        auto result = reader.readFile(conn, 0x0F, 0x02);
        EXPECT_EQ(result, body);
    });
}

TEST(CardReaderApolloTest, SelectFailureThrows)
{
    PCSCConnection conn(PCSCConnection::DetachedTag{}, "fake-apollo");
    conn.setTransmitFilter([&](const APDUCommand&) -> APDUResponse { return err(0x6A, 0x82); });

    eidcard::CardReaderApollo reader;
    EXPECT_THROW(reader.readFile(conn, 0x0F, 0x02), std::runtime_error);
}

TEST(CardReaderApolloTest, MultiChunkBodyAssembledInOrder)
{
    // Body large enough to require two READ BINARY chunks (chunk size = 0xFF = 255).
    PCSCConnection conn(PCSCConnection::DetachedTag{}, "fake-apollo");

    std::vector<uint8_t> body(400, 0);
    for (size_t i = 0; i < body.size(); ++i)
        body[i] = static_cast<uint8_t>(i & 0xFF);

    auto header = apolloHeader(static_cast<uint16_t>(body.size()));

    int callIdx = 0;
    conn.setTransmitFilter([&](const APDUCommand& cmd) -> APDUResponse {
        ++callIdx;
        if (callIdx == 1)
            return ok(); // SELECT
        if (callIdx == 2)
            return ok(header); // header
        if (callIdx == 3) {
            // First body chunk: offset=6, len=0xFF
            EXPECT_EQ(cmd.ins, 0xB0);
            return ok({body.begin(), body.begin() + 255});
        }
        if (callIdx == 4) {
            // Second body chunk: offset=6+255=261, len=body.size()-255=145
            EXPECT_EQ(cmd.ins, 0xB0);
            return ok({body.begin() + 255, body.end()});
        }
        return ok();
    });

    eidcard::CardReaderApollo reader;
    auto result = reader.readFile(conn, 0x0F, 0x02);
    EXPECT_EQ(result, body);
}
