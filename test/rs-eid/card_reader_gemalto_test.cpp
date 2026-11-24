// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// CardReaderGemalto unit tests.
//
// Gemalto cards: 4-byte file header, LE u16 length at offset 2, READ BINARY
// retry policy with re-SELECT. Only the happy-path single-try case is exercised
// here — the retry/reconnect paths require a live PCSCConnection handle and
// belong in hardware integration tests.

#include <gtest/gtest.h>

#include "apdu.h"
#include "card_protocol.h"
#include "card_reader_gemalto.h"
#include "pcsc_connection.h"

#include <algorithm>
#include <cstdint>
#include <stdexcept>
#include <utility>
#include <vector>

using LibreSCRS::SmartCard::Internal::APDUCommand;
using LibreSCRS::SmartCard::Internal::APDUResponse;
using LibreSCRS::SmartCard::Internal::PCSCConnection;

namespace {

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

// Gemalto header: 4 bytes. Bytes 0..1 arbitrary, bytes 2..3 = LE u16 content length.
std::vector<uint8_t> gemaltoHeader(uint16_t contentLen)
{
    return {0xB1, 0xB2, static_cast<uint8_t>(contentLen & 0xFF), static_cast<uint8_t>((contentLen >> 8) & 0xFF)};
}

} // namespace

TEST(CardReaderGemaltoTest, SelectApplicationDetectsSerid)
{
    PCSCConnection conn(PCSCConnection::DetachedTag{}, "fake-gemalto");

    conn.setTransmitFilter([&](const APDUCommand& cmd) -> APDUResponse {
        // SELECT by AID
        EXPECT_EQ(cmd.cla, 0x00);
        EXPECT_EQ(cmd.ins, 0xA4);
        EXPECT_EQ(cmd.p1, 0x04); // SELECT by DF name
        // Accept the SERID AID exchange — should not be called for the
        // others if first match succeeds.
        if (cmd.data == eidcard::protocol::AID_SERID)
            return ok();
        return err(0x6A, 0x82);
    });

    auto detected = eidcard::CardReaderGemalto::selectApplication(conn);
    EXPECT_EQ(detected, eidcard::CardType::Gemalto2014);
}

TEST(CardReaderGemaltoTest, SelectApplicationDetectsSerifAsForeignerIF2020)
{
    PCSCConnection conn(PCSCConnection::DetachedTag{}, "fake-gemalto");

    conn.setTransmitFilter([&](const APDUCommand& cmd) -> APDUResponse {
        if (cmd.data == eidcard::protocol::AID_SERID)
            return err(0x6A, 0x82);
        if (cmd.data == eidcard::protocol::AID_SERIF)
            return ok();
        return err(0x6A, 0x82);
    });

    auto detected = eidcard::CardReaderGemalto::selectApplication(conn);
    EXPECT_EQ(detected, eidcard::CardType::ForeignerIF2020);
}

TEST(CardReaderGemaltoTest, SelectApplicationDetectsSerrpAsForeignerIF2020)
{
    PCSCConnection conn(PCSCConnection::DetachedTag{}, "fake-gemalto");

    conn.setTransmitFilter([&](const APDUCommand& cmd) -> APDUResponse {
        if (cmd.data == eidcard::protocol::AID_SERID)
            return err(0x6A, 0x82);
        if (cmd.data == eidcard::protocol::AID_SERIF)
            return err(0x6A, 0x82);
        if (cmd.data == eidcard::protocol::AID_SERRP)
            return ok();
        return err(0x6A, 0x82);
    });

    auto detected = eidcard::CardReaderGemalto::selectApplication(conn);
    EXPECT_EQ(detected, eidcard::CardType::ForeignerIF2020);
}

TEST(CardReaderGemaltoTest, SelectApplicationReturnsUnknownOnAllFailures)
{
    PCSCConnection conn(PCSCConnection::DetachedTag{}, "fake-gemalto");

    conn.setTransmitFilter([&](const APDUCommand&) -> APDUResponse { return err(0x6A, 0x82); });

    auto detected = eidcard::CardReaderGemalto::selectApplication(conn);
    EXPECT_EQ(detected, eidcard::CardType::Unknown);
}

TEST(CardReaderGemaltoTest, ReadFileBodyOnlyHappyPath)
{
    PCSCConnection conn(PCSCConnection::DetachedTag{}, "fake-gemalto");

    const std::vector<uint8_t> body = {'g', 'e', 'm'};
    auto header = gemaltoHeader(static_cast<uint16_t>(body.size()));

    int callIdx = 0;
    conn.setTransmitFilter([&](const APDUCommand& cmd) -> APDUResponse {
        ++callIdx;
        if (callIdx == 1) {
            // SELECT BY PATH from current DF (P1=0x08)
            EXPECT_EQ(cmd.ins, 0xA4);
            EXPECT_EQ(cmd.p1, 0x08);
            EXPECT_EQ(cmd.le, 4u);
            return ok();
        }
        if (callIdx == 2) {
            // Header read: 4 bytes at offset 0
            EXPECT_EQ(cmd.ins, 0xB0);
            EXPECT_EQ(cmd.p1, 0x00);
            EXPECT_EQ(cmd.p2, 0x00);
            EXPECT_EQ(cmd.le, 4u);
            return ok(header);
        }
        if (callIdx == 3) {
            // Body read: offset=4
            EXPECT_EQ(cmd.ins, 0xB0);
            EXPECT_EQ(cmd.p1, 0x00);
            EXPECT_EQ(cmd.p2, 4u);
            return ok(body);
        }
        return ok();
    });

    eidcard::CardReaderGemalto reader;
    auto result = reader.readFile(conn, 0x0F, 0x02);
    EXPECT_EQ(result, body);
}

TEST(CardReaderGemaltoTest, ReadFileRawIncludesHeaderAndBody)
{
    PCSCConnection conn(PCSCConnection::DetachedTag{}, "fake-gemalto");

    const std::vector<uint8_t> body = {0x10, 0x20, 0x30, 0x40, 0x50};
    auto header = gemaltoHeader(static_cast<uint16_t>(body.size()));

    int callIdx = 0;
    conn.setTransmitFilter([&](const APDUCommand&) -> APDUResponse {
        ++callIdx;
        if (callIdx == 1)
            return ok(); // SELECT
        if (callIdx == 2)
            return ok(header); // header
        return ok(body);       // body
    });

    eidcard::CardReaderGemalto reader;
    auto result = reader.readFileRaw(conn, 0x0F, 0x02);
    ASSERT_EQ(result.size(), header.size() + body.size());
    EXPECT_EQ(std::vector<uint8_t>(result.begin(), result.begin() + 4), header);
    EXPECT_EQ(std::vector<uint8_t>(result.begin() + 4, result.end()), body);
}

TEST(CardReaderGemaltoTest, ReadFileEmptyBodyReturnsHeaderOnlyForRaw)
{
    PCSCConnection conn(PCSCConnection::DetachedTag{}, "fake-gemalto");

    auto header = gemaltoHeader(0); // declares 0 body bytes

    int callIdx = 0;
    conn.setTransmitFilter([&](const APDUCommand&) -> APDUResponse {
        ++callIdx;
        if (callIdx == 1)
            return ok();
        if (callIdx == 2)
            return ok(header);
        // Should not request body
        ADD_FAILURE() << "Empty body should short-circuit READ BINARY";
        return ok();
    });

    eidcard::CardReaderGemalto reader;
    auto bodyOnly = reader.readFile(conn, 0x0F, 0x02);
    EXPECT_TRUE(bodyOnly.empty());
}

namespace {

// Serves READ BINARY out of `file` (header included), at most `perAnswer`
// bytes per answer, and logs the length each READ BINARY asked for.
struct GemaltoChip
{
    std::vector<uint8_t> file;
    size_t perAnswer;
    std::vector<std::pair<size_t, size_t>> asked; // offset, le

    GemaltoChip(size_t bodyLen, size_t perAnswer) : perAnswer(perAnswer)
    {
        file = gemaltoHeader(static_cast<uint16_t>(bodyLen));
        for (size_t i = 0; i < bodyLen; ++i)
            file.push_back(static_cast<uint8_t>((i * 5 + 1) & 0xFF));
    }

    APDUResponse operator()(const APDUCommand& cmd)
    {
        if (cmd.ins != 0xB0)
            return ok();
        const size_t offset = (static_cast<size_t>(cmd.p1) << 8) | cmd.p2;
        asked.emplace_back(offset, cmd.le);
        if (offset >= file.size())
            return ok();
        const size_t n = std::min({static_cast<size_t>(cmd.le), perAnswer, file.size() - offset});
        return ok({file.begin() + static_cast<std::ptrdiff_t>(offset),
                   file.begin() + static_cast<std::ptrdiff_t>(offset + n)});
    }
};

} // namespace

TEST(CardReaderGemaltoTest, BodyIsAskedForWholeThroughTheRetryHook)
{
    PCSCConnection conn(PCSCConnection::DetachedTag{}, "fake-gemalto");
    GemaltoChip chip(2048, 958);
    conn.setTransmitFilter([&](const APDUCommand& cmd) { return chip(cmd); });

    eidcard::CardReaderGemalto reader;
    const auto result = reader.readFile(conn, 0x0F, 0x02);

    EXPECT_EQ(result, std::vector<uint8_t>(chip.file.begin() + 4, chip.file.end()));
    ASSERT_EQ(chip.asked.size(), 4u);                               // header, 958, 958, 132
    EXPECT_EQ(chip.asked[1], (std::pair<size_t, size_t>{4, 2048})); // 16-bit length reaches the card
    EXPECT_EQ(chip.asked[2], (std::pair<size_t, size_t>{4 + 958, 2048 - 958}));
}

TEST(CardReaderGemaltoTest, NoReadStartsAtTheEndOfTheFile)
{
    PCSCConnection conn(PCSCConnection::DetachedTag{}, "fake-gemalto");
    GemaltoChip chip(1916, 958);
    conn.setTransmitFilter([&](const APDUCommand& cmd) { return chip(cmd); });

    eidcard::CardReaderGemalto reader;
    const auto result = reader.readFile(conn, 0x0F, 0x02);

    EXPECT_EQ(result.size(), 1916u);
    for (const auto& [offset, le] : chip.asked)
        EXPECT_LT(offset, chip.file.size());
}
