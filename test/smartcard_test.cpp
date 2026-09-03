// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <gtest/gtest.h>
#include <apdu.h>
#include <array>
#include <tlv.h>
#include <ber.h>
#include <smartcard/chunked_read.h>

#include "fake_pcsc_connection.h"

#include <algorithm>
#include <cstddef>
#include <fstream>
#include <iterator>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

using namespace LibreSCRS::SmartCard::Internal;

// --- APDU tests ---

TEST(APDUTest, VerifyPINCommand)
{
    std::array<uint8_t, 4> pin = {0x31, 0x32, 0x33, 0x34};
    auto cmd = LibreSCRS::SmartCard::Internal::verifyPIN(0x01, pin);
    auto bytes = cmd.toBytes();
    // CLA=0x00, INS=0x20, P1=0x00, P2=0x01, Lc=4, data=31323334, no Le
    EXPECT_EQ(bytes[0], 0x00);
    EXPECT_EQ(bytes[1], 0x20);
    EXPECT_EQ(bytes[2], 0x00);
    EXPECT_EQ(bytes[3], 0x01);
    EXPECT_EQ(bytes[4], 0x04); // Lc
    EXPECT_EQ(bytes[5], 0x31);
    EXPECT_EQ(bytes[6], 0x32);
    EXPECT_EQ(bytes[7], 0x33);
    EXPECT_EQ(bytes[8], 0x34);
    EXPECT_EQ(bytes.size(), 9u); // 4 header + 1 Lc + 4 data, no Le
}

TEST(APDUTest, VerifyPINStatusCommand)
{
    auto cmd = LibreSCRS::SmartCard::Internal::verifyPINStatus(0x01);
    auto bytes = cmd.toBytes();
    // 4 header bytes + Le=0x00 (Le required for SM — Case 1 triggers 6988 on some cards)
    EXPECT_EQ(bytes.size(), 5u);
    EXPECT_EQ(bytes[0], 0x00);
    EXPECT_EQ(bytes[1], 0x20);
    EXPECT_EQ(bytes[2], 0x00);
    EXPECT_EQ(bytes[3], 0x01);
    EXPECT_EQ(bytes[4], 0x00);
}

TEST(APDUTest, ChangeReferenceDataCommand)
{
    std::array<uint8_t, 4> oldPin = {0x31, 0x32, 0x33, 0x34};
    std::array<uint8_t, 4> newPin = {0x35, 0x36, 0x37, 0x38};
    auto cmd = LibreSCRS::SmartCard::Internal::changeReferenceData(0x01, oldPin, newPin);
    auto bytes = cmd.toBytes();
    EXPECT_EQ(bytes[0], 0x00);
    EXPECT_EQ(bytes[1], 0x24); // INS
    EXPECT_EQ(bytes[2], 0x00);
    EXPECT_EQ(bytes[3], 0x01);
    EXPECT_EQ(bytes[4], 0x08); // Lc = 4+4
    EXPECT_EQ(bytes[5], 0x31);
    EXPECT_EQ(bytes[9], 0x35);
    EXPECT_EQ(bytes.size(), 13u); // 4 header + 1 Lc + 8 data, no Le
}

TEST(APDUTest, ChangeReferenceDataCommandDefaultP1IsByteIdentical)
{
    // Regression: extending changeReferenceData with a trailing defaulted P1
    // must not change a single byte of the pre-existing (no-P1-arg) call.
    std::array<uint8_t, 4> oldPin = {0x31, 0x32, 0x33, 0x34};
    std::array<uint8_t, 4> newPin = {0x35, 0x36, 0x37, 0x38};
    auto cmdDefault = LibreSCRS::SmartCard::Internal::changeReferenceData(0x01, oldPin, newPin);
    auto cmdExplicitZero = LibreSCRS::SmartCard::Internal::changeReferenceData(0x01, oldPin, newPin, 0x00);
    EXPECT_EQ(cmdDefault.toBytes(), cmdExplicitZero.toBytes());
    EXPECT_EQ(cmdDefault.toBytes()[2], 0x00); // P1
}

TEST(APDUTest, ChangeReferenceDataCommandExplicitP1)
{
    // Transport activation passes a non-zero P1; everything else is unchanged.
    std::array<uint8_t, 4> oldPin = {0x31, 0x32, 0x33, 0x34};
    std::array<uint8_t, 4> newPin = {0x35, 0x36, 0x37, 0x38};
    auto cmd = LibreSCRS::SmartCard::Internal::changeReferenceData(0x01, oldPin, newPin, 0x02);
    auto bytes = cmd.toBytes();
    EXPECT_EQ(bytes[0], 0x00);
    EXPECT_EQ(bytes[1], 0x24); // INS
    EXPECT_EQ(bytes[2], 0x02); // P1 (caller-supplied)
    EXPECT_EQ(bytes[3], 0x01); // P2 = pinRef
    EXPECT_EQ(bytes[4], 0x08); // Lc = 4+4
    EXPECT_EQ(bytes[5], 0x31);
    EXPECT_EQ(bytes[9], 0x35);
    EXPECT_EQ(bytes.size(), 13u);
}

TEST(APDUTest, ResetRetryCounterCommandWithNewPin)
{
    std::array<uint8_t, 4> puk = {0x39, 0x38, 0x37, 0x36};
    std::array<uint8_t, 4> newPin = {0x31, 0x32, 0x33, 0x34};
    auto cmd = LibreSCRS::SmartCard::Internal::resetRetryCounter(0x03, 0x05, puk, newPin);
    auto bytes = cmd.toBytes();
    EXPECT_EQ(bytes[0], 0x00);
    EXPECT_EQ(bytes[1], 0x2C);    // INS = RESET RETRY COUNTER
    EXPECT_EQ(bytes[2], 0x03);    // P1 (caller-supplied)
    EXPECT_EQ(bytes[3], 0x05);    // P2 = pinRef
    EXPECT_EQ(bytes[4], 0x08);    // Lc = 4 (puk) + 4 (newPin)
    EXPECT_EQ(bytes[5], 0x39);    // puk[0]
    EXPECT_EQ(bytes[9], 0x31);    // newPin[0]
    EXPECT_EQ(bytes.size(), 13u); // 4 header + 1 Lc + 8 data, no Le
}

TEST(APDUTest, ResetRetryCounterCommandResetOnly)
{
    // newPin omitted entirely: data field is PUK only.
    std::array<uint8_t, 4> puk = {0x39, 0x38, 0x37, 0x36};
    auto cmd = LibreSCRS::SmartCard::Internal::resetRetryCounter(0x01, 0x07, puk);
    auto bytes = cmd.toBytes();
    EXPECT_EQ(bytes[0], 0x00);
    EXPECT_EQ(bytes[1], 0x2C);
    EXPECT_EQ(bytes[2], 0x01); // P1
    EXPECT_EQ(bytes[3], 0x07); // P2 = pinRef
    EXPECT_EQ(bytes[4], 0x04); // Lc = 4 (puk only)
    EXPECT_EQ(bytes[5], 0x39);
    EXPECT_EQ(bytes.size(), 9u); // 4 header + 1 Lc + 4 data, no Le
}

TEST(APDUTest, ActivateCommandWithObjectRef)
{
    std::array<uint8_t, 2> objRef = {0xAA, 0xBB};
    auto cmd = LibreSCRS::SmartCard::Internal::activate(0x04, 0x06, objRef);
    auto bytes = cmd.toBytes();
    EXPECT_EQ(bytes[0], 0x00);
    EXPECT_EQ(bytes[1], 0x44); // INS = ACTIVATE
    EXPECT_EQ(bytes[2], 0x04); // P1 (caller-supplied)
    EXPECT_EQ(bytes[3], 0x06); // P2 (caller-supplied)
    EXPECT_EQ(bytes[4], 0x02); // Lc
    EXPECT_EQ(bytes[5], 0xAA);
    EXPECT_EQ(bytes[6], 0xBB);
    EXPECT_EQ(bytes.size(), 7u); // 4 header + 1 Lc + 2 data, no Le
}

TEST(APDUTest, ActivateCommandNoObjectRef)
{
    // No ref data: bare header, no Lc, no Le (Case 1).
    auto cmd = LibreSCRS::SmartCard::Internal::activate(0x04, 0x06);
    auto bytes = cmd.toBytes();
    EXPECT_EQ(bytes.size(), 4u);
    EXPECT_EQ(bytes[0], 0x00);
    EXPECT_EQ(bytes[1], 0x44);
    EXPECT_EQ(bytes[2], 0x04);
    EXPECT_EQ(bytes[3], 0x06);
}

// --- TLV tests ---

TEST(TLVTest, ParseEmptyData)
{
    auto fields = parseTLV(nullptr, 0);
    EXPECT_TRUE(fields.empty());
}

TEST(TLVTest, ParseSingleField)
{
    // Tag 0x0001 (LE: 01 00), Length 0x0003 (LE: 03 00), Value "abc"
    const uint8_t data[] = {0x01, 0x00, 0x03, 0x00, 'a', 'b', 'c'};
    auto fields = parseTLV(data, sizeof(data));
    ASSERT_EQ(fields.size(), 1u);
    EXPECT_EQ(fields[0].tag, 0x0001);
    EXPECT_EQ(fields[0].asString(), "abc");
}

TEST(TLVTest, ParseMultipleFields)
{
    // Field 1: tag=0x0001, len=2, value="hi"
    // Field 2: tag=0x0002, len=3, value="bye"
    const uint8_t data[] = {0x01, 0x00, 0x02, 0x00, 'h', 'i', 0x02, 0x00, 0x03, 0x00, 'b', 'y', 'e'};
    auto fields = parseTLV(data, sizeof(data));
    ASSERT_EQ(fields.size(), 2u);
    EXPECT_EQ(fields[0].tag, 0x0001);
    EXPECT_EQ(fields[0].asString(), "hi");
    EXPECT_EQ(fields[1].tag, 0x0002);
    EXPECT_EQ(fields[1].asString(), "bye");
}

TEST(TLVTest, FindStringByTag)
{
    const uint8_t data[] = {0x01, 0x00, 0x02, 0x00, 'h', 'i', 0x02, 0x00, 0x03, 0x00, 'b', 'y', 'e'};
    auto fields = parseTLV(data, sizeof(data));
    EXPECT_EQ(findString(fields, 0x0002), "bye");
    EXPECT_EQ(findString(fields, 0x9999), "");
}

// --- BER-TLV tests ---

TEST(BERTest, ParseEmptyData)
{
    auto root = parseBER(nullptr, 0);
    EXPECT_TRUE(root.children.empty());
}

TEST(BERTest, ParsePrimitiveField)
{
    // Tag 0x81, Length 3, Value "abc"
    const uint8_t data[] = {0x81, 0x03, 'a', 'b', 'c'};
    auto root = parseBER(data, sizeof(data));
    ASSERT_EQ(root.children.size(), 1u);
    EXPECT_EQ(root.children[0].tag, 0x81u);
    EXPECT_EQ(root.children[0].asString(), "abc");
    EXPECT_FALSE(root.children[0].constructed);
}

TEST(BERTest, MergeBERTrees)
{
    const uint8_t data1[] = {0x81, 0x01, 'a'};
    const uint8_t data2[] = {0x82, 0x01, 'b'};
    auto tree1 = parseBER(data1, sizeof(data1));
    auto tree2 = parseBER(data2, sizeof(data2));
    mergeBER(tree1, tree2);
    ASSERT_EQ(tree1.children.size(), 2u);
    EXPECT_EQ(tree1.children[0].tag, 0x81u);
    EXPECT_EQ(tree1.children[1].tag, 0x82u);
}

// --- Chunked file reader: the cap on a card-chosen allocation ---
//
// readChunkedFile allocates whatever the file header declares, and the header
// is card-controlled bytes that arrive before anything has authenticated the
// card. The hostile header below is read from fuzz/corpus/, so the fuzz seed
// and this regression case cannot drift apart.
//
// Every case here asserts the number of recorded commands as well as the
// refusal. Without that second assertion the suite would pass for an
// implementation that reserves four gigabytes first and complains afterwards,
// which is the defect being closed.

namespace {

std::vector<uint8_t> readChunkedReadCorpus(const std::string& leaf)
{
    const std::string path = std::string(LIBRESCRS_FUZZ_CORPUS_DIR) + "/chunked_read/" + leaf;
    std::ifstream in(path, std::ios::binary);
    EXPECT_TRUE(in.good()) << "corpus file missing: " << path;
    std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    EXPECT_FALSE(bytes.empty()) << "corpus file empty: " << path;
    return bytes;
}

/// Serves READ BINARY out of a flat card image; past the end it answers with a
/// successful empty read, the way the loop expects EOF to arrive.
LibreSCRS::SecureChannel::TestSupport::FakePCSCConnection::ResponseFn imageResponder(std::vector<uint8_t> image)
{
    return [image = std::move(image)](const APDUCommand& cmd) {
        APDUResponse resp;
        resp.sw1 = 0x90;
        resp.sw2 = 0x00;
        const size_t offset = (static_cast<size_t>(cmd.p1) << 8) | cmd.p2;
        if (offset >= image.size()) {
            return resp;
        }
        const size_t want = cmd.le == 0 ? 256u : cmd.le;
        const size_t have = std::min(want, image.size() - offset);
        resp.data.assign(image.begin() + static_cast<ptrdiff_t>(offset),
                         image.begin() + static_cast<ptrdiff_t>(offset + have));
        return resp;
    };
}

/// The custom parser shape: eight-byte header, little-endian u32 body length
/// at offset 0. A caller-supplied parser is free to return any length, which
/// is why the cap cannot live in HeaderLengthSpec.
std::optional<HeaderParseResult> parseLeU32Header(std::span<const uint8_t> hdr)
{
    if (hdr.size() < 8) {
        return std::nullopt;
    }
    size_t declared = 0;
    for (int i = 0; i < 4; ++i) {
        declared |= static_cast<size_t>(hdr[i]) << (8 * i);
    }
    return HeaderParseResult{8, declared};
}

} // namespace

TEST(ChunkedReadTest, CustomHeaderParserCannotOutrunTheReadCap)
{
    LibreSCRS::SecureChannel::TestSupport::FakePCSCConnection conn;
    conn.setResponder(imageResponder(readChunkedReadCorpus("cr_header_declares_4gib.bin")));

    ChunkedReadOptions opts;
    opts.headerSpec.headerSize = 8;
    opts.errorPrefix = "cap";
    opts.parseHeader = parseLeU32Header;

    EXPECT_THROW((void)readChunkedFile(conn, opts), std::runtime_error);
    // One command: the header read. No body was ever asked for, so nothing
    // was reserved for it either.
    EXPECT_EQ(conn.history().size(), 1u);
}

TEST(ChunkedReadTest, DefaultHeaderSpecRefusesBeyondTheDefaultCap)
{
    // Four length octets at offset 4 of an eight-byte header: 32 MiB declared.
    std::vector<uint8_t> image = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02};
    LibreSCRS::SecureChannel::TestSupport::FakePCSCConnection conn;
    conn.setResponder(imageResponder(image));

    ChunkedReadOptions opts;
    opts.headerSpec.headerSize = 8;
    opts.headerSpec.lengthOffset = 4;
    opts.headerSpec.lengthBytes = 4;
    opts.errorPrefix = "cap";

    EXPECT_THROW((void)readChunkedFile(conn, opts), std::runtime_error);
    EXPECT_EQ(conn.history().size(), 1u);
}

TEST(ChunkedReadTest, CallerCapTighterThanTheDefaultStillBites)
{
    // 128 KiB declared, under the default ceiling but over the 64 KiB a
    // caller reading eID files sets for itself.
    std::vector<uint8_t> image = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00};
    LibreSCRS::SecureChannel::TestSupport::FakePCSCConnection conn;
    conn.setResponder(imageResponder(image));

    ChunkedReadOptions opts;
    opts.headerSpec.headerSize = 8;
    opts.headerSpec.lengthOffset = 4;
    opts.headerSpec.lengthBytes = 4;
    opts.maxTotalBytes = 64 * 1024;
    opts.errorPrefix = "cap";

    EXPECT_THROW((void)readChunkedFile(conn, opts), std::runtime_error);
    EXPECT_EQ(conn.history().size(), 1u);
}

TEST(ChunkedReadTest, ReadUnderTheCapStillReturnsTheFile)
{
    // Guards the three cases above: a ceiling that refused everything would
    // satisfy them and ship a reader that reads nothing.
    std::vector<uint8_t> image = {0x00, 0x00, 0x04, 0x00};
    image.insert(image.end(), 4u, 0x41);
    LibreSCRS::SecureChannel::TestSupport::FakePCSCConnection conn;
    conn.setResponder(imageResponder(image));

    ChunkedReadOptions opts;
    opts.errorPrefix = "cap";

    const auto body = readChunkedFile(conn, opts);
    EXPECT_EQ(body, std::vector<uint8_t>(4u, 0x41));
    EXPECT_GT(conn.history().size(), 1u);
}
