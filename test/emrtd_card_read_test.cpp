// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

// EMRTDCard::readFile against a scripted chip: a data group past offset
// 0x7FFF is read with the odd-INS READ BINARY, and a file the chip cuts short
// is no file.

#include "emrtd_card.h"

#include <apdu.h>
#include <fake_channel.h>
#include <gtest/gtest.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <vector>

namespace {

using LibreSCRS::SecureChannel::ChannelState;
using LibreSCRS::SecureChannel::TestSupport::FakeChannel;
using LibreSCRS::SmartCard::Internal::APDUCommand;
using LibreSCRS::SmartCard::Internal::APDUResponse;

// A DG2-shaped file of 40 KiB: tag 75, a three-byte length, then a body
// whose every byte is a function of its offset, so a wrapped read shows.
std::vector<std::uint8_t> bigFile()
{
    constexpr std::size_t kBody = 40 * 1024;
    std::vector<std::uint8_t> f{0x75, 0x83, static_cast<std::uint8_t>(kBody >> 16),
                                static_cast<std::uint8_t>(kBody >> 8), static_cast<std::uint8_t>(kBody & 0xFF)};
    for (std::size_t i = 0; i < kBody; ++i)
        f.push_back(static_cast<std::uint8_t>((i * 7 + i / 251) & 0xFF));
    return f;
}

// The chip: B0 takes the offset from P1-P2 as a card does, its top bit
// masked, so an offset past 0x7FFF sent with B0 lands at offset - 0x8000;
// B1 takes the offset from DO'54 and answers in DO'53.
struct Chip
{
    std::vector<std::uint8_t> file = bigFile();
    int readsAnswered = 0;
    std::optional<int> failOnRead; // answer this read (0-based) with 6982

    APDUResponse answer(const APDUCommand& cmd)
    {
        if (cmd.ins == 0xA4)
            return APDUResponse{{}, 0x90, 0x00};
        const int read = readsAnswered++;
        if (failOnRead && *failOnRead == read)
            return APDUResponse{{}, 0x69, 0x82};
        std::size_t offset = 0;
        if (cmd.ins == 0xB0) {
            offset = (static_cast<std::size_t>(cmd.p1 & 0x7F) << 8) | cmd.p2;
        } else if (cmd.ins == 0xB1) {
            if (cmd.data.size() < 2 || cmd.data[0] != 0x54 || cmd.data[1] + 2u != cmd.data.size())
                return APDUResponse{{}, 0x6A, 0x80};
            for (std::size_t i = 2; i < cmd.data.size(); ++i)
                offset = (offset << 8) | cmd.data[i];
        } else {
            return APDUResponse{{}, 0x6D, 0x00};
        }
        if (offset >= file.size())
            return APDUResponse{{}, 0x6B, 0x00};
        const std::size_t room = cmd.ins == 0xB1 ? 252 : 256;
        const std::size_t n = std::min(room, file.size() - offset);
        std::vector<std::uint8_t> data(file.begin() + static_cast<std::ptrdiff_t>(offset),
                                       file.begin() + static_cast<std::ptrdiff_t>(offset + n));
        if (cmd.ins == 0xB1) {
            std::vector<std::uint8_t> wrapped{0x53, 0x81, static_cast<std::uint8_t>(n)};
            wrapped.insert(wrapped.end(), data.begin(), data.end());
            data = std::move(wrapped);
        }
        return APDUResponse{std::move(data), 0x90, 0x00};
    }
};

} // namespace

TEST(EmrtdCardRead, DataGroupPastOffset7FFFIsReadWithTheOddIns)
{
    Chip chip;
    FakeChannel channel(LibreSCRS::SmartCard::AppletAid{}, ChannelState::Open, true);
    channel.transmitHandler = [&chip](const APDUCommand& cmd) { return chip.answer(cmd); };
    emrtd::EMRTDCard card(channel);

    const auto read = card.readDataGroupSafe(2);

    ASSERT_TRUE(read.has_value());
    ASSERT_EQ(read->status, emrtd::DGReadStatus::OK);
    ASSERT_EQ(read->data.size(), chip.file.size());
    EXPECT_TRUE(read->data == chip.file) << "the tail past 0x7FFF must be the file's tail, not its beginning again";
}

TEST(EmrtdCardRead, AFileCutShortByAnErrorIsNoFile)
{
    Chip chip;
    chip.failOnRead = 2;
    FakeChannel channel(LibreSCRS::SmartCard::AppletAid{}, ChannelState::Open, true);
    channel.transmitHandler = [&chip](const APDUCommand& cmd) { return chip.answer(cmd); };
    emrtd::EMRTDCard card(channel);

    const auto read = card.readDataGroupSafe(2);
    ASSERT_TRUE(read.has_value());
    EXPECT_EQ(read->status, emrtd::DGReadStatus::ERROR);
}

TEST(EmrtdCardRead, AFileEndingBeforeItsDeclaredLengthIsNoFile)
{
    Chip chip;
    chip.file.resize(1000); // the header still declares 40 KiB
    FakeChannel channel(LibreSCRS::SmartCard::AppletAid{}, ChannelState::Open, true);
    channel.transmitHandler = [&chip](const APDUCommand& cmd) { return chip.answer(cmd); };
    emrtd::EMRTDCard card(channel);

    const auto read = card.readDataGroupSafe(2);
    ASSERT_TRUE(read.has_value());
    EXPECT_EQ(read->status, emrtd::DGReadStatus::ERROR);
}

namespace {
using LibreSCRS::SmartCard::TransportError;

void breakAfter(FakeChannel& channel, TransportError::Kind kind, int answerFirst)
{
    auto seen = std::make_shared<int>(0);
    channel.onTransmitCallback = [&channel, kind, answerFirst, seen] {
        if (++*seen > answerFirst)
            channel.transmitFailure = TransportError{kind, "scripted link failure"};
    };
}
} // namespace

TEST(EmrtdCardRead, ALinkFailureOnADataGroupIsTheError)
{
    FakeChannel channel(LibreSCRS::SmartCard::AppletAid{}, ChannelState::Open, true);
    breakAfter(channel, TransportError::Kind::IntegrityFailure, 1); // SELECT answers, READ BINARY fails
    emrtd::EMRTDCard card(channel);

    const auto read = card.readDataGroupSafe(2);

    ASSERT_FALSE(read.has_value());
    EXPECT_EQ(read.error().kind, TransportError::Kind::IntegrityFailure);
}

TEST(EmrtdCardRead, ALinkFailureOnTheComAndSodIsTheError)
{
    FakeChannel channel(LibreSCRS::SmartCard::AppletAid{}, ChannelState::Open, true);
    breakAfter(channel, TransportError::Kind::NoCardPresent, 0);
    emrtd::EMRTDCard card(channel);

    const auto com = card.readCOM();
    ASSERT_FALSE(com.has_value());
    EXPECT_EQ(com.error().kind, TransportError::Kind::NoCardPresent);
    const auto sod = card.readSOD();
    ASSERT_FALSE(sod.has_value());
    EXPECT_EQ(sod.error().kind, TransportError::Kind::NoCardPresent);
}

TEST(EmrtdCardRead, ACardAnswerIsAValueNotAnError)
{
    FakeChannel channel(LibreSCRS::SmartCard::AppletAid{}, ChannelState::Open, true);
    channel.transmitHandler = [](const APDUCommand&) { return APDUResponse{{}, 0x6A, 0x82}; };
    emrtd::EMRTDCard card(channel);

    const auto read = card.readDataGroupSafe(11);
    ASSERT_TRUE(read.has_value());
    EXPECT_EQ(read->status, emrtd::DGReadStatus::NOT_PRESENT);
    const auto sod = card.readSOD();
    ASSERT_TRUE(sod.has_value());
    EXPECT_FALSE(sod->has_value());
}

// --- The read asks for the whole remaining file ---

namespace {

struct AskedRead
{
    std::uint8_t ins;
    std::size_t offset;
    std::size_t le;
};

// A chip that answers as much as it is asked for, but at most `perAnswer`
// bytes, and logs what it was asked. B1 answers wrap the data in a DO'53 whose
// header costs up to four bytes of the Le.
struct WideChip
{
    std::vector<std::uint8_t> file;
    std::size_t perAnswer = 65535;
    std::vector<AskedRead> asked;

    explicit WideChip(std::size_t body)
    {
        file = {0x75, 0x83, static_cast<std::uint8_t>(body >> 16), static_cast<std::uint8_t>(body >> 8),
                static_cast<std::uint8_t>(body & 0xFF)};
        for (std::size_t i = 0; i < body; ++i)
            file.push_back(static_cast<std::uint8_t>((i * 7 + i / 251) & 0xFF));
    }

    APDUResponse answer(const APDUCommand& cmd)
    {
        if (cmd.ins == 0xA4)
            return APDUResponse{{}, 0x90, 0x00};
        std::size_t offset = 0;
        if (cmd.ins == 0xB0) {
            offset = (static_cast<std::size_t>(cmd.p1 & 0x7F) << 8) | cmd.p2;
        } else {
            for (std::size_t i = 2; i < cmd.data.size(); ++i)
                offset = (offset << 8) | cmd.data[i];
        }
        const std::size_t le = cmd.le == 0 ? 256 : cmd.le;
        asked.push_back({cmd.ins, offset, le});
        if (offset >= file.size())
            return APDUResponse{{}, 0x6B, 0x00};
        if (cmd.ins == 0xB0) {
            const std::size_t n = std::min({le, perAnswer, file.size() - offset});
            return APDUResponse{{file.begin() + static_cast<std::ptrdiff_t>(offset),
                                 file.begin() + static_cast<std::ptrdiff_t>(offset + n)},
                                0x90,
                                0x00};
        }
        const std::size_t n = std::min({le - 4, perAnswer, file.size() - offset});
        std::vector<std::uint8_t> wrapped{0x53, 0x82, static_cast<std::uint8_t>(n >> 8),
                                          static_cast<std::uint8_t>(n & 0xFF)};
        wrapped.insert(wrapped.end(), file.begin() + static_cast<std::ptrdiff_t>(offset),
                       file.begin() + static_cast<std::ptrdiff_t>(offset + n));
        return APDUResponse{std::move(wrapped), 0x90, 0x00};
    }
};

auto readDg2(WideChip& chip)
{
    FakeChannel channel(LibreSCRS::SmartCard::AppletAid{}, ChannelState::Open, true);
    channel.transmitHandler = [&chip](const APDUCommand& cmd) { return chip.answer(cmd); };
    emrtd::EMRTDCard card(channel);
    return card.readDataGroupSafe(2);
}

} // namespace

TEST(EmrtdCardRead, AFileOver64KiBIsAskedForWholeThenFromTheOddIns)
{
    WideChip chip(70000);
    const auto read = readDg2(chip);

    ASSERT_TRUE(read.has_value());
    ASSERT_EQ(read->status, emrtd::DGReadStatus::OK);
    EXPECT_TRUE(read->data == chip.file);
    ASSERT_GE(chip.asked.size(), 2u);
    EXPECT_EQ(chip.asked[0].ins, 0xB0);
    EXPECT_EQ(chip.asked[0].le, 65535u);
    EXPECT_EQ(chip.asked[1].ins, 0xB1);
    EXPECT_EQ(chip.asked[1].offset, 65535u);
    EXPECT_EQ(chip.asked[1].le, (chip.file.size() - 65535u) + 4u); // the remaining plus the DO'53 header
}

TEST(EmrtdCardRead, ShortAnswersAreContinuedByTheirOwnLength)
{
    WideChip chip(2043); // file of 2048
    chip.perAnswer = 958;
    const auto read = readDg2(chip);

    ASSERT_TRUE(read.has_value());
    ASSERT_EQ(read->status, emrtd::DGReadStatus::OK);
    EXPECT_TRUE(read->data == chip.file);
    ASSERT_EQ(chip.asked.size(), 3u);
    EXPECT_EQ(chip.asked[0].le, 65535u); // length not known before the first answer
    EXPECT_EQ(chip.asked[1].offset, 958u);
    EXPECT_EQ(chip.asked[1].le, 2048u - 958u);
}

TEST(EmrtdCardRead, NoReadStartsAtTheEndOfAFileOfTwoFullAnswers)
{
    WideChip chip(1911); // file of 1916 = 2 x 958
    chip.perAnswer = 958;
    const auto read = readDg2(chip);

    ASSERT_TRUE(read.has_value());
    ASSERT_EQ(read->status, emrtd::DGReadStatus::OK);
    EXPECT_TRUE(read->data == chip.file);
    for (const auto& a : chip.asked)
        EXPECT_LT(a.offset, chip.file.size());
}
