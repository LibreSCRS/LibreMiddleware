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

    const auto read = card.readDataGroup(2);

    ASSERT_TRUE(read.has_value());
    ASSERT_EQ(read->size(), chip.file.size());
    EXPECT_TRUE(*read == chip.file) << "the tail past 0x7FFF must be the file's tail, not its beginning again";
}

TEST(EmrtdCardRead, AFileCutShortByAnErrorIsNoFile)
{
    Chip chip;
    chip.failOnRead = 2;
    FakeChannel channel(LibreSCRS::SmartCard::AppletAid{}, ChannelState::Open, true);
    channel.transmitHandler = [&chip](const APDUCommand& cmd) { return chip.answer(cmd); };
    emrtd::EMRTDCard card(channel);

    EXPECT_FALSE(card.readDataGroup(2).has_value());
}

TEST(EmrtdCardRead, AFileEndingBeforeItsDeclaredLengthIsNoFile)
{
    Chip chip;
    chip.file.resize(1000); // the header still declares 40 KiB
    FakeChannel channel(LibreSCRS::SmartCard::AppletAid{}, ChannelState::Open, true);
    channel.transmitHandler = [&chip](const APDUCommand& cmd) { return chip.answer(cmd); };
    emrtd::EMRTDCard card(channel);

    EXPECT_FALSE(card.readDataGroup(2).has_value());
}
