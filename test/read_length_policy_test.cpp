// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <gtest/gtest.h>

#include "apdu.h"
#include <smartcard/read_length_policy.h>

#include <LibreSCRS/SmartCard/TransportError.h>

#include <vector>

using namespace LibreSCRS::SmartCard;
using namespace LibreSCRS::SmartCard::Internal;

namespace {

const std::vector<uint8_t> kGeoInfo = {0x43, 0x01, 0xF8, 0x47, 0x03, 0xF6, 0x21, 0xE0, 0x7F, 0x66,
                                       0x08, 0x02, 0x02, 0x03, 0xC0, 0x02, 0x02, 0x03, 0xC0};

std::expected<APDUResponse, TransportError> answer(std::vector<uint8_t> data, uint8_t sw1, uint8_t sw2)
{
    return APDUResponse{std::move(data), sw1, sw2};
}

size_t wire(size_t len, size_t block)
{
    auto lf = [](size_t v) { return v < 128 ? 1 : v < 256 ? 2 : 3; };
    const size_t pad = (len / block + 1) * block;
    return 1 + lf(1 + pad) + 1 + pad + 4 + 10 + 2;
}

} // namespace

TEST(ParseExtendedLengthInfo, TakesTheResponseSizeOfASymmetricPair)
{
    EXPECT_EQ(parseExtendedLengthInfo(kGeoInfo), 960u);
}

TEST(ParseExtendedLengthInfo, TakesTheSecondIntegerOfAnAsymmetricPair)
{
    const std::vector<uint8_t> info = {0x7F, 0x66, 0x08, 0x02, 0x02, 0x03, 0xC0, 0x02, 0x02, 0x08, 0x00};
    EXPECT_EQ(parseExtendedLengthInfo(info), 2048u);
}

TEST(ParseExtendedLengthInfo, NoDataObjectGivesNothing)
{
    const std::vector<uint8_t> info = {0x43, 0x01, 0xF8};
    EXPECT_EQ(parseExtendedLengthInfo(info), std::nullopt);
}

TEST(ParseExtendedLengthInfo, LengthPastTheEndGivesNothing)
{
    const std::vector<uint8_t> info = {0x7F, 0x66, 0x09, 0x02, 0x02, 0x03, 0xC0, 0x02, 0x02, 0x03, 0xC0};
    EXPECT_EQ(parseExtendedLengthInfo(info), std::nullopt);
}

TEST(ParseExtendedLengthInfo, FirstElementThatIsNotAnIntegerGivesNothing)
{
    const std::vector<uint8_t> info = {0x7F, 0x66, 0x08, 0x04, 0x02, 0x03, 0xC0, 0x02, 0x02, 0x03, 0xC0};
    EXPECT_EQ(parseExtendedLengthInfo(info), std::nullopt);
}

TEST(ParseExtendedLengthInfo, ZeroLengthIntegerGivesNothing)
{
    const std::vector<uint8_t> info = {0x7F, 0x66, 0x06, 0x02, 0x00, 0x02, 0x02, 0x03, 0xC0};
    EXPECT_EQ(parseExtendedLengthInfo(info), std::nullopt);
}

TEST(ParseExtendedLengthInfo, OnlyOneIntegerGivesNothing)
{
    const std::vector<uint8_t> info = {0x7F, 0x66, 0x04, 0x02, 0x02, 0x03, 0xC0};
    EXPECT_EQ(parseExtendedLengthInfo(info), std::nullopt);
}

namespace {
constexpr ReadLengthState kBefores[] = {ReadLengthState::Untested, ReadLengthState::Accepted};
}

TEST(ClassifyLearnAnswer, WarningWithDeclarationIsDeclared)
{
    for (const auto before : kBefores) {
        auto r = classifyLearnAnswer(answer(kGeoInfo, 0x62, 0x82), before);
        EXPECT_EQ(r.first, ReadLengthState::Declared);
        EXPECT_EQ(r.second, 960u);
    }
}

TEST(ClassifyLearnAnswer, SuccessWithoutDeclarationIsAccepted)
{
    for (const auto before : kBefores)
        EXPECT_EQ(classifyLearnAnswer(answer({0x01, 0x02}, 0x90, 0x00), before).first, ReadLengthState::Accepted);
}

TEST(ClassifyLearnAnswer, DeclaredResponseOf256IsShort)
{
    const std::vector<uint8_t> info = {0x7F, 0x66, 0x08, 0x02, 0x02, 0x01, 0x00, 0x02, 0x02, 0x01, 0x00};
    for (const auto before : kBefores)
        EXPECT_EQ(classifyLearnAnswer(answer(info, 0x90, 0x00), before).first, ReadLengthState::Short);
}

TEST(ClassifyLearnAnswer, DeclaredResponseAroundTheShortLengthLimit)
{
    const auto declaring = [](std::uint8_t hi, std::uint8_t lo) {
        return std::vector<uint8_t>{0x7F, 0x66, 0x08, 0x02, 0x02, 0x03, 0xC0, 0x02, 0x02, hi, lo};
    };
    for (const auto before : kBefores) {
        EXPECT_EQ(classifyLearnAnswer(answer(declaring(0x01, 0x02), 0x90, 0x00), before).first, ReadLengthState::Short);
        const auto over = classifyLearnAnswer(answer(declaring(0x01, 0x03), 0x90, 0x00), before);
        EXPECT_EQ(over.first, ReadLengthState::Declared);
        EXPECT_EQ(over.second, 259u);
    }
}

TEST(ClassifyLearnAnswer, WrongLengthIsShortOnlyFromUntested)
{
    for (const std::uint8_t sw2 : {0x00, 0x01}) {
        EXPECT_EQ(classifyLearnAnswer(answer({}, 0x67, sw2), ReadLengthState::Untested).first, ReadLengthState::Short);
        EXPECT_EQ(classifyLearnAnswer(answer({}, 0x67, sw2), ReadLengthState::Accepted).first,
                  ReadLengthState::Accepted);
    }
}

TEST(ClassifyLearnAnswer, OtherStatusWordsKeepTheStateTheyStartedFrom)
{
    for (const auto before : kBefores)
        for (auto [a, b] : {std::pair<uint8_t, uint8_t>{0x6C, 0x13},
                            {0x6A, 0x82},
                            {0x6D, 0x00},
                            {0x6E, 0x00},
                            {0x69, 0x86},
                            {0x69, 0x82}})
            EXPECT_EQ(classifyLearnAnswer(answer({}, a, b), before).first, before);
}

TEST(ClassifyLearnAnswer, TransportErrorIsShort)
{
    std::expected<APDUResponse, TransportError> e = std::unexpected(TransportError{});
    for (const auto before : kBefores)
        EXPECT_EQ(classifyLearnAnswer(e, before).first, ReadLengthState::Short);
}

TEST(MaxSmProtectedData, KnownValues)
{
    EXPECT_EQ(maxSmProtectedData(960, 16), 927u);
    EXPECT_EQ(maxSmProtectedData(960, 8), 935u);
}

TEST(MaxSmProtectedData, IsTheLargestPayloadThatFits)
{
    for (size_t n : {300u, 960u, 4096u, 65535u})
        for (size_t b : {8u, 16u}) {
            const size_t m = maxSmProtectedData(n, b);
            EXPECT_LE(wire(m, b), n);
            EXPECT_GT(wire(m + 1, b), n);
        }
}

TEST(ReadLengthPolicyAllowedLe, ShortIsAlways256)
{
    ReadLengthPolicy p;
    p.learn(ReadLengthState::Short);
    EXPECT_EQ(p.allowedLe(0), 256u);
    EXPECT_EQ(p.allowedLe(16), 256u);
}

TEST(ReadLengthPolicyAllowedLe, UntestedAndAcceptedGrowOnlyOnThePlainChannel)
{
    ReadLengthPolicy p;
    EXPECT_EQ(p.state(), ReadLengthState::Untested);
    EXPECT_EQ(p.allowedLe(0), 2048u);
    EXPECT_EQ(p.allowedLe(8), 256u);
    p.markAccepted();
    EXPECT_EQ(p.state(), ReadLengthState::Accepted);
    EXPECT_EQ(p.allowedLe(0), 2048u);
    EXPECT_EQ(p.allowedLe(16), 256u);
}

TEST(ReadLengthPolicyAllowedLe, DeclaredFollowsTheCardsFigure)
{
    ReadLengthPolicy p;
    p.learn(ReadLengthState::Declared, 960);
    EXPECT_EQ(p.declaredResponseMax(), 960u);
    EXPECT_EQ(p.allowedLe(0), 958u);
    EXPECT_EQ(p.allowedLe(16), 927u);
}

TEST(ReadLengthPolicyAllowedLe, DeclaredIsCappedAt65535)
{
    ReadLengthPolicy p;
    p.learn(ReadLengthState::Declared, 70000);
    EXPECT_EQ(p.allowedLe(0), 65535u);
}

TEST(ReadLengthPolicyAllowedLe, DeclaredAroundTheShortLengthLimit)
{
    ReadLengthPolicy at;
    at.learn(ReadLengthState::Declared, 258);
    EXPECT_EQ(at.allowedLe(0), 256u);
    ReadLengthPolicy over;
    over.learn(ReadLengthState::Declared, 259);
    EXPECT_EQ(over.allowedLe(0), 257u);
}

TEST(ReadLengthPolicyTransitions, AcceptedOnlyFromUntested)
{
    ReadLengthPolicy p;
    p.learn(ReadLengthState::Short);
    p.markAccepted();
    EXPECT_EQ(p.state(), ReadLengthState::Short);
}

TEST(ReadLengthPolicyTransitions, DemoteWorksFromAnyState)
{
    for (auto s : {ReadLengthState::Untested, ReadLengthState::Accepted, ReadLengthState::Declared}) {
        ReadLengthPolicy p;
        p.learn(s, 960);
        p.demoteToShort();
        EXPECT_EQ(p.state(), ReadLengthState::Short);
    }
}

TEST(ReadLengthPolicyCommand, LearnCommandIsReadBinaryOfSfi1)
{
    const auto c = learnReadLengthCommand();
    EXPECT_EQ(c.cla, 0x00);
    EXPECT_EQ(c.ins, 0xB0);
    EXPECT_EQ(c.p1, 0x81);
    EXPECT_EQ(c.p2, 0x00);
    EXPECT_EQ(c.le, 2048);
}

TEST(IsReadBinary, RecognisesReadBinaryWithLeOnly)
{
    EXPECT_TRUE(isReadBinary(APDUCommand{0x00, 0xB0, 0, 0, {}, 256, true}));
    EXPECT_TRUE(isReadBinary(APDUCommand{0x00, 0xB1, 0, 0, {}, 256, true}));
    EXPECT_FALSE(isReadBinary(APDUCommand{0x00, 0xB0, 0, 0, {}, 0, false}));
    EXPECT_FALSE(isReadBinary(APDUCommand{0x00, 0xA4, 0, 0, {}, 256, true}));
    EXPECT_FALSE(isReadBinary(APDUCommand{0x00, 0x2A, 0, 0, {}, 256, true}));
}

TEST(RequestedLe, ZeroMeans256)
{
    EXPECT_EQ(requestedLe(APDUCommand{0x00, 0xB0, 0, 0, {}, 0, true}), 256u);
    EXPECT_EQ(requestedLe(APDUCommand{0x00, 0xB0, 0, 0, {}, 2048, true}), 2048u);
}
