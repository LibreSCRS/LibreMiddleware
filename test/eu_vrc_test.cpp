// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <gtest/gtest.h>
#include <eu_vrc_types.h>
#include <eu_vrc_card.h>
#include <ber.h>

#include <cstdint>
#include <vector>

// Data type tests

TEST(EuVrcTypes, DefaultConstruction)
{
    euvrc::EuVrcData data;
    EXPECT_TRUE(data.registrationNumber.empty());
    EXPECT_TRUE(data.vehicleMake.empty());
    EXPECT_TRUE(data.vin.empty());
    EXPECT_TRUE(data.nationalTags.empty());
}

TEST(EuVrcTypes, NationalExtensions)
{
    euvrc::EuVrcData data;
    data.nationalTags.push_back({0xC2, "0712978750036"});
    data.nationalTags.push_back({0xC5, "2019"});
    EXPECT_EQ(data.nationalTags.size(), 2u);
    EXPECT_EQ(data.nationalTags[0].second, "0712978750036");
}

// Detection tests

#include "eu_vrc_detection.h"

TEST(EuVrcDetection, AllKnownSequencesReturned)
{
    auto sequences = euvrc::getAllKnownAidSequences();
    // EU standard + 3 Serbian sequences = 4
    EXPECT_EQ(sequences.size(), 4u);
}

TEST(EuVrcDetection, EuStandardAidIsSingleSelect)
{
    auto sequences = euvrc::getAllKnownAidSequences();
    // First should be EU standard (single command)
    EXPECT_EQ(sequences[0].selectCommands.size(), 1u);
    EXPECT_EQ(sequences[0].name, "EU-EVR-01");
}

TEST(EuVrcDetection, SerbianSequencesAreMultiStep)
{
    auto sequences = euvrc::getAllKnownAidSequences();
    for (size_t i = 1; i < sequences.size(); ++i) {
        EXPECT_EQ(sequences[i].selectCommands.size(), 3u)
            << "Sequence " << sequences[i].name << " should have 3 commands";
    }
}

TEST(EuVrcDetection, EuStandardFileFids)
{
    auto fids = euvrc::getStandardFileFids();
    // D001, D011, E001, E011, C001, C011 = 6
    EXPECT_EQ(fids.size(), 6u);
}

TEST(EuVrcDetection, NationalExtensionFids)
{
    auto fids = euvrc::getNationalExtensionFids();
    // D021, D031, E021, C021 = 4
    EXPECT_EQ(fids.size(), 4u);
}

// Field extraction tests

TEST(EuVrcCard, ExtractMandatoryFields)
{
    // Build a minimal BER tree: tag 71 containing tag 81 (reg number) and 87 (make)
    LibreSCRS::SmartCard::Internal::BERField root;
    LibreSCRS::SmartCard::Internal::BERField mandatory;
    mandatory.tag = 0x71;
    mandatory.constructed = true;

    LibreSCRS::SmartCard::Internal::BERField regNum;
    regNum.tag = 0x81;
    regNum.value = {'B', 'G', '-', '1', '2', '3'};
    mandatory.children.push_back(regNum);

    LibreSCRS::SmartCard::Internal::BERField vehicleContainer;
    vehicleContainer.tag = 0xA3;
    vehicleContainer.constructed = true;
    LibreSCRS::SmartCard::Internal::BERField make;
    make.tag = 0x87;
    make.value = {'V', 'W'};
    vehicleContainer.children.push_back(make);
    mandatory.children.push_back(vehicleContainer);

    root.children.push_back(mandatory);

    auto data = euvrc::extractFields(root);
    EXPECT_EQ(data.registrationNumber, "BG-123");
    EXPECT_EQ(data.vehicleMake, "VW");
}

TEST(EuVrcCard, ExtractNationalExtensions)
{
    LibreSCRS::SmartCard::Internal::BERField root;
    LibreSCRS::SmartCard::Internal::BERField optional;
    optional.tag = 0x72;
    optional.constructed = true;

    // EU tag
    LibreSCRS::SmartCard::Internal::BERField category;
    category.tag = 0x98;
    category.value = {'M', '1'};
    optional.children.push_back(category);

    // National extension tag (>= 0xC0)
    LibreSCRS::SmartCard::Internal::BERField jmbg;
    jmbg.tag = 0xC2;
    jmbg.value = {'1', '2', '3', '4'};
    optional.children.push_back(jmbg);

    root.children.push_back(optional);

    auto data = euvrc::extractFields(root);
    EXPECT_EQ(data.vehicleCategory, "M1");
    EXPECT_EQ(data.nationalTags.size(), 1u);
    EXPECT_EQ(data.nationalTags[0].first, 0xC2u);
    EXPECT_EQ(data.nationalTags[0].second, "1234");
}

TEST(EuVrcCard, DateFormatConversion)
{
    EXPECT_EQ(euvrc::formatVrcDate("20190315"), "15.03.2019");
    EXPECT_EQ(euvrc::formatVrcDate("invalid"), "invalid");
    EXPECT_EQ(euvrc::formatVrcDate(""), "");
}

// =============================================================================
// Header derivation: the two contracts the BER length decoder actually has.
//
// One caller -- this one, when the FCI said nothing about the file size --
// decodes a length to learn how many bytes still have to be read FROM THE CARD,
// so the value legitimately exceeds the buffer in hand. Every other caller
// decodes a length that must fit bytes which have already arrived. A change to
// the shared decoder that enforces containment, or that clamps to the buffer,
// is correct for the second contract and wrong for this one -- and until these
// cases existed it would have been discovered on a card rather than here.
// =============================================================================
namespace {

// A header the card could really hand over: the first bytes do not parse as
// BER at all (a multi-byte tag followed by a length octet claiming 127 length
// octets), so the reader falls back to the NXP header-skip -- body at
// `hdr[1] + 2` -- and finds a TLV there declaring a 2000-byte body. 2000 is far
// larger than any buffer the header is handed in, which is the point.
std::vector<uint8_t> declaringHeader(size_t bufferSize)
{
    std::vector<uint8_t> hdr{0x7F, 0x02, 0xFF, 0x00, 0x71, 0x82, 0x07, 0xD0};
    hdr.resize(bufferSize, 0x00);
    return hdr;
}

constexpr size_t kDataOffset = 0x02 + 2;       // hdr[1] + 2
constexpr size_t kDeclaredBody = 1 + 3 + 2000; // tag + length octets + declared body

} // namespace

TEST(EuVrcHeader, DeclaresMoreThanTheHeaderHolds)
{
    const auto hdr = declaringHeader(32);

    const auto res = euvrc::detail::deriveEuVrcHeader(hdr, 0);

    ASSERT_TRUE(res.has_value());
    EXPECT_EQ(res->dataOffset, kDataOffset);
    EXPECT_EQ(res->totalToRead, kDeclaredBody);
}

// The control. Without it the two paths are indistinguishable: a decoder that
// stopped answering at all would still look right in the case above.
TEST(EuVrcHeader, FciSizeWinsAndSkipsTheLengthWalk)
{
    const auto hdr = declaringHeader(32);

    const auto res = euvrc::detail::deriveEuVrcHeader(hdr, 4096);

    ASSERT_TRUE(res.has_value());
    EXPECT_EQ(res->dataOffset, kDataOffset);
    EXPECT_EQ(res->totalToRead, 4096U - kDataOffset);
}

// The same header in a larger buffer must give the same answer. Tools hand a
// buffer of exactly the size they read, so a decoder that clamped its answer to
// the buffer would agree with the first case and disagree here -- which is the
// one perturbation the first case cannot catch.
TEST(EuVrcHeader, LargerBufferSameAnswer)
{
    const auto small = euvrc::detail::deriveEuVrcHeader(declaringHeader(32), 0);
    const auto large = euvrc::detail::deriveEuVrcHeader(declaringHeader(64), 0);

    ASSERT_TRUE(small.has_value());
    ASSERT_TRUE(large.has_value());
    EXPECT_EQ(large->totalToRead, small->totalToRead);
    EXPECT_EQ(large->totalToRead, kDeclaredBody);
}
