// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <gtest/gtest.h>
#include <eu_vrc_types.h>
#include <eu_vrc_card.h>
#include <ber.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <string>
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

namespace {

using EuVrcStringField = std::string euvrc::EuVrcData::*;

// One field of the certificate: where Directive 2003/127/EC puts it, written
// out as literal tags so this table does not share a dictionary with the parser.
struct DirectivePath
{
    std::vector<uint32_t> path;
    EuVrcStringField member;
    const char* name;
};

const std::vector<DirectivePath>& directivePaths()
{
    using D = euvrc::EuVrcData;
    static const std::vector<DirectivePath> paths = {
        {{0x71, 0x80}, &D::version, "version"},
        {{0x71, 0x9F33}, &D::memberState, "memberState"},
        {{0x71, 0x9F35}, &D::competentAuthority, "competentAuthority"},
        {{0x71, 0x9F36}, &D::issuingAuthority, "issuingAuthority"},
        {{0x71, 0x9F38}, &D::documentNumber, "documentNumber"},
        {{0x71, 0x9F34}, &D::previousDocument, "previousDocument"},
        {{0x71, 0x81}, &D::registrationNumber, "registrationNumber"},
        {{0x71, 0x82}, &D::firstRegistration, "firstRegistration"},
        {{0x71, 0xA1, 0xA2, 0x83}, &D::holderName, "holderName"},
        {{0x71, 0xA1, 0xA2, 0x84}, &D::holderOtherNames, "holderOtherNames"},
        {{0x71, 0xA1, 0xA2, 0x85}, &D::holderAddress, "holderAddress"},
        {{0x71, 0x86}, &D::ownershipStatus, "ownershipStatus"},
        {{0x71, 0xA3, 0x87}, &D::vehicleMake, "vehicleMake"},
        {{0x71, 0xA3, 0x88}, &D::vehicleType, "vehicleType"},
        {{0x71, 0xA3, 0x89}, &D::commercialDesc, "commercialDesc"},
        {{0x71, 0x8A}, &D::vin, "vin"},
        {{0x71, 0xA4, 0x8B}, &D::maxLadenMass, "maxLadenMass"},
        {{0x71, 0x8C}, &D::vehicleMass, "vehicleMass"},
        {{0x71, 0x8D}, &D::expiryDate, "expiryDate"},
        {{0x71, 0x8E}, &D::registrationDate, "registrationDate"},
        {{0x71, 0x8F}, &D::typeApproval, "typeApproval"},
        {{0x71, 0xA5, 0x90}, &D::engineCapacity, "engineCapacity"},
        {{0x71, 0xA5, 0x91}, &D::maxNetPower, "maxNetPower"},
        {{0x71, 0xA5, 0x92}, &D::fuelType, "fuelType"},
        {{0x71, 0x93}, &D::powerWeightRatio, "powerWeightRatio"},
        {{0x71, 0xA6, 0x94}, &D::numberOfSeats, "numberOfSeats"},
        {{0x71, 0xA6, 0x95}, &D::standingPlaces, "standingPlaces"},
        {{0x72, 0xA4, 0x96}, &D::maxLadenMassService, "maxLadenMassService"},
        {{0x72, 0xA4, 0x97}, &D::maxLadenMassWhole, "maxLadenMassWhole"},
        {{0x72, 0x98}, &D::vehicleCategory, "vehicleCategory"},
        {{0x72, 0x99}, &D::numberOfAxles, "numberOfAxles"},
        {{0x72, 0x9A}, &D::wheelbase, "wheelbase"},
        {{0x72, 0x9B}, &D::brakedTrailerMass, "brakedTrailerMass"},
        {{0x72, 0x9C}, &D::unbrakedTrailerMass, "unbrakedTrailerMass"},
        {{0x72, 0xA5, 0x9D}, &D::ratedEngineSpeed, "ratedEngineSpeed"},
        {{0x72, 0xA5, 0x9E}, &D::engineIdNumber, "engineIdNumber"},
        {{0x72, 0x9F24}, &D::colour, "colour"},
        {{0x72, 0x9F25}, &D::maxSpeed, "maxSpeed"},
        {{0x72, 0x9F26}, &D::stationarySoundLevel, "stationarySoundLevel"},
        {{0x72, 0x9F27}, &D::engineSpeedRef, "engineSpeedRef"},
        {{0x72, 0x9F28}, &D::driveBySound, "driveBySound"},
        {{0x72, 0x9F2F}, &D::fuelConsumption, "fuelConsumption"},
        {{0x72, 0x9F30}, &D::co2, "co2"},
        {{0x72, 0x9F31}, &D::envCategory, "envCategory"},
        {{0x72, 0x9F32}, &D::fuelTankCapacity, "fuelTankCapacity"},
        {{0x71, 0xA1, 0xA7, 0x83}, &D::owner2Name, "owner2Name"},
        {{0x71, 0xA1, 0xA9, 0x83}, &D::userName, "userName"},
        {{0x71, 0xA1, 0xA9, 0x84}, &D::userOtherNames, "userOtherNames"},
        {{0x71, 0xA1, 0xA9, 0x85}, &D::userAddress, "userAddress"},
    };
    return paths;
}

// Puts @p value at @p path under @p root, creating the containers on the way.
void place(LibreSCRS::SmartCard::Internal::BERField& root, const std::vector<uint32_t>& path, const std::string& value)
{
    auto* node = &root;
    for (std::size_t i = 0; i < path.size(); ++i) {
        auto it = std::find_if(node->children.begin(), node->children.end(),
                               [&](const auto& child) { return child.tag == path[i]; });
        if (it == node->children.end()) {
            LibreSCRS::SmartCard::Internal::BERField child;
            child.tag = path[i];
            child.constructed = i + 1 < path.size();
            node->children.push_back(child);
            it = std::prev(node->children.end());
        }
        node = &*it;
    }
    node->value.assign(value.begin(), value.end());
}

bool isDateField(EuVrcStringField member)
{
    using D = euvrc::EuVrcData;
    return member == &D::firstRegistration || member == &D::expiryDate || member == &D::registrationDate;
}

} // namespace

// Every field the certificate defines is read from its own path and from no
// other: each gets a distinct value, so a tag read under the wrong name, or a
// field read from a neighbour's path, shows up as the wrong value.
TEST(EuVrcCard, EveryFieldIsReadFromItsDirectivePath)
{
    LibreSCRS::SmartCard::Internal::BERField root;
    std::vector<std::string> values;
    for (std::size_t i = 0; i < directivePaths().size(); ++i) {
        const auto& entry = directivePaths()[i];
        values.push_back(isDateField(entry.member) ? "2019031" + std::to_string(i % 10) : "v" + std::to_string(i));
        place(root, entry.path, values.back());
    }

    const auto data = euvrc::extractFields(root);
    for (std::size_t i = 0; i < directivePaths().size(); ++i) {
        const auto& entry = directivePaths()[i];
        const auto expected = isDateField(entry.member) ? euvrc::formatVrcDate(values[i]) : values[i];
        EXPECT_EQ(data.*entry.member, expected) << entry.name;
    }
}

// The user (C.3) is read from the optional container when the mandatory one
// carries none of it.
TEST(EuVrcCard, UserFallsBackToTheOptionalContainer)
{
    LibreSCRS::SmartCard::Internal::BERField root;
    place(root, {0x72, 0xA1, 0xA9, 0x83}, "name");
    place(root, {0x72, 0xA1, 0xA9, 0x84}, "other");
    place(root, {0x72, 0xA1, 0xA9, 0x85}, "address");

    const auto data = euvrc::extractFields(root);
    EXPECT_EQ(data.userName, "name");
    EXPECT_EQ(data.userOtherNames, "other");
    EXPECT_EQ(data.userAddress, "address");
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
