// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <gtest/gtest.h>
#include <eu-vrc/eu_vrc_types.h>
#include <eu-vrc/eu_vrc_card.h>
#include <smartcard/ber.h>

// Task 1: Data types tests

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

// Task 2: Detection tests

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

// Task 3: Field extraction tests

TEST(EuVrcCard, ExtractMandatoryFields)
{
    // Build a minimal BER tree: tag 71 containing tag 81 (reg number) and 87 (make)
    smartcard::BERField root;
    smartcard::BERField mandatory;
    mandatory.tag = 0x71;
    mandatory.constructed = true;

    smartcard::BERField regNum;
    regNum.tag = 0x81;
    regNum.value = {'B', 'G', '-', '1', '2', '3'};
    mandatory.children.push_back(regNum);

    smartcard::BERField vehicleContainer;
    vehicleContainer.tag = 0xA3;
    vehicleContainer.constructed = true;
    smartcard::BERField make;
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
    smartcard::BERField root;
    smartcard::BERField optional;
    optional.tag = 0x72;
    optional.constructed = true;

    // EU tag
    smartcard::BERField category;
    category.tag = 0x98;
    category.value = {'M', '1'};
    optional.children.push_back(category);

    // National extension tag (>= 0xC0)
    smartcard::BERField jmbg;
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
