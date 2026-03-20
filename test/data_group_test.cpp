// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <gtest/gtest.h>
#include <emrtd/data_group.h>

using namespace emrtd;

TEST(DataGroupTest, EmptyInput)
{
    std::map<int, std::vector<uint8_t>> rawDGs;
    auto parsed = parseDataGroups(rawDGs);
    EXPECT_FALSE(parsed.dg1.has_value());
    EXPECT_FALSE(parsed.dg2.has_value());
    EXPECT_TRUE(parsed.raw.empty());
}

TEST(DataGroupTest, UnknownDGGoesToRaw)
{
    std::map<int, std::vector<uint8_t>> rawDGs;
    rawDGs[16] = {0x01, 0x02, 0x03};

    auto parsed = parseDataGroups(rawDGs);
    EXPECT_TRUE(parsed.raw.count(16) > 0);
    EXPECT_EQ(parsed.raw[16].size(), 3u);
}

TEST(DataGroupTest, DG1ParsesMRZ)
{
    // Build a minimal DG1: tag 0x61, length, sub-tag 0x5F1F, length, MRZ bytes
    std::string mrzStr = "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<\n"
                         "L898902C<5UTO7407272F1207146ZE184226B<<<<<10";
    std::vector<uint8_t> mrzBytes(mrzStr.begin(), mrzStr.end());

    // Build TLV: 61 [len] 5F1F [len] [MRZ]
    std::vector<uint8_t> dg1;
    dg1.push_back(0x61);

    // Inner TLV: 5F1F [len] [data]
    std::vector<uint8_t> inner;
    inner.push_back(0x5F);
    inner.push_back(0x1F);
    if (mrzBytes.size() < 128) {
        inner.push_back(static_cast<uint8_t>(mrzBytes.size()));
    } else {
        inner.push_back(0x81);
        inner.push_back(static_cast<uint8_t>(mrzBytes.size()));
    }
    inner.insert(inner.end(), mrzBytes.begin(), mrzBytes.end());

    // Outer length
    if (inner.size() < 128) {
        dg1.push_back(static_cast<uint8_t>(inner.size()));
    } else {
        dg1.push_back(0x81);
        dg1.push_back(static_cast<uint8_t>(inner.size()));
    }
    dg1.insert(dg1.end(), inner.begin(), inner.end());

    std::map<int, std::vector<uint8_t>> rawDGs;
    rawDGs[1] = dg1;

    auto parsed = parseDataGroups(rawDGs);
    ASSERT_TRUE(parsed.dg1.has_value());
    EXPECT_EQ(parsed.dg1->surname, "ERIKSSON");
    EXPECT_EQ(parsed.dg1->givenNames, "ANNA MARIA");
}
