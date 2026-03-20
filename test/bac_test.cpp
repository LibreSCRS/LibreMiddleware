// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <gtest/gtest.h>
#include <emrtd/crypto/bac.h>

using namespace emrtd::crypto;

// BAC key derivation tests — ICAO 9303 Part 3 §4.9 algorithm
// Uses document number L898902C, DOB 740727, DOE 120714 as worked example

TEST(BACTest, CheckDigitComputation)
{
    // Check digits computed per ICAO 9303 Part 3 Section 4.9 algorithm (weight 7,3,1).
    // Verified by manual computation.
    // L=21,8=8,9=9,8=8,9=9,0=0,2=2,C=12,<=0 → 313 % 10 = 3
    EXPECT_EQ(detail::computeCheckDigit("L898902C<"), 3);
    // 7×7+4×3+0×1+7×7+2×3+7×1 = 123 % 10 = 3
    EXPECT_EQ(detail::computeCheckDigit("740727"), 3);
    // 1×7+2×3+0×1+7×7+1×3+4×1 = 69 % 10 = 9
    EXPECT_EQ(detail::computeCheckDigit("120714"), 9);
}

TEST(BACTest, KeySeedDerivation)
{
    auto keys = deriveBACKeys("L898902C", "740727", "120714");

    EXPECT_EQ(keys.encKey.size(), 16u);
    EXPECT_EQ(keys.macKey.size(), 16u);

    // Key vectors derived from MRZ_information = "L898902C<3" + "7407273" + "1207149"
    // K_seed = SHA-1(MRZ_information)[0:16], KDF(K_seed,1/2) with parity adjustment.
    // Verified by running the implementation against ICAO 9303 Part 3 §4.9 algorithm.
    std::vector<uint8_t> expectedEnc = {0xCB, 0x10, 0x61, 0xFE, 0x76, 0x4F, 0x0B, 0x1C,
                                        0x86, 0xF1, 0x91, 0xC2, 0x2A, 0x51, 0x97, 0x31};
    std::vector<uint8_t> expectedMac = {0x25, 0xDA, 0x08, 0xAD, 0x4A, 0xA2, 0x0E, 0x3D,
                                        0x38, 0xF8, 0x02, 0xD9, 0x75, 0x85, 0x32, 0x57};
    EXPECT_EQ(keys.encKey, expectedEnc);
    EXPECT_EQ(keys.macKey, expectedMac);
}

TEST(BACTest, KeysAreDifferent)
{
    auto keys = deriveBACKeys("L898902C", "740727", "120714");
    EXPECT_NE(keys.encKey, keys.macKey);
}

TEST(BACTest, DifferentMRZProducesDifferentKeys)
{
    auto keys1 = deriveBACKeys("L898902C", "740727", "120714");
    auto keys2 = deriveBACKeys("X123456Y", "800101", "250101");
    EXPECT_NE(keys1.encKey, keys2.encKey);
    EXPECT_NE(keys1.macKey, keys2.macKey);
}

TEST(BACTest, PaddedDocumentNumber)
{
    auto keys = deriveBACKeys("AB1234", "800101", "250101");
    EXPECT_EQ(keys.encKey.size(), 16u);
}
