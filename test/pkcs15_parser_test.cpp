// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <pkcs15/pkcs15_parser.h>

#include "pkcs15_test_vectors.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <span>
#include <vector>

using namespace pkcs15;
using namespace pkcs15::test_vectors;

// =============================================================================
// parseODF tests
// =============================================================================

TEST(ParseODF, FullODF)
{
    auto odf = parseODF(SAMPLE_ODF);
    EXPECT_EQ(odf.privateKeysPath, (std::vector<uint8_t>{0x44, 0x00}));
    EXPECT_EQ(odf.publicKeysPath, (std::vector<uint8_t>{0x44, 0x01}));
    EXPECT_EQ(odf.trustedPublicKeysPath, (std::vector<uint8_t>{0x44, 0x02}));
    EXPECT_EQ(odf.secretKeysPath, (std::vector<uint8_t>{0x44, 0x03}));
    EXPECT_EQ(odf.certificatesPath, (std::vector<uint8_t>{0x44, 0x04}));
    EXPECT_EQ(odf.trustedCertificatesPath, (std::vector<uint8_t>{0x44, 0x05}));
    EXPECT_EQ(odf.usefulCertificatesPath, (std::vector<uint8_t>{0x44, 0x06}));
    EXPECT_EQ(odf.dataObjectsPath, (std::vector<uint8_t>{0x44, 0x07}));
    EXPECT_EQ(odf.authObjectsPath, (std::vector<uint8_t>{0x44, 0x08}));
}

TEST(ParseODF, EmptyInput)
{
    auto odf = parseODF({});
    EXPECT_TRUE(odf.privateKeysPath.empty());
    EXPECT_TRUE(odf.authObjectsPath.empty());
}

TEST(ParseODF, ZeroPadding)
{
    // ODF followed by zero-padding (simulates fixed-size card file)
    std::vector<uint8_t> padded(SAMPLE_ODF.begin(), SAMPLE_ODF.end());
    padded.resize(padded.size() + 64, 0x00);
    auto odf = parseODF(padded);
    EXPECT_EQ(odf.privateKeysPath, (std::vector<uint8_t>{0x44, 0x00}));
    EXPECT_EQ(odf.authObjectsPath, (std::vector<uint8_t>{0x44, 0x08}));
}

TEST(ParseODF, PartialODF)
{
    // Only privateKeys and certificates entries
    constexpr std::array<uint8_t, 16> partial = {
        0xA0, 0x06, 0x30, 0x04, 0x04, 0x02, 0x44, 0x00, 0xA4, 0x06, 0x30, 0x04, 0x04, 0x02, 0x44, 0x04,
    };
    auto odf = parseODF(partial);
    EXPECT_EQ(odf.privateKeysPath, (std::vector<uint8_t>{0x44, 0x00}));
    EXPECT_EQ(odf.certificatesPath, (std::vector<uint8_t>{0x44, 0x04}));
    EXPECT_TRUE(odf.publicKeysPath.empty());
    EXPECT_TRUE(odf.authObjectsPath.empty());
}

TEST(ParseODF, UnknownTagSkipped)
{
    // An unknown context tag (0xA9) should be silently skipped
    constexpr std::array<uint8_t, 16> withUnknown = {
        0xA9, 0x06, 0x30, 0x04, 0x04, 0x02, 0xFF, 0xFF, // unknown tag
        0xA0, 0x06, 0x30, 0x04, 0x04, 0x02, 0x44, 0x00, // privateKeys
    };
    auto odf = parseODF(withUnknown);
    EXPECT_EQ(odf.privateKeysPath, (std::vector<uint8_t>{0x44, 0x00}));
}

TEST(ParseODF, Malformed)
{
    // First byte 0x55 is not a valid ODF context tag, but parseBER will parse it
    // as a primitive TLV. The parser should skip unknown tags, not crash.
    constexpr std::array<uint8_t, 4> malformed = {0x55, 0x02, 0x00, 0x00};
    auto odf = parseODF(malformed);
    EXPECT_TRUE(odf.privateKeysPath.empty());
}

// =============================================================================
// parseTokenInfo tests
// =============================================================================

TEST(ParseTokenInfo, FullTokenInfo)
{
    auto info = parseTokenInfo(SAMPLE_TOKEN_INFO);
    EXPECT_EQ(info.serialNumber, "T00000083");
    EXPECT_EQ(info.manufacturer, "SSCDv1 PACE MD");
    EXPECT_EQ(info.label, "eID V4.0");
}

TEST(ParseTokenInfo, EmptyInput)
{
    auto info = parseTokenInfo({});
    EXPECT_TRUE(info.label.empty());
    EXPECT_TRUE(info.serialNumber.empty());
    EXPECT_TRUE(info.manufacturer.empty());
}

TEST(ParseTokenInfo, MinimalTokenInfo)
{
    // Just version + serialNumber, no optional fields
    constexpr std::array<uint8_t, 16> minimal = {
        0x30, 0x0E,                                                       // SEQUENCE
        0x02, 0x01, 0x00,                                                 // INTEGER 0
        0x04, 0x09, 0x54, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x38, 0x33, // OCTET STRING "T00000083"
    };
    auto info = parseTokenInfo(minimal);
    EXPECT_EQ(info.serialNumber, "T00000083");
    EXPECT_TRUE(info.manufacturer.empty());
    EXPECT_TRUE(info.label.empty());
}

// =============================================================================
// parseCDF tests
// =============================================================================

TEST(ParseCDF, FullCDF)
{
    auto certs = parseCDF(SAMPLE_CDF);
    ASSERT_EQ(certs.size(), 4u);

    // Cert 0
    EXPECT_EQ(certs[0].label, "Intermediate Sign cert");
    EXPECT_TRUE(certs[0].authority);
    EXPECT_EQ(certs[0].id, (std::vector<uint8_t>{0x15, 0xB8, 0x12, 0xE9}));
    EXPECT_EQ(certs[0].path, (std::vector<uint8_t>{0x3F, 0x00, 0x50, 0x15, 0x44, 0x09}));

    // Cert 1
    EXPECT_EQ(certs[1].label, "Intermediate Auth cert");
    EXPECT_TRUE(certs[1].authority);
    EXPECT_EQ(certs[1].id, (std::vector<uint8_t>{0xF0, 0x3E, 0x78, 0xBB}));
    EXPECT_EQ(certs[1].path, (std::vector<uint8_t>{0x3F, 0x00, 0x50, 0x15, 0x44, 0x0A}));

    // Cert 2
    EXPECT_EQ(certs[2].label, "Sign");
    EXPECT_FALSE(certs[2].authority);
    EXPECT_EQ(certs[2].id, (std::vector<uint8_t>{0x4F, 0x79, 0x7B, 0x48}));
    EXPECT_EQ(certs[2].path, (std::vector<uint8_t>{0x3F, 0x00, 0x0D, 0xF5, 0x01, 0x15}));

    // Cert 3
    EXPECT_EQ(certs[3].label, "Auth");
    EXPECT_FALSE(certs[3].authority);
    EXPECT_EQ(certs[3].id, (std::vector<uint8_t>{0x26, 0xDA, 0xF7, 0x50}));
    EXPECT_EQ(certs[3].path, (std::vector<uint8_t>{0x3F, 0x00, 0x50, 0x15, 0x44, 0x0C}));
}

TEST(ParseCDF, EmptyInput)
{
    auto certs = parseCDF({});
    EXPECT_TRUE(certs.empty());
}

TEST(ParseCDF, ZeroPadding)
{
    std::vector<uint8_t> padded(SAMPLE_CDF.begin(), SAMPLE_CDF.end());
    padded.resize(padded.size() + 128, 0x00);
    auto certs = parseCDF(padded);
    ASSERT_EQ(certs.size(), 4u);
    EXPECT_EQ(certs[0].label, "Intermediate Sign cert");
}

// =============================================================================
// parsePrKDF tests
// =============================================================================

TEST(ParsePrKDF, FullPrKDF)
{
    auto keys = parsePrKDF(SAMPLE_PRKDF);
    ASSERT_EQ(keys.size(), 2u);

    // Key 0: Sign Key
    EXPECT_EQ(keys[0].label, "Sign Key");
    EXPECT_EQ(keys[0].id, (std::vector<uint8_t>{0x4F, 0x79, 0x7B, 0x48}));
    EXPECT_EQ(keys[0].keySizeBits, 3072u);
    EXPECT_EQ(keys[0].path, (std::vector<uint8_t>{0x3F, 0x00, 0x0D, 0xF5, 0x01, 0x16}));

    // Key 1: Auth Key
    EXPECT_EQ(keys[1].label, "Auth Key");
    EXPECT_EQ(keys[1].id, (std::vector<uint8_t>{0x26, 0xDA, 0xF7, 0x50}));
    EXPECT_EQ(keys[1].keySizeBits, 3072u);
    EXPECT_EQ(keys[1].path, (std::vector<uint8_t>{0x3F, 0x00, 0x50, 0x15, 0x44, 0x0D}));
}

TEST(ParsePrKDF, EmptyInput)
{
    auto keys = parsePrKDF({});
    EXPECT_TRUE(keys.empty());
}

TEST(ParsePrKDF, ZeroPadding)
{
    std::vector<uint8_t> padded(SAMPLE_PRKDF.begin(), SAMPLE_PRKDF.end());
    padded.resize(padded.size() + 64, 0x00);
    auto keys = parsePrKDF(padded);
    ASSERT_EQ(keys.size(), 2u);
    EXPECT_EQ(keys[0].label, "Sign Key");
}

TEST(ParsePrKDF, CertKeyIdPairing)
{
    // Verify that key IDs match corresponding certificate IDs
    auto keys = parsePrKDF(SAMPLE_PRKDF);
    auto certs = parseCDF(SAMPLE_CDF);

    // Sign Key id should match Sign cert id
    EXPECT_EQ(keys[0].id, certs[2].id);
    // Auth Key id should match Auth cert id
    EXPECT_EQ(keys[1].id, certs[3].id);
}

// =============================================================================
// parseAODF tests
// =============================================================================

TEST(ParseAODF, FullAODF)
{
    auto pins = parseAODF(SAMPLE_AODF);
    ASSERT_EQ(pins.size(), 4u);

    // PIN 0: PACE CAN
    EXPECT_EQ(pins[0].label, "PACE CAN");
    EXPECT_EQ(pins[0].pinReference, 0x02);
    EXPECT_EQ(pins[0].pinType, PinType::Utf8);
    EXPECT_EQ(pins[0].minLength, 4);
    EXPECT_EQ(pins[0].storedLength, 12);
    EXPECT_EQ(pins[0].maxLength, 12);
    EXPECT_EQ(pins[0].path, (std::vector<uint8_t>{0x3F, 0x00}));
    EXPECT_FALSE(pins[0].local);
    EXPECT_TRUE(pins[0].initialized);

    // PIN 1: User PIN
    EXPECT_EQ(pins[1].label, "User PIN");
    EXPECT_EQ(pins[1].pinReference, 0x86);
    EXPECT_EQ(pins[1].pinType, PinType::Ascii);
    EXPECT_EQ(pins[1].minLength, 6);
    EXPECT_EQ(pins[1].storedLength, 6);
    EXPECT_EQ(pins[1].maxLength, 6);
    EXPECT_EQ(pins[1].path, (std::vector<uint8_t>{0x3F, 0x00}));
    EXPECT_TRUE(pins[1].local);
    EXPECT_TRUE(pins[1].initialized);

    // PIN 2: Global PUK
    EXPECT_EQ(pins[2].label, "Global PUK");
    EXPECT_EQ(pins[2].pinReference, 0x93);
    EXPECT_EQ(pins[2].pinType, PinType::Ascii);
    EXPECT_EQ(pins[2].minLength, 8);
    EXPECT_EQ(pins[2].storedLength, 8);
    EXPECT_EQ(pins[2].maxLength, 8);
    EXPECT_EQ(pins[2].path, (std::vector<uint8_t>{0x3F, 0x00}));
    EXPECT_FALSE(pins[2].local);
    EXPECT_TRUE(pins[2].initialized);

    // PIN 3: Signature PIN
    EXPECT_EQ(pins[3].label, "Signature PIN");
    EXPECT_EQ(pins[3].pinReference, 0x92);
    EXPECT_EQ(pins[3].pinType, PinType::Ascii);
    EXPECT_EQ(pins[3].minLength, 6);
    EXPECT_EQ(pins[3].storedLength, 6);
    EXPECT_EQ(pins[3].maxLength, 6);
    EXPECT_EQ(pins[3].path, (std::vector<uint8_t>{0x3F, 0x00, 0x0D, 0xF5}));
    EXPECT_TRUE(pins[3].local);
    EXPECT_TRUE(pins[3].initialized);
}

TEST(ParseAODF, EmptyInput)
{
    auto pins = parseAODF({});
    EXPECT_TRUE(pins.empty());
}

TEST(ParseAODF, ZeroPadding)
{
    std::vector<uint8_t> padded(SAMPLE_AODF.begin(), SAMPLE_AODF.end());
    padded.resize(padded.size() + 128, 0x00);
    auto pins = parseAODF(padded);
    ASSERT_EQ(pins.size(), 4u);
    EXPECT_EQ(pins[0].label, "PACE CAN");
}
