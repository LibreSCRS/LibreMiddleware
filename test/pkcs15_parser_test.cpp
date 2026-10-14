// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <pkcs15_parser.h>

#include "fixtures/appletsuitegen1_aodf_20260718.h"
#include "fixtures/binary_serial_tokeninfo_20260820.h"
#include "fixtures/ec_prkdf_20260820.h"
#include "fixtures/ec_pukdf_20260820.h"
#include "fixtures/rs_eid_ec_prkdf_20260903.h"
#include "pkcs15_test_vectors.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <limits>
#include <span>
#include <string>
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

TEST(ParseAODF, GemaltoToken_UserPin)
{
    auto pins = parseAODF(GEMALTO_AODF);
    ASSERT_GE(pins.size(), 2u);
    const auto& pin = pins[0];
    EXPECT_EQ(pin.label, "User Pin");
    EXPECT_EQ(pin.pinReference, 0x03);
    EXPECT_EQ(pin.pinType, PinType::Ascii);
    EXPECT_EQ(pin.minLength, 4);
    EXPECT_EQ(pin.storedLength, 15);
    EXPECT_FALSE(pin.hasMaxLength);
    EXPECT_EQ(pin.maxLength, 0);
    EXPECT_EQ(pin.padChar, 0x00);
    EXPECT_EQ(pin.lastPinChange, "20210302064541Z");
    EXPECT_EQ(pin.path, (std::vector<uint8_t>{0x3F, 0x00}));
    EXPECT_TRUE(pin.local);
    EXPECT_TRUE(pin.initialized);
}

TEST(ParseAODF, GemaltoToken_SOPin)
{
    auto pins = parseAODF(GEMALTO_AODF);
    ASSERT_GE(pins.size(), 2u);
    const auto& pin = pins[1];
    EXPECT_EQ(pin.label, "SO Pin");
    EXPECT_EQ(pin.pinReference, 0x01);
    EXPECT_EQ(pin.pinType, PinType::Ascii);
    EXPECT_EQ(pin.minLength, 4);
    EXPECT_EQ(pin.storedLength, 15);
    EXPECT_FALSE(pin.hasMaxLength);
    EXPECT_EQ(pin.padChar, 0x00);
    EXPECT_EQ(pin.lastPinChange, "20210302064541Z");
}

TEST(ParseAODF, GemaltoToken_ChallengeResponseKey)
{
    // The CRK object uses [1] CONSTRUCTED (0xA1) at the top level, not SEQUENCE.
    // The AODF parser only extracts SEQUENCE (0x30) entries as PinInfo objects,
    // so the CRK is correctly skipped — only User Pin and SO Pin are returned.
    auto pins = parseAODF(GEMALTO_AODF);
    ASSERT_EQ(pins.size(), 2u);
}

TEST(ParseAODF, AppletSuiteGen1Aodf_HasMaxLength)
{
    auto pins = parseAODF(SAMPLE_AODF);
    ASSERT_EQ(pins.size(), 4u);
    EXPECT_TRUE(pins[0].hasMaxLength);
    EXPECT_EQ(pins[0].maxLength, 12);
    EXPECT_TRUE(pins[1].hasMaxLength);
    EXPECT_EQ(pins[1].maxLength, 6);
}

TEST(ParseAODF, LifecycleEvidenceFields)
{
    // Hardware-scanned AppletSuiteGen1 EF.AODF: soPin (pinFlags 0x01) and
    // change-disabled (pinFlags 0x20) bits, plus the protecting-object
    // authId from CommonObjectAttributes (the unblock-authority chain).
    // The accessControlRules' nested OCTET STRINGs must NOT be mistaken
    // for the authId.
    auto pins = parseAODF(LibreSCRS::test::fixtures::kAppletSuiteGen1Aodf20260718);
    ASSERT_EQ(pins.size(), 4u);

    // PACE CAN: change-disabled + unblock-disabled; no protecting object.
    EXPECT_TRUE(pins[0].changeDisabled);
    EXPECT_TRUE(pins[0].unblockDisabled);
    EXPECT_FALSE(pins[0].soPin);
    EXPECT_TRUE(pins[0].authId.empty());
    EXPECT_EQ(pins[0].id, (std::vector<uint8_t>{0x02}));

    // User PIN: protected/unblocked by object 0x03 (the Global PUK).
    EXPECT_FALSE(pins[1].soPin);
    EXPECT_FALSE(pins[1].changeDisabled);
    EXPECT_EQ(pins[1].authId, (std::vector<uint8_t>{0x03}));
    EXPECT_EQ(pins[1].id, (std::vector<uint8_t>{0x06}));

    // Global PUK: soPin + unblock-disabled; own id 0x03; not protected by
    // anything (CommonObjectAttributes carries no authId).
    EXPECT_TRUE(pins[2].soPin);
    EXPECT_TRUE(pins[2].unblockDisabled);
    EXPECT_FALSE(pins[2].changeDisabled);
    EXPECT_TRUE(pins[2].authId.empty());
    EXPECT_EQ(pins[2].id, (std::vector<uint8_t>{0x03}));

    // Signature PIN: chained to the same PUK object.
    EXPECT_FALSE(pins[3].soPin);
    EXPECT_EQ(pins[3].authId, (std::vector<uint8_t>{0x03}));
    EXPECT_EQ(pins[3].id, (std::vector<uint8_t>{0x22}));
}

// =============================================================================
// EC private keys — the PrivateKeyType CHOICE
// =============================================================================

// PrivateKeyType is a CHOICE: privateRSAKey is the untagged SEQUENCE, and
// privateECKey is [0]. A reader that accepts only the untagged form drops
// every EC key without a word, and an empty key list reads downstream as "this
// card has no keys" rather than as a parse that refused what it was given. On
// a card whose only key is EC that is the whole PKCS#11 surface: no keys means
// no certificate is published either (a certificate is only published against
// a retained key), so the slot answers empty for objects AND mechanisms while
// the token itself enumerates perfectly.
TEST(ParsePrKDF, KeepsAnEcPrivateKeyRecord)
{
    const auto keys = parsePrKDF(EC_PRKDF_SINGLE_KEY);

    ASSERT_EQ(keys.size(), 1U) << "a [0] privateECKey record is a key, not noise";
    EXPECT_EQ(keys[0].label, "34b8bc40-4afc-4c45-be0f-8524fc10d80f");
    EXPECT_EQ(keys[0].id, (std::vector<uint8_t>{0x34, 0xB8, 0xBC, 0x40, 0x4A, 0xFC, 0x4C, 0x45, 0xBE, 0x0F, 0x85, 0x24,
                                                0xFC, 0x10, 0xD8, 0x0F}));
    EXPECT_EQ(keys[0].authId, (std::vector<uint8_t>{0x06}));
    EXPECT_EQ(keys[0].keyReference, 0x47);
    EXPECT_EQ(keys[0].path, (std::vector<uint8_t>{0x3F, 0x00, 0x50, 0x15}));
    EXPECT_TRUE(keys[0].canSign);
}

// The type has to come from the OUTER CHOICE tag. typeAttributes is [1] for
// BOTH key types under ISO 7816-15, so "it has a [1], therefore RSA" labels
// this EC record RSA -- a parser that merely stopped dropping the record would
// pass every assertion above and still hand the PKCS#11 layer the wrong key
// type, wrong mechanisms and a modulus length for a curve.
TEST(ParsePrKDF, EcKeyTypeComesFromTheChoiceTagNotTheTypeAttributes)
{
    const auto keys = parsePrKDF(EC_PRKDF_SINGLE_KEY);

    ASSERT_EQ(keys.size(), 1U);
    EXPECT_EQ(keys[0].keyType, KeyType::Ec);
    // ECPrivateKeyAttributes carries no modulusLength, so an absent size here
    // is conformant -- and must not be back-filled from an RSA assumption.
    EXPECT_EQ(keys[0].keySizeBits, 0);
}

// CommonObjectAttributes carries userConsent: how many times the holder must
// consent before the key is used. A card that sets it wants the PIN presented
// per operation, and PKCS#11 spells exactly that as CKA_ALWAYS_AUTHENTICATE.
// Dropping it produces a token that looks usable, logs in once, and then has
// its second signature refused by the card with nothing in the client able to
// explain why.
TEST(ParsePrKDF, EcKeyCarriesUserConsent)
{
    const auto keys = parsePrKDF(EC_PRKDF_SINGLE_KEY);

    ASSERT_EQ(keys.size(), 1U);
    EXPECT_EQ(keys[0].userConsent, 1U);
}

// Absent userConsent is the common case and means no per-operation consent --
// it must read as 0, never as a defaulted 1 that would make every ordinary
// card demand a PIN it never asked for.
TEST(ParsePrKDF, AbsentUserConsentIsZero)
{
    const auto keys = parsePrKDF(SAMPLE_PRKDF);

    ASSERT_FALSE(keys.empty());
    for (const auto& key : keys) {
        EXPECT_EQ(key.userConsent, 0U) << "key '" << key.label << "'";
    }
}

namespace {

std::vector<uint8_t> tlv(uint8_t tag, const std::vector<uint8_t>& content)
{
    std::vector<uint8_t> out{tag, static_cast<uint8_t>(content.size())};
    out.insert(out.end(), content.begin(), content.end());
    return out;
}

// One RSA PrKDF record -- id 01, key file 3F00/4410 -- around the given
// CommonObjectAttributes content, so each test varies only that member.
std::vector<uint8_t> rsaKeyWithCommonObjectAttributes(const std::vector<uint8_t>& commonObjectAttributes)
{
    std::vector<uint8_t> body = tlv(0x30, commonObjectAttributes);
    const std::vector<uint8_t> rest = {0x30, 0x03, 0x04, 0x01, 0x01,                               // id 01
                                       0xA1, 0x0C, 0x30, 0x0A, 0x30, 0x08, 0x04, 0x04, 0x3F, 0x00, // path
                                       0x44, 0x10, 0x02, 0x00};
    body.insert(body.end(), rest.begin(), rest.end());
    return tlv(0x30, body);
}

// CommonObjectAttributes content: label "KEY" followed by @p tail.
std::vector<uint8_t> labelledKeyThen(const std::vector<uint8_t>& tail)
{
    std::vector<uint8_t> out = {0x0C, 0x03, 0x4B, 0x45, 0x59};
    out.insert(out.end(), tail.begin(), tail.end());
    return out;
}

} // namespace

// 256 is encoded 01 00. Its last octet alone is zero, which reads as "no
// consent needed" -- the one wrong answer here that fails open.
TEST(ParsePrKDF, UserConsentIsReadAsAWholeInteger)
{
    const auto keys = parsePrKDF(rsaKeyWithCommonObjectAttributes(labelledKeyThen({0x02, 0x02, 0x01, 0x00})));

    ASSERT_EQ(keys.size(), 1U);
    EXPECT_EQ(keys[0].userConsent, 256U);
    EXPECT_TRUE(requiresPerOperationAuth(keys[0]));
}

// Every CommonObjectAttributes member is OPTIONAL, the label included. The
// INTEGER is the only one of its type there, so it needs no label to anchor
// it; a record without one must still say the card wants its PIN.
TEST(ParsePrKDF, UserConsentWithoutALabelIsStillRead)
{
    const auto keys = parsePrKDF(rsaKeyWithCommonObjectAttributes({0x04, 0x01, 0x01, 0x02, 0x01, 0x01}));

    ASSERT_EQ(keys.size(), 1U);
    EXPECT_EQ(keys[0].userConsent, 1U);
    EXPECT_TRUE(requiresPerOperationAuth(keys[0]));
}

TEST(ParsePrKDF, ZeroUserConsentDoesNotAskForThePin)
{
    const auto keys = parsePrKDF(rsaKeyWithCommonObjectAttributes(labelledKeyThen({0x02, 0x01, 0x00})));

    ASSERT_EQ(keys.size(), 1U);
    EXPECT_EQ(keys[0].userConsent, 0U);
    EXPECT_FALSE(requiresPerOperationAuth(keys[0]));
}

// Five octets do not fit the field. Refusing them as "absent" -- what the
// other INTEGER fields in this parser do -- would turn an over-wide consent
// count into "no PIN needed"; it saturates instead.
TEST(ParsePrKDF, OverWideUserConsentStaysNonZero)
{
    const auto keys =
        parsePrKDF(rsaKeyWithCommonObjectAttributes(labelledKeyThen({0x02, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00})));

    ASSERT_EQ(keys.size(), 1U);
    EXPECT_EQ(keys[0].userConsent, std::numeric_limits<uint32_t>::max());
    EXPECT_TRUE(requiresPerOperationAuth(keys[0]));
}

// Encodings a reader can get wrong while every everyday value still passes.
// userConsent is (1..ub), so a card never means "no consent" by any of them;
// each must keep the key asking for its PIN.
struct UserConsentEncoding
{
    const char* name;
    std::vector<uint8_t> integer; // the whole INTEGER TLV
    uint32_t expected;
};

class UserConsentEncodingTest : public ::testing::TestWithParam<UserConsentEncoding>
{};

TEST_P(UserConsentEncodingTest, StaysNonZero)
{
    const auto keys = parsePrKDF(rsaKeyWithCommonObjectAttributes(labelledKeyThen(GetParam().integer)));

    ASSERT_EQ(keys.size(), 1U);
    EXPECT_EQ(keys[0].userConsent, GetParam().expected);
    EXPECT_TRUE(requiresPerOperationAuth(keys[0]));
}

INSTANTIATE_TEST_SUITE_P(ParsePrKDF, UserConsentEncodingTest,
                         ::testing::Values(
                             // A leading 00 keeps 128 positive; dropping or trusting that octet alone reads 0.
                             UserConsentEncoding{"LeadingZeroOctet", {0x02, 0x02, 0x00, 0x80}, 128U},
                             // High bit set: a signed reader sees -1, and clamping that to 0 fails open.
                             UserConsentEncoding{"HighBitOctet", {0x02, 0x01, 0xFF}, 255U},
                             // Present but empty: no value to read, yet the card put the member there.
                             // Skipping it reads as absent, so it saturates like an over-wide one.
                             UserConsentEncoding{"ZeroLength", {0x02, 0x00}, std::numeric_limits<uint32_t>::max()}),
                         [](const ::testing::TestParamInfo<UserConsentEncoding>& info) {
                             return std::string(info.param.name);
                         });

// A malformed record with two INTEGERs must not let the later one cancel the
// earlier: the larger consent count wins, never simply the last one read.
TEST(ParsePrKDF, RepeatedUserConsentKeepsTheLargest)
{
    const auto keys =
        parsePrKDF(rsaKeyWithCommonObjectAttributes(labelledKeyThen({0x02, 0x01, 0x01, 0x02, 0x01, 0x00})));

    ASSERT_EQ(keys.size(), 1U);
    EXPECT_EQ(keys[0].userConsent, 1U);
    EXPECT_TRUE(requiresPerOperationAuth(keys[0]));
}

// The rule both readers share, against the scanned cards: the EC key asks for
// its PIN per operation, the sample RSA keys do not.
TEST(PerOperationAuth, FollowsTheScannedCards)
{
    const auto ecKeys = parsePrKDF(EC_PRKDF_SINGLE_KEY);
    ASSERT_EQ(ecKeys.size(), 1U);
    EXPECT_TRUE(requiresPerOperationAuth(ecKeys[0]));

    for (const auto& key : parsePrKDF(SAMPLE_PRKDF)) {
        EXPECT_FALSE(requiresPerOperationAuth(key)) << "key '" << key.label << "'";
    }
}

// =============================================================================
// KeyUsageFlags derive, and the handle a plugin hands out for a key
// =============================================================================

namespace {

// One [0] privateECKey record (id 01) in DF 3F00/5015, addressed by
// @p keyReference, with @p usageBits as the KeyUsageFlags BIT STRING content.
std::vector<uint8_t> ecKeyRecord(uint8_t keyReference, const std::vector<uint8_t>& usageBits)
{
    std::vector<uint8_t> keyAttributes = {0x04, 0x01, 0x01};
    const auto usage = tlv(0x03, usageBits);
    keyAttributes.insert(keyAttributes.end(), usage.begin(), usage.end());
    keyAttributes.insert(keyAttributes.end(), {0x02, 0x01, keyReference});

    std::vector<uint8_t> body = tlv(0x30, {0x0C, 0x03, 0x4B, 0x45, 0x59}); // label "KEY"
    const auto attributes = tlv(0x30, keyAttributes);
    body.insert(body.end(), attributes.begin(), attributes.end());
    body.insert(body.end(), {0xA1, 0x0A, 0x30, 0x08, 0x30, 0x06, 0x04, 0x04, 0x3F, 0x00, 0x50, 0x15});
    return tlv(0xA0, body);
}

} // namespace

// The scanned key allows derive (bit 8, 0x80 of the third byte) next to a bit
// 15 PKCS#15 does not define. Derive is read; the undefined bit changes nothing.
TEST(ParsePrKDF, ScannedEcKeyAllowsDerive)
{
    const auto keys = parsePrKDF(RS_EID_EC_PRKDF);

    ASSERT_EQ(keys.size(), 1U);
    EXPECT_EQ(keys[0].keyType, KeyType::Ec);
    EXPECT_TRUE(keys[0].canDerive);
    EXPECT_TRUE(keys[0].canSign);
    EXPECT_EQ(keys[0].keyReference, 0x47);
    EXPECT_EQ(keys[0].userConsent, 1U);
    EXPECT_EQ(keys[0].id.size(), 16U);
}

TEST(ParsePrKDF, UsageWithoutTheDeriveBitDoesNotDerive)
{
    const auto twoBytes = parsePrKDF(EC_PRKDF_SINGLE_KEY); // usage 02 64: no third byte at all
    ASSERT_EQ(twoBytes.size(), 1U);
    EXPECT_FALSE(twoBytes[0].canDerive);

    const auto bit15Only = parsePrKDF(ecKeyRecord(0x47, {0x00, 0x64, 0x01}));
    ASSERT_EQ(bit15Only.size(), 1U);
    EXPECT_FALSE(bit15Only[0].canDerive) << "bit 15 is not derive";
}

// The unused-bits count (first content byte, at most 7) can only cover the low
// bits of the last byte, never its MSB -- which is where derive sits.
TEST(ParsePrKDF, DeriveIsReadWhateverTheUnusedBitCount)
{
    const auto keys = parsePrKDF(ecKeyRecord(0x47, {0x07, 0x00, 0x80}));

    ASSERT_EQ(keys.size(), 1U);
    EXPECT_TRUE(keys[0].canDerive);
    EXPECT_FALSE(keys[0].canSign);
}

// The card command selects a key by its reference when the PrKDF carries one
// (resolveKeyRef); the handle a plugin hands out follows the same choice.
TEST(KeyHandle, KeyReferenceComesFirst)
{
    const auto keys = parsePrKDF(RS_EID_EC_PRKDF);

    ASSERT_EQ(keys.size(), 1U);
    EXPECT_EQ(keyHandle(keys[0]), std::uint16_t{0x47}) << "not 5015, the DF the key lives in";
}

TEST(KeyHandle, KeyFileWithoutAReferenceKeepsItsPath)
{
    const auto keys = parsePrKDF(rsaKeyWithCommonObjectAttributes({0x0C, 0x03, 0x4B, 0x45, 0x59}));

    ASSERT_EQ(keys.size(), 1U);
    ASSERT_EQ(keys[0].keyReference, 0);
    EXPECT_EQ(keyHandle(keys[0]), std::uint16_t{0x4410});
}

TEST(KeyHandle, NeitherReferenceNorPathIsOne)
{
    PrivateKeyInfo bare;
    EXPECT_EQ(keyHandle(bare), std::uint16_t{1});
    bare.path = {0x44};
    EXPECT_EQ(keyHandle(bare), std::uint16_t{1}) << "one path byte names no file";
}

// Two keys in one DF share every path byte; only their references tell them
// apart. A handle taken from the path first gave both 5015.
TEST(KeyHandle, TwoKeysInOneDfStayApart)
{
    auto prkdf = ecKeyRecord(0x47, {0x00, 0x64});
    const auto second = ecKeyRecord(0x48, {0x00, 0x64});
    prkdf.insert(prkdf.end(), second.begin(), second.end());
    const auto keys = parsePrKDF(prkdf);

    ASSERT_EQ(keys.size(), 2U);
    ASSERT_EQ(keys[0].path, keys[1].path);
    EXPECT_EQ(keyHandle(keys[0]), std::uint16_t{0x47});
    EXPECT_EQ(keyHandle(keys[1]), std::uint16_t{0x48});
}

// A serialNumber is an OCTET STRING, and nothing says its bytes are text. This
// card's carries a nested ISO 7816 `84` TLV around its ICCSN, so reading it as
// characters yields unprintable bytes -- which then travel: into
// CK_TOKEN_INFO.serialNumber, into the `serial` field of every pkcs11: URI the
// token publishes, and into generated documentation, where a single binary
// byte makes the whole file invalid UTF-8.
TEST(ParseTokenInfo, BinarySerialIsHexEncodedNotPassedThroughAsText)
{
    const auto info = parseTokenInfo(BINARY_SERIAL_TOKENINFO);

    // The ICCSN itself, unwrapped from the `84` TLV -- the same eight bytes
    // EF.D003 returns on this card.
    EXPECT_EQ(info.serialNumber, "2077B202775C2B10");
    EXPECT_EQ(info.manufacturer, "cv cryptovision gmbh (c) v1.1j");
    EXPECT_EQ(info.label, "SSCDv1 PACE MD");

    // Whatever the encoding, the result has to be safe to put in a URI and in
    // a UTF-8 document.
    for (const unsigned char c : info.serialNumber) {
        EXPECT_GE(c, 0x20) << "a serial that reaches a pkcs11: URI must be printable";
        EXPECT_LT(c, 0x7F);
    }
}

// A printable serial is text and must stay EXACTLY as it reads -- hex-encoding
// one would change the identity every existing consumer already matches on.
TEST(ParseTokenInfo, PrintableSerialIsLeftAlone)
{
    const auto info = parseTokenInfo(SAMPLE_TOKEN_INFO);
    EXPECT_EQ(info.serialNumber, "T00000083");
}

// =============================================================================
// parsePuKDF
// =============================================================================

// PublicKeyType is the same CHOICE shape as PrivateKeyType, with the same
// trap: publicRSAKey untagged, publicECKey [0]. The public key is the only
// source of CKA_EC_PARAMS / CKA_EC_POINT that does not require parsing a
// certificate, so a reader that drops it forces the slot to pay a card read
// for something the profile already had.
TEST(ParsePuKDF, KeepsAnEcPublicKeyRecord)
{
    const auto keys = parsePuKDF(EC_PUKDF_SINGLE_KEY);

    ASSERT_EQ(keys.size(), 1U);
    EXPECT_EQ(keys[0].keyType, KeyType::Ec);
    EXPECT_EQ(keys[0].label, "34b8bc40-4afc-4c45-be0f-8524fc10d80f");
    // The SAME id the private key carries -- that pairing is the whole point.
    EXPECT_EQ(keys[0].id, (std::vector<uint8_t>{0x34, 0xB8, 0xBC, 0x40, 0x4A, 0xFC, 0x4C, 0x45, 0xBE, 0x0F, 0x85, 0x24,
                                                0xFC, 0x10, 0xD8, 0x0F}));
    EXPECT_EQ(keys[0].keyReference, 0x47);
    EXPECT_EQ(keys[0].path, (std::vector<uint8_t>{0x3F, 0x00, 0x50, 0x15, 0x44, 0x0D}));
}

// The pairing has to hold across the two directories, since that is what the
// PKCS#11 layer matches a certificate, a private key and its public half on.
TEST(ParsePuKDF, PublicAndPrivateRecordsShareTheirIdentifier)
{
    const auto priv = parsePrKDF(EC_PRKDF_SINGLE_KEY);
    const auto pub = parsePuKDF(EC_PUKDF_SINGLE_KEY);

    ASSERT_EQ(priv.size(), 1U);
    ASSERT_EQ(pub.size(), 1U);
    EXPECT_EQ(priv[0].id, pub[0].id);
    EXPECT_EQ(priv[0].keyReference, pub[0].keyReference);
}

TEST(ParsePuKDF, EmptyInput)
{
    EXPECT_TRUE(parsePuKDF({}).empty());
}

// =============================================================================
// parseDODF
// =============================================================================

// The DODF is where a card advertises its data containers -- on the bench
// card that means the MS-minidriver set (cardid, mscp\cmapfile), whose
// cmapfile carries the key size independently of any certificate. The parser
// lifts label, applicationName, applicationOID (raw) and path; it decodes
// nothing further -- the consumer decides what a container means.
TEST(ParseDODF, LiftsOpaqueMinidriverObjects)
{
    const auto objs = parseDODF(MSCP_DODF);

    ASSERT_EQ(objs.size(), 3U);
    EXPECT_EQ(objs[0].label, "cardid");
    EXPECT_EQ(objs[0].applicationName, "mscp");
    EXPECT_TRUE(objs[0].applicationOid.empty());
    EXPECT_EQ(objs[0].path, (std::vector<uint8_t>{0x63, 0x77}));

    EXPECT_EQ(objs[1].label, "cmapfile");
    EXPECT_EQ(objs[1].applicationName, "mscp");
    EXPECT_EQ(objs[1].path, (std::vector<uint8_t>{0x57, 0x03}));
}

// oidDO is the [1] alternative of the DataType CHOICE -- the same outer-tag
// discrimination the key parsers already learned the hard way.
TEST(ParseDODF, OidDoComesFromTheChoiceTag)
{
    const auto objs = parseDODF(MSCP_DODF);

    ASSERT_EQ(objs.size(), 3U);
    EXPECT_EQ(objs[2].label, "oiddata");
    EXPECT_EQ(objs[2].applicationOid, (std::vector<uint8_t>{0x55, 0x04, 0x03}));
    EXPECT_EQ(objs[2].path, (std::vector<uint8_t>{0x57, 0x04}));
}

TEST(ParseDODF, EmptyInput)
{
    EXPECT_TRUE(parseDODF({}).empty());
}

// =============================================================================
// INTEGER length: the card chooses it, and DER permits more than eight octets.
//
// These build the smallest AODF that reaches the PinAttributes INTEGER fields,
// so the only thing that varies between the cases is the encoding of one
// INTEGER. The boundary case is here on purpose: a refusal written `>= 8`
// instead of `> 8` would reject a legitimate eight-octet value and no
// over-length case would notice.
// =============================================================================
namespace {

std::vector<uint8_t> aodfWithMinLength(const std::vector<uint8_t>& minLenInteger)
{
    std::vector<uint8_t> pinAttrs{
        0x03, 0x02, 0x00, 0x40, // BIT STRING pinFlags (local)
        0x0A, 0x01, 0x01,       // ENUMERATED pinType
    };
    pinAttrs.push_back(0x02); // INTEGER minLength
    pinAttrs.push_back(static_cast<uint8_t>(minLenInteger.size()));
    pinAttrs.insert(pinAttrs.end(), minLenInteger.begin(), minLenInteger.end());
    pinAttrs.insert(pinAttrs.end(), {0x02, 0x01, 0x08}); // INTEGER storedLength
    pinAttrs.insert(pinAttrs.end(), {0x02, 0x01, 0x0C}); // INTEGER maxLength

    std::vector<uint8_t> typeAttrs{0x30, static_cast<uint8_t>(pinAttrs.size())};
    typeAttrs.insert(typeAttrs.end(), pinAttrs.begin(), pinAttrs.end());

    std::vector<uint8_t> entry{
        0x30, 0x05, 0x0C, 0x03, 'P',  'I', 'N', // CommonObjectAttributes
        0x30, 0x03, 0x04, 0x01, 0x01,           // CommonAuthObjectAttributes
    };
    entry.push_back(0xA1); // [1] typeAttributes
    entry.push_back(static_cast<uint8_t>(typeAttrs.size()));
    entry.insert(entry.end(), typeAttrs.begin(), typeAttrs.end());

    std::vector<uint8_t> out{0x30, static_cast<uint8_t>(entry.size())};
    out.insert(out.end(), entry.begin(), entry.end());
    return out;
}

} // namespace

TEST(ParseAODF, EightOctetIntegerIsStillDecoded)
{
    const auto aodf = aodfWithMinLength({0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08});
    const auto pins = parseAODF(aodf);

    ASSERT_EQ(pins.size(), 1U);
    EXPECT_EQ(pins[0].minLength, 8);
}

// Nine octets declaring 2^64 + 8. The ninth shift carries the leading octet
// straight off the top of the accumulator, so the value that came back was
// eight -- a plausible PIN length that the encoding does not carry, from bytes
// the card chose. Nothing reports it: since C++20 the shift is a defined wrap,
// not undefined behaviour, so no sanitizer sees it either.
TEST(ParseAODF, IntegerLongerThanTheAccumulatorIsRefused)
{
    const auto aodf = aodfWithMinLength({0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08});
    const auto pins = parseAODF(aodf);

    ASSERT_EQ(pins.size(), 1U);
    EXPECT_EQ(pins[0].minLength, 0);
}

// A negative INTEGER that does fit is decoded as it always was: the refusal is
// about width, not about sign.
TEST(ParseAODF, EightOctetIntegerWithTheTopBitSetKeepsItsSign)
{
    const auto aodf = aodfWithMinLength({0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xF8});
    const auto pins = parseAODF(aodf);

    ASSERT_EQ(pins.size(), 1U);
    EXPECT_EQ(pins[0].minLength, -8);
}

// A value that fits the accumulator but not the field it lands in. The caller
// used to narrow to `int`, so a card declaring 2^32 + 5 got a PIN minimum
// length of five: the same fault as the over-wide INTEGER, with the boundary
// moved from eight octets to four. The refusal is now the caller's, because the
// accumulator is not what these fields are.
TEST(ParseAODF, AnIntegerTooLargeForThePinFieldIsRefused)
{
    const auto aodf = aodfWithMinLength({0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x05}); // 2^32 + 5
    const auto pins = parseAODF(aodf);

    ASSERT_EQ(pins.size(), 1U);
    EXPECT_EQ(pins[0].minLength, 0);
}
