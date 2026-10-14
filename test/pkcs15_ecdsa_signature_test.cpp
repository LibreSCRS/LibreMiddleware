// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

// ECDSA replies as cards give them -- DER, SEQUENCE { r, s } with INTEGERs at
// the full field width, or raw r || s -- turned into the plugin contract's
// fixed-width r || s, and only when the result verifies. No card I/O; OpenSSL
// makes the keys and the signatures.

#include "ecdsa_signature.h"

#include "ec_test_key.h"

#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <random>
#include <span>
#include <vector>

namespace {

using LibreSCRS::TestSupport::ecdsaDer;
using LibreSCRS::TestSupport::ecdsaRawOf;
using LibreSCRS::TestSupport::EcTestKey;
using LibreSCRS::TestSupport::fixedWidthSequence;
using LibreSCRS::TestSupport::makeEcTestKey;
using pkcs15::EcdsaRawCheck;
using pkcs15::ecdsaRawFromCardReply;
using pkcs15::ecdsaRawVerifiesWithCertificate;

// The check the plugin passes: the candidate is a signature over @p hash by
// the public key in @p key's certificate.
EcdsaRawCheck checkedBy(const EcTestKey& key, std::span<const std::uint8_t> hash)
{
    return [&key, hash](std::span<const std::uint8_t> candidate) {
        return ecdsaRawVerifiesWithCertificate(key.certDer, hash, candidate);
    };
}

// Passes every candidate: what is refused under it, the walker refused.
const EcdsaRawCheck acceptsAnything = [](std::span<const std::uint8_t>) { return true; };

TEST(EcdsaReply, DerFromACardBecomesFixedWidthRaw)
{
    const auto key = makeEcTestKey("P-384");
    const std::vector<std::uint8_t> hash(48, 0x5C);
    const auto der = key.signDer(hash);

    const auto raw = ecdsaRawFromCardReply(der, key.fieldBytes, checkedBy(key, hash));

    ASSERT_TRUE(raw.has_value());
    EXPECT_EQ(*raw, ecdsaRawOf(der, key.fieldBytes));
    EXPECT_TRUE(key.verifiesRaw(hash, *raw));
}

// A card that writes r and s at the full field width: an r whose top bit is
// set is a NEGATIVE INTEGER to DER, yet it is the card's r.
TEST(EcdsaReply, FixedWidthIntegerWithTheTopBitSetIsRead)
{
    const auto key = makeEcTestKey("P-384");
    const std::vector<std::uint8_t> hash(48, 0x5C);
    const auto rs = key.rawSignatureWhere(hash, [](std::span<const std::uint8_t> raw) { return raw[0] >= 0x80; }, 256);
    const auto reply = fixedWidthSequence(rs, /*zeroPrefix=*/false);
    ASSERT_EQ(std::vector<std::uint8_t>(reply.begin(), reply.begin() + 4),
              (std::vector<std::uint8_t>{0x30, 0x64, 0x02, 0x30}));

    const auto raw = ecdsaRawFromCardReply(reply, key.fieldBytes, checkedBy(key, hash));

    ASSERT_TRUE(raw.has_value());
    EXPECT_EQ(*raw, rs);
}

// 30 66 02 31 00 r 02 31 00 s: every INTEGER 49 bytes behind a 00. When r's
// top bit is clear that 00 is padding DER forbids; it is still the card's r.
TEST(EcdsaReply, ZeroPrefixedFixedWidthIntegersAreRead)
{
    const auto key = makeEcTestKey("P-384");
    const std::vector<std::uint8_t> hash(48, 0x5C);
    const auto rs = key.rawSignatureWhere(
        hash, [](std::span<const std::uint8_t> raw) { return raw[0] != 0x00 && raw[0] < 0x80; }, 256);
    const auto reply = fixedWidthSequence(rs, /*zeroPrefix=*/true);
    ASSERT_EQ(std::vector<std::uint8_t>(reply.begin(), reply.begin() + 5),
              (std::vector<std::uint8_t>{0x30, 0x66, 0x02, 0x31, 0x00}));

    const auto raw = ecdsaRawFromCardReply(reply, key.fieldBytes, checkedBy(key, hash));

    ASSERT_TRUE(raw.has_value());
    EXPECT_EQ(*raw, rs);
}

// An r below 2^(8 * (width - 1)) comes out of DER at least a byte short; the
// contract wants it left-padded. About one P-256 signature in 256.
TEST(EcdsaReply, ShortIntegerIsLeftPaddedWithZeros)
{
    const auto key = makeEcTestKey("P-256");
    const std::vector<std::uint8_t> hash(32, 0x5C);
    const auto rs = key.rawSignatureWhere(hash, [](std::span<const std::uint8_t> raw) { return raw[0] == 0x00; });
    const auto der = ecdsaDer(std::span(rs).first(32), std::span(rs).subspan(32));

    const auto raw = ecdsaRawFromCardReply(der, key.fieldBytes, checkedBy(key, hash));

    ASSERT_TRUE(raw.has_value());
    EXPECT_EQ((*raw)[0], 0x00);
    EXPECT_EQ(*raw, rs);
}

TEST(EcdsaReply, RawReplyOfTheFieldWidthIsKept)
{
    const auto key = makeEcTestKey("P-384");
    const std::vector<std::uint8_t> hash(48, 0x5C);
    const auto rs = ecdsaRawOf(key.signDer(hash), key.fieldBytes);

    const auto raw = ecdsaRawFromCardReply(rs, key.fieldBytes, checkedBy(key, hash));

    ASSERT_TRUE(raw.has_value());
    EXPECT_EQ(*raw, rs);
}

// A real signature whose DER is exactly 96 bytes reads both ways; the
// certificate's public key says which reading the card meant.
TEST(EcdsaReply, AmbiguousReplyTakesTheReadingThatVerifies)
{
    const auto key = makeEcTestKey("P-384");
    const auto chosen = key.signatureWithRawWidthDer();
    ASSERT_EQ(chosen.der.size(), 96U);

    const auto raw = ecdsaRawFromCardReply(chosen.der, 48, checkedBy(key, chosen.hash));

    ASSERT_TRUE(raw.has_value());
    EXPECT_NE(*raw, chosen.der) << "the DER reading verifies, the raw one does not";
    EXPECT_TRUE(key.verifiesRaw(chosen.hash, *raw));
}

// Two readings that both pass cannot both be the card's signature. A real key
// never verifies both; the stand-in check here accepts anything.
TEST(EcdsaReply, TwoReadingsThatBothPassAreRefused)
{
    const auto key = makeEcTestKey("P-384");
    const auto chosen = key.signatureWithRawWidthDer();
    ASSERT_EQ(chosen.der.size(), 96U);

    EXPECT_FALSE(ecdsaRawFromCardReply(chosen.der, 48, acceptsAnything).has_value());
}

// Every reading is checked: a well-formed reply that is no signature by the
// certificate's key -- damaged, or made by another key -- never comes back.
TEST(EcdsaReply, SignatureThatDoesNotVerifyIsRefused)
{
    const auto key = makeEcTestKey("P-384");
    const auto other = makeEcTestKey("P-384");
    const std::vector<std::uint8_t> hash(48, 0x5C);

    auto damaged = key.signDer(hash);
    damaged.back() ^= 0x01; // the last byte of s
    EXPECT_FALSE(ecdsaRawFromCardReply(damaged, 48, checkedBy(key, hash)).has_value());
    EXPECT_FALSE(ecdsaRawFromCardReply(other.signDer(hash), 48, checkedBy(key, hash)).has_value());
    EXPECT_FALSE(ecdsaRawFromCardReply(ecdsaRawOf(other.signDer(hash), 48), 48, checkedBy(key, hash)).has_value());
    EXPECT_TRUE(ecdsaRawFromCardReply(key.signDer(hash), 48, checkedBy(key, hash)).has_value()) << "control";
}

TEST(EcdsaReply, ReplyOfNeitherShapeIsRefused)
{
    const auto key = makeEcTestKey("P-384");
    const std::vector<std::uint8_t> hash(48, 0x5C);
    EXPECT_FALSE(ecdsaRawFromCardReply(std::vector<std::uint8_t>(96, 0xA5), 48, checkedBy(key, hash)).has_value())
        << "the raw width, but no signature";
    EXPECT_FALSE(ecdsaRawFromCardReply(std::vector<std::uint8_t>(50, 0xA5), 48, acceptsAnything).has_value());
    EXPECT_FALSE(ecdsaRawFromCardReply(std::vector<std::uint8_t>{}, 48, acceptsAnything).has_value());
    EXPECT_FALSE(ecdsaRawFromCardReply(std::vector<std::uint8_t>(96, 0xA5), 0, acceptsAnything).has_value())
        << "no width, no answer";

    // Neither reply below has the raw width, and the check passes anything:
    // the walker itself refuses them.
    auto trailing = key.signDer(hash);
    trailing.push_back(0x00);
    ASSERT_NE(trailing.size(), 96U);
    EXPECT_FALSE(ecdsaRawFromCardReply(trailing, 48, acceptsAnything).has_value()) << "nothing may follow the SEQUENCE";

    const std::vector<std::uint8_t> wideR(49, 0x11);
    const auto tooWide = ecdsaDer(wideR, std::vector<std::uint8_t>(48, 0x22));
    ASSERT_NE(tooWide.size(), 96U);
    EXPECT_FALSE(ecdsaRawFromCardReply(tooWide, 48, acceptsAnything).has_value()) << "r wider than the field";

    auto three = fixedWidthSequence(ecdsaRawOf(key.signDer(hash), 48), /*zeroPrefix=*/true); // 30 66 ...
    three.insert(three.end(), {0x02, 0x01, 0x01});
    three[1] = static_cast<std::uint8_t>(three[1] + 3); // 0x69: still the short form, and the whole reply
    EXPECT_FALSE(ecdsaRawFromCardReply(three, 48, acceptsAnything).has_value()) << "exactly two INTEGERs";
}

// Lengths are definite. An indefinite SEQUENCE (30 80) is refused, with or
// without its end-of-contents, and so is a decoder that would read 80 as a
// short-form 128.
TEST(EcdsaReply, IndefiniteLengthIsRefused)
{
    const std::vector<std::uint8_t> withEndOfContents = {0x30, 0x80, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x00, 0x00};
    EXPECT_FALSE(ecdsaRawFromCardReply(withEndOfContents, 32, acceptsAnything).has_value());

    // 30 80 | 02 3E r | 02 3E s: exactly 128 content bytes, two INTEGERs that
    // fit a P-521 field.
    std::vector<std::uint8_t> eightyAs128 = {0x30, 0x80, 0x02, 0x3E};
    eightyAs128.insert(eightyAs128.end(), 0x3E, 0x11);
    eightyAs128.insert(eightyAs128.end(), {0x02, 0x3E});
    eightyAs128.insert(eightyAs128.end(), 0x3E, 0x22);
    ASSERT_EQ(eightyAs128.size(), 130U);
    EXPECT_FALSE(ecdsaRawFromCardReply(eightyAs128, 66, acceptsAnything).has_value());
}

// A length in three bytes (82 hi lo) is wider than any ECDSA reply needs: the
// short form or 81 xx covers P-521. Refused for the SEQUENCE and an INTEGER.
TEST(EcdsaReply, LengthInThreeBytesIsRefused)
{
    std::vector<std::uint8_t> sequence82 = {0x30, 0x82, 0x00, 0x44, 0x02, 0x20};
    sequence82.insert(sequence82.end(), 0x20, 0x11);
    sequence82.insert(sequence82.end(), {0x02, 0x20});
    sequence82.insert(sequence82.end(), 0x20, 0x22);
    ASSERT_EQ(sequence82.size(), 72U);
    EXPECT_FALSE(ecdsaRawFromCardReply(sequence82, 32, acceptsAnything).has_value());

    std::vector<std::uint8_t> integer82 = {0x30, 0x46, 0x02, 0x82, 0x00, 0x20};
    integer82.insert(integer82.end(), 0x20, 0x11);
    integer82.insert(integer82.end(), {0x02, 0x20});
    integer82.insert(integer82.end(), 0x20, 0x22);
    ASSERT_EQ(integer82.size(), 72U);
    EXPECT_FALSE(ecdsaRawFromCardReply(integer82, 32, acceptsAnything).has_value());
}

TEST(EcdsaReply, NoCheckNoAnswer)
{
    const auto key = makeEcTestKey("P-384");
    const std::vector<std::uint8_t> hash(48, 0x5C);

    EXPECT_FALSE(ecdsaRawFromCardReply(key.signDer(hash), 48, EcdsaRawCheck{}).has_value())
        << "every signature is checked; without a check there is nothing to return";
}

// P-521: r and s are 66 bytes, so the SEQUENCE is longer than 127 bytes and
// its length takes the long form 81 xx.
TEST(EcdsaReply, P521SequenceUsesTheLongLengthForm)
{
    const auto key = makeEcTestKey("P-521");
    ASSERT_EQ(key.fieldBytes, 66U);
    const std::vector<std::uint8_t> hash(64, 0x5C);
    const auto der = key.signDer(hash);
    ASSERT_EQ(der[1], 0x81);
    const auto rs = ecdsaRawOf(der, 66);
    const auto fixed = fixedWidthSequence(rs, /*zeroPrefix=*/true);
    ASSERT_EQ(fixed[1], 0x81);

    for (const auto& reply : {der, fixed}) {
        const auto raw = ecdsaRawFromCardReply(reply, 66, checkedBy(key, hash));
        ASSERT_TRUE(raw.has_value());
        EXPECT_EQ(*raw, rs);
    }
}

// Every curve a card carries, many real signatures each: the contract's
// r || s comes back whether the card wrote DER, either fixed-width form, or
// raw r || s.
TEST(EcdsaReply, RoundTripsRealSignaturesOnEveryCurve)
{
    std::mt19937 rng(20261014U);
    for (const char* curve : {"P-256", "P-384", "P-521"}) {
        const auto key = makeEcTestKey(curve);
        for (int i = 0; i < 40; ++i) {
            std::vector<std::uint8_t> hash(key.fieldBytes == 66 ? 64 : key.fieldBytes);
            for (auto& b : hash)
                b = static_cast<std::uint8_t>(rng());
            const auto der = key.signDer(hash);
            const auto rs = ecdsaRawOf(der, key.fieldBytes);

            for (const auto& reply : {der, fixedWidthSequence(rs, false), fixedWidthSequence(rs, true), rs}) {
                const auto raw = ecdsaRawFromCardReply(reply, key.fieldBytes, checkedBy(key, hash));
                ASSERT_TRUE(raw.has_value()) << curve << ", signature " << i;
                EXPECT_EQ(*raw, rs);
            }
        }
    }
}

TEST(EcdsaCertificateCheck, AcceptsOnlyItsOwnKeysSignature)
{
    const auto key = makeEcTestKey("P-256");
    const auto other = makeEcTestKey("P-256");
    const std::vector<std::uint8_t> hash(32, 0x6E);
    const auto raw = ecdsaRawOf(key.signDer(hash), key.fieldBytes);

    EXPECT_TRUE(ecdsaRawVerifiesWithCertificate(key.certDer, hash, raw));
    EXPECT_FALSE(ecdsaRawVerifiesWithCertificate(other.certDer, hash, raw));
    auto flipped = raw;
    flipped.back() ^= 0x01;
    EXPECT_FALSE(ecdsaRawVerifiesWithCertificate(key.certDer, hash, flipped));
    EXPECT_FALSE(ecdsaRawVerifiesWithCertificate(std::vector<std::uint8_t>{0x30, 0x00}, hash, raw));
    EXPECT_FALSE(ecdsaRawVerifiesWithCertificate(key.certDer, hash, std::span(raw).first(63)));
}

// r || s must be exactly the width of the certificate's curve. Zeros on the
// left do not change the numbers, so a P-256 signature widened to P-521's
// 66-byte halves would verify all the same -- and break the contract's width.
TEST(EcdsaCertificateCheck, RefusesAWidthOtherThanTheCurves)
{
    const auto key = makeEcTestKey("P-256");
    const std::vector<std::uint8_t> hash(32, 0x6E);
    const auto der = key.signDer(hash);

    EXPECT_TRUE(ecdsaRawVerifiesWithCertificate(key.certDer, hash, ecdsaRawOf(der, 32))) << "control";
    EXPECT_FALSE(ecdsaRawVerifiesWithCertificate(key.certDer, hash, ecdsaRawOf(der, 66)));
    EXPECT_FALSE(ecdsaRawFromCardReply(der, 66, checkedBy(key, hash)).has_value())
        << "a caller's wrong width finds no reading that verifies";
}

} // namespace
