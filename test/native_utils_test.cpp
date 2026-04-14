// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

// Unit tests for native-backend internal utilities that the wider public
// API does not exercise directly: the round-4 derEncodeLength rewrite
// (now throws on ≥16 MiB), the round-4 sha256Base64 simplification, and
// spot-checks on base64 primitives. These test the internal headers
// (lib/libresign/src/native/) via relative include because they are not
// part of the public LibreSign include surface.

#include "../lib/libresign/src/native/der_utils.h"
#include "../lib/libresign/src/native/native_utils.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

using libresign::derEncodeLength;
using libresign::native_utils::base64Encode;
using libresign::native_utils::sha256;
using libresign::native_utils::sha256Base64;

// ---------------------------------------------------------------------------
// derEncodeLength — round-4 R4-M4 fix: throw std::length_error on ≥ 16 MiB
// ---------------------------------------------------------------------------

TEST(DerEncodeLength, ShortFormZero)
{
    auto out = derEncodeLength(0);
    ASSERT_EQ(out.size(), 1u);
    EXPECT_EQ(out[0], 0x00);
}

TEST(DerEncodeLength, ShortFormBoundary127)
{
    auto out = derEncodeLength(127);
    ASSERT_EQ(out.size(), 1u);
    EXPECT_EQ(out[0], 0x7F);
}

TEST(DerEncodeLength, LongForm1Byte)
{
    auto out = derEncodeLength(128);
    ASSERT_EQ(out.size(), 2u);
    EXPECT_EQ(out[0], 0x81);
    EXPECT_EQ(out[1], 0x80);
}

TEST(DerEncodeLength, LongForm2Bytes)
{
    auto out = derEncodeLength(256);
    ASSERT_EQ(out.size(), 3u);
    EXPECT_EQ(out[0], 0x82);
    EXPECT_EQ(out[1], 0x01);
    EXPECT_EQ(out[2], 0x00);
}

TEST(DerEncodeLength, LongForm3Bytes)
{
    auto out = derEncodeLength(65536);
    ASSERT_EQ(out.size(), 4u);
    EXPECT_EQ(out[0], 0x83);
    EXPECT_EQ(out[1], 0x01);
    EXPECT_EQ(out[2], 0x00);
    EXPECT_EQ(out[3], 0x00);
}

TEST(DerEncodeLength, MaxBoundary3Bytes)
{
    // 16 MiB - 1 = 0xFFFFFF must still fit in 3-byte long form
    auto out = derEncodeLength(0xFFFFFF);
    ASSERT_EQ(out.size(), 4u);
    EXPECT_EQ(out[0], 0x83);
}

TEST(DerEncodeLength, ThrowsAt16MiB)
{
    // 0x1000000 = 16 MiB — needs 0x84 (4-byte) encoding, which we refuse.
    EXPECT_THROW(derEncodeLength(0x1000000), std::length_error);
}

TEST(DerEncodeLength, ThrowsOnLargeValues)
{
    EXPECT_THROW(derEncodeLength(1ULL << 32), std::length_error);
}

// ---------------------------------------------------------------------------
// sha256Base64 — round-4 R4-M5: equivalent to base64Encode(sha256(data))
// ---------------------------------------------------------------------------

TEST(Sha256Base64, EmptyInputParity)
{
    std::vector<uint8_t> empty;
    EXPECT_EQ(sha256Base64(empty), base64Encode(sha256(empty)));
}

TEST(Sha256Base64, KnownVectorAbc)
{
    // "abc" SHA-256 digest (NIST test vector), hex:
    //   ba7816bf 8f01cfea 414140de 5dae2223 b00361a3 96177a9c b410ff61 f20015ad
    // Verify by independently building the same digest + base64-encoding it.
    std::vector<uint8_t> abc{'a', 'b', 'c'};
    const std::vector<uint8_t> expectedDigest{0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
                                              0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
                                              0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
                                              0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad};
    EXPECT_EQ(sha256(abc), expectedDigest);
    EXPECT_EQ(sha256Base64(abc), base64Encode(expectedDigest));
}

TEST(Sha256Base64, ParityWithSha256PlusBase64)
{
    // 100-byte pseudo-random buffer — sha256Base64 must equal the composition.
    std::vector<uint8_t> data;
    for (int i = 0; i < 100; ++i)
        data.push_back(static_cast<uint8_t>((i * 37 + 11) & 0xFF));
    EXPECT_EQ(sha256Base64(data), base64Encode(sha256(data)));
}

// ---------------------------------------------------------------------------
// derSequence / derOctetString — round-4 utilities. Each wraps content with
// the DER tag + length from derEncodeLength, so correctness boils down to
// the tag byte + preserving content.
// ---------------------------------------------------------------------------

TEST(DerWrappers, SequenceEmpty)
{
    std::vector<uint8_t> empty;
    auto out = libresign::derSequence(empty);
    ASSERT_EQ(out.size(), 2u);
    EXPECT_EQ(out[0], 0x30); // SEQUENCE tag
    EXPECT_EQ(out[1], 0x00); // length 0
}

TEST(DerWrappers, OctetStringShortForm)
{
    std::vector<uint8_t> content{0xDE, 0xAD, 0xBE, 0xEF};
    auto out = libresign::derOctetString(content);
    ASSERT_EQ(out.size(), 6u);
    EXPECT_EQ(out[0], 0x04); // OCTET STRING tag
    EXPECT_EQ(out[1], 0x04); // short-form length
    EXPECT_EQ(out[2], 0xDE);
    EXPECT_EQ(out[5], 0xEF);
}

TEST(DerWrappers, SequenceLongForm)
{
    // 200-byte content forces the long-form length (0x81 0xC8)
    std::vector<uint8_t> content(200, 0x55);
    auto out = libresign::derSequence(content);
    ASSERT_EQ(out.size(), 203u);
    EXPECT_EQ(out[0], 0x30);
    EXPECT_EQ(out[1], 0x81);
    EXPECT_EQ(out[2], 0xC8);
    EXPECT_EQ(out[3], 0x55);
}

// ---------------------------------------------------------------------------
// digestInfoPrefixForAlgo — round-4 extraction. Maps OpenSSL MD name strings
// to PKCS#1 DigestInfo prefixes (RFC 8017 §9.2).
// ---------------------------------------------------------------------------

TEST(DigestInfoPrefix, Sha256)
{
    auto p = libresign::native_utils::digestInfoPrefixForAlgo("SHA2-256");
    ASSERT_EQ(p.size(), 19u);
    EXPECT_EQ(p[0], 0x30);
    // Last three bytes: 0x04 0x20 (OCTET STRING length 32 for SHA-256 hash)
    EXPECT_EQ(p[17], 0x04);
    EXPECT_EQ(p[18], 0x20);
}

TEST(DigestInfoPrefix, Sha384)
{
    auto p = libresign::native_utils::digestInfoPrefixForAlgo("SHA2-384");
    ASSERT_FALSE(p.empty());
    EXPECT_EQ(p[0], 0x30);
}

TEST(DigestInfoPrefix, Sha512)
{
    auto p = libresign::native_utils::digestInfoPrefixForAlgo("SHA2-512");
    ASSERT_FALSE(p.empty());
    EXPECT_EQ(p[0], 0x30);
}

TEST(DigestInfoPrefix, UnknownReturnsEmpty)
{
    // Unknown algorithm names return an empty span so callers can fail
    // closed rather than sign with a wrong prefix.
    auto p = libresign::native_utils::digestInfoPrefixForAlgo("MD5");
    EXPECT_TRUE(p.empty());
    auto p2 = libresign::native_utils::digestInfoPrefixForAlgo("");
    EXPECT_TRUE(p2.empty());
}
