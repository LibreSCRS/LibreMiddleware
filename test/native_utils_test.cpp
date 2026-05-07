// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

// Unit tests for native-backend internal utilities that the wider public
// API does not exercise directly: the derEncodeLength implementation
// (throws on ≥16 MiB), sha256Base64, and spot-checks on base64
// primitives. These test the internal headers
// (lib/libresign/src/native/) via relative include because they are not
// part of the public LibreSign include surface.

#include "../lib/libresign/src/native/der_utils.h"
#include "../lib/libresign/src/native/native_utils.h"

#include <miniz.h>

#include <gtest/gtest.h>

#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

using libresign::derEncodeLength;
using libresign::native_utils::base64Decode;
using libresign::native_utils::base64Encode;
using libresign::native_utils::sha256;
using libresign::native_utils::sha256Base64;

// ---------------------------------------------------------------------------
// derEncodeLength — throws std::length_error on ≥ 16 MiB
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
// sha256Base64 — equivalent to base64Encode(sha256(data))
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
    const std::vector<uint8_t> expectedDigest{0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40,
                                              0xde, 0x5d, 0xae, 0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17,
                                              0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad};
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
// base64Decode — M1: consolidated from duplicated anonymous-namespace copies
// ---------------------------------------------------------------------------

TEST(Base64Decode, RoundTrip)
{
    // Encode then decode: must reproduce original bytes.
    std::vector<uint8_t> original{0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD};
    auto encoded = base64Encode(original);
    auto decoded = base64Decode(encoded);
    EXPECT_EQ(decoded, original);
}

TEST(Base64Decode, EmptyInput)
{
    auto result = base64Decode("");
    EXPECT_TRUE(result.empty());
}

TEST(Base64Decode, WhitespaceInput)
{
    auto result = base64Decode("   \n\t  ");
    EXPECT_TRUE(result.empty());
}

TEST(Base64Decode, KnownVector)
{
    // "Hello" base64 = "SGVsbG8="
    auto result = base64Decode("SGVsbG8=");
    std::vector<uint8_t> expected{'H', 'e', 'l', 'l', 'o'};
    EXPECT_EQ(result, expected);
}

TEST(Base64Decode, WhitespaceInMiddle)
{
    // Same as above but with embedded whitespace (as seen in XML certs)
    auto result = base64Decode("SGVs\n  bG8=");
    std::vector<uint8_t> expected{'H', 'e', 'l', 'l', 'o'};
    EXPECT_EQ(result, expected);
}

TEST(Base64Decode, NoPadding)
{
    // "Hello" base64 without padding: "SGVsbG8" — should still decode
    auto result = base64Decode("SGVsbG8");
    std::vector<uint8_t> expected{'H', 'e', 'l', 'l', 'o'};
    EXPECT_EQ(result, expected);
}

// ---------------------------------------------------------------------------
// derSequence / derOctetString — each wraps content with
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
// digestInfoPrefixForAlgo — maps OpenSSL MD name strings
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

// ---------------------------------------------------------------------------
// flateDecode — zlib decompression for PDF FlateDecode streams
// ---------------------------------------------------------------------------

using libresign::native_utils::flateDecode;
using libresign::native_utils::reversePngPredictor;

TEST(FlateDecode, RoundTrip)
{
    // Compress known data with mz_compress, then decompress with flateDecode.
    const std::string input = "Hello, FlateDecode! This is a test of zlib round-trip compression.";
    std::vector<uint8_t> src(input.begin(), input.end());

    // Compress
    mz_ulong compBound = mz_compressBound(static_cast<mz_ulong>(src.size()));
    std::vector<uint8_t> compressed(compBound);
    mz_ulong compLen = compBound;
    int rc = mz_compress(compressed.data(), &compLen, src.data(), static_cast<mz_ulong>(src.size()));
    ASSERT_EQ(rc, MZ_OK);
    compressed.resize(compLen);

    // Decompress
    auto result = flateDecode(compressed);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, src);
}

TEST(FlateDecode, RoundTripWithSizeHint)
{
    // Provide an exact size hint to avoid reallocation loops.
    const std::string input = "Size-hinted decompression test data payload.";
    std::vector<uint8_t> src(input.begin(), input.end());

    mz_ulong compBound = mz_compressBound(static_cast<mz_ulong>(src.size()));
    std::vector<uint8_t> compressed(compBound);
    mz_ulong compLen = compBound;
    int rc = mz_compress(compressed.data(), &compLen, src.data(), static_cast<mz_ulong>(src.size()));
    ASSERT_EQ(rc, MZ_OK);
    compressed.resize(compLen);

    auto result = flateDecode(compressed, src.size());
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, src);
}

TEST(FlateDecode, LargeData)
{
    // 64 KiB of repetitive data — compresses well, tests buffer growth.
    std::vector<uint8_t> src(65536);
    for (size_t i = 0; i < src.size(); ++i)
        src[i] = static_cast<uint8_t>(i % 251);

    mz_ulong compBound = mz_compressBound(static_cast<mz_ulong>(src.size()));
    std::vector<uint8_t> compressed(compBound);
    mz_ulong compLen = compBound;
    int rc = mz_compress(compressed.data(), &compLen, src.data(), static_cast<mz_ulong>(src.size()));
    ASSERT_EQ(rc, MZ_OK);
    compressed.resize(compLen);

    auto result = flateDecode(compressed);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, src);
}

TEST(FlateDecode, CorruptDataReturnsNullopt)
{
    std::vector<uint8_t> garbage{0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04};
    auto result = flateDecode(garbage);
    EXPECT_FALSE(result.has_value());
}

TEST(FlateDecode, EmptyInputReturnsNullopt)
{
    std::vector<uint8_t> empty;
    auto result = flateDecode(std::span<const uint8_t>(empty));
    EXPECT_FALSE(result.has_value());
}

// ---------------------------------------------------------------------------
// reversePngPredictor — PNG row filter reversal for PDF xref streams
// ---------------------------------------------------------------------------

TEST(ReversePngPredictor, UpFilter)
{
    // 3 columns, 2 rows with Up filter (0x02).
    // Row 0: filter=02, data=[0A, 0B, 0C] → output [0A, 0B, 0C] (prev row is zeros)
    // Row 1: filter=02, data=[01, 02, 03] → output [0A+01, 0B+02, 0C+03] = [0B, 0D, 0F]
    std::vector<uint8_t> data{0x02, 0x0A, 0x0B, 0x0C, 0x02, 0x01, 0x02, 0x03};
    auto result = reversePngPredictor(data, 3);
    ASSERT_TRUE(result.has_value());
    std::vector<uint8_t> expected{0x0A, 0x0B, 0x0C, 0x0B, 0x0D, 0x0F};
    EXPECT_EQ(*result, expected);
}

TEST(ReversePngPredictor, NoneFilter)
{
    // Filter 0x00: data passes through unchanged.
    std::vector<uint8_t> data{0x00, 0x10, 0x20, 0x30, 0x00, 0x40, 0x50, 0x60};
    auto result = reversePngPredictor(data, 3);
    ASSERT_TRUE(result.has_value());
    std::vector<uint8_t> expected{0x10, 0x20, 0x30, 0x40, 0x50, 0x60};
    EXPECT_EQ(*result, expected);
}

TEST(ReversePngPredictor, SubFilter)
{
    // Filter 0x01 (Sub): each byte adds the previous byte in the same row.
    // Row: filter=01, data=[05, 03, 04]
    // out[0] = 05 (no left neighbor), out[1] = 03+05 = 08, out[2] = 04+08 = 0C
    std::vector<uint8_t> data{0x01, 0x05, 0x03, 0x04};
    auto result = reversePngPredictor(data, 3);
    ASSERT_TRUE(result.has_value());
    std::vector<uint8_t> expected{0x05, 0x08, 0x0C};
    EXPECT_EQ(*result, expected);
}

TEST(ReversePngPredictor, InvalidSizeReturnsNullopt)
{
    // 3 columns means rowBytes=4, but data has 5 bytes (not divisible by 4).
    std::vector<uint8_t> data{0x02, 0x0A, 0x0B, 0x0C, 0xFF};
    auto result = reversePngPredictor(data, 3);
    EXPECT_FALSE(result.has_value());
}

TEST(ReversePngPredictor, ZeroColumnsReturnsNullopt)
{
    std::vector<uint8_t> data{0x00, 0x01};
    auto result = reversePngPredictor(data, 0);
    EXPECT_FALSE(result.has_value());
}

TEST(ReversePngPredictor, NegativeColumnsReturnsNullopt)
{
    std::vector<uint8_t> data{0x00, 0x01};
    auto result = reversePngPredictor(data, -1);
    EXPECT_FALSE(result.has_value());
}

TEST(ReversePngPredictor, EmptyDataReturnsNullopt)
{
    std::vector<uint8_t> empty;
    auto result = reversePngPredictor(empty, 3);
    EXPECT_FALSE(result.has_value());
}

TEST(ReversePngPredictor, UnsupportedFilterReturnsNullopt)
{
    // Filter byte 0x05 is undefined — returns nullopt.
    std::vector<uint8_t> data{0x05, 0x0A, 0x0B, 0x0C};
    auto result = reversePngPredictor(data, 3);
    EXPECT_FALSE(result.has_value());
}

TEST(ReversePngPredictor, AverageFilter)
{
    // Filter 3 (Average): out[c] = raw[c] + floor((left + above) / 2)
    // 3 columns, 2 rows
    // Row 0: [03, 0A, 0B, 0C] — left=0 above=0 → raw values literal
    //   c=0: 0A + (0+0)/2 = 0A, c=1: 0B + (0A+0)/2 = 10, c=2: 0C + (10+0)/2 = 14
    // Row 1: [03, 01, 02, 03] — above from row 0
    //   c=0: 01 + (0+0A)/2 = 06, c=1: 02 + (06+10)/2 = 0D, c=2: 03 + (0D+14)/2 = 13
    std::vector<uint8_t> data = {0x03, 0x0A, 0x0B, 0x0C, 0x03, 0x01, 0x02, 0x03};
    auto result = reversePngPredictor(data, 3);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->at(0), 0x0A);
    EXPECT_EQ(result->at(1), 0x10);
    EXPECT_EQ(result->at(2), 0x14);
    EXPECT_EQ(result->at(3), 0x06);
    EXPECT_EQ(result->at(4), 0x0D);
    EXPECT_EQ(result->at(5), 0x13);
}

TEST(ReversePngPredictor, PaethFilter)
{
    // Filter 4 (Paeth): paeth predictor with left, above, upper-left
    // 2 columns, 1 row (no previous row, so above=0, upper-left=0)
    // Row 0: [04, 0A, 05] — left=0,above=0,ul=0 for c=0 → 0A; left=0A,above=0,ul=0 for c=1 → 0F
    std::vector<uint8_t> data = {0x04, 0x0A, 0x05};
    auto result = reversePngPredictor(data, 2);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->at(0), 0x0A);
    EXPECT_EQ(result->at(1), 0x0F); // 0x05 + paeth(0x0A, 0, 0) = 0x05 + 0x0A
}
