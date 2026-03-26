// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <gtest/gtest.h>
#include <emrtd/crypto/pace.h>

// Internal header — needed to test KDF, AES-CMAC, padding directly
#include "../lib/emrtd-crypto/src/crypto_utils.h"

using namespace emrtd::crypto;

TEST(PACETest, ParseCardAccessEmpty)
{
    auto oids = parseCardAccess({});
    EXPECT_TRUE(oids.empty());
}

TEST(PACETest, ParseCardAccessSingleOID)
{
    // Minimal SecurityInfos containing id-PACE-ECDH-GM-AES-CBC-CMAC-128
    // Build ASN.1: SET { SEQUENCE { OID, INTEGER 2, INTEGER 13 } }
    // OID 0.4.0.127.0.7.2.2.4.2.2 encoded as:
    // 04 00 7F 00 07 02 02 04 02 02
    std::vector<uint8_t> cardAccess = {
        0x31, 0x14,                                                 // SET OF
        0x30, 0x12,                                                 // SEQUENCE
        0x06, 0x0A,                                                 // OID (10 bytes)
        0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x02, 0x02, //
        0x02, 0x01, 0x02,                                           // INTEGER 2
        0x02, 0x01, 0x0D                                            // INTEGER 13
    };

    auto oids = parseCardAccess(cardAccess);
    ASSERT_EQ(oids.size(), 1u);
    EXPECT_EQ(oids[0], "0.4.0.127.0.7.2.2.4.2.2");
}

TEST(PACETest, ParseCardAccessMultipleOIDs)
{
    // SET containing two SecurityInfos
    std::vector<uint8_t> cardAccess = {0x31, 0x28,
                                       // SecurityInfo 1: AES-128
                                       0x30, 0x12, 0x06, 0x0A, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x02,
                                       0x02, 0x02, 0x01, 0x02, 0x02, 0x01, 0x0D,
                                       // SecurityInfo 2: AES-256
                                       0x30, 0x12, 0x06, 0x0A, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x02,
                                       0x04, 0x02, 0x01, 0x02, 0x02, 0x01, 0x0D};

    auto oids = parseCardAccess(cardAccess);
    ASSERT_EQ(oids.size(), 2u);
    EXPECT_EQ(oids[0], "0.4.0.127.0.7.2.2.4.2.2");
    EXPECT_EQ(oids[1], "0.4.0.127.0.7.2.2.4.2.4");
}

TEST(PACETest, ParseCardAccessIgnoresNonPACE)
{
    // SET with a non-PACE OID (e.g., Chip Authentication prefix)
    std::vector<uint8_t> cardAccess = {0x31, 0x12, 0x30, 0x10, 0x06, 0x08, 0x04, 0x00, 0x7F, 0x00,
                                       0x07, 0x02, 0x02, 0x03, 0x02, 0x01, 0x02, 0x02, 0x01, 0x0D};

    auto oids = parseCardAccess(cardAccess);
    EXPECT_TRUE(oids.empty());
}

TEST(PACETest, ParseCardAccessWithParamsSingleEntry)
{
    // Same CardAccess as ParseCardAccessSingleOID: OID + version 2 + paramId 13
    std::vector<uint8_t> cardAccess = {
        0x31, 0x14,                                                 // SET OF
        0x30, 0x12,                                                 // SEQUENCE
        0x06, 0x0A,                                                 // OID (10 bytes)
        0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x02, 0x02, //
        0x02, 0x01, 0x02,                                           // INTEGER 2 (version)
        0x02, 0x01, 0x0D                                            // INTEGER 13 (paramId)
    };

    auto entries = parseCardAccessWithParams(cardAccess);
    ASSERT_EQ(entries.size(), 1u);
    EXPECT_EQ(entries[0].first, "0.4.0.127.0.7.2.2.4.2.2");
    EXPECT_EQ(entries[0].second, 13);
}

TEST(PACETest, ParseCardAccessWithParamsMultipleEntries)
{
    // SET containing two SecurityInfos with different paramIds
    std::vector<uint8_t> cardAccess = {0x31, 0x28,
                                       // SecurityInfo 1: AES-128, paramId=13 (brainpoolP256r1)
                                       0x30, 0x12, 0x06, 0x0A, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x02,
                                       0x02, 0x02, 0x01, 0x02, 0x02, 0x01, 0x0D,
                                       // SecurityInfo 2: AES-256, paramId=12 (secp256r1)
                                       0x30, 0x12, 0x06, 0x0A, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x02,
                                       0x04, 0x02, 0x01, 0x02, 0x02, 0x01, 0x0C};

    auto entries = parseCardAccessWithParams(cardAccess);
    ASSERT_EQ(entries.size(), 2u);
    EXPECT_EQ(entries[0].first, "0.4.0.127.0.7.2.2.4.2.2");
    EXPECT_EQ(entries[0].second, 13);
    EXPECT_EQ(entries[1].first, "0.4.0.127.0.7.2.2.4.2.4");
    EXPECT_EQ(entries[1].second, 12);
}

TEST(PACETest, ParseCardAccessWithParamsNoParamId)
{
    // SecurityInfo with OID and version only — no paramId INTEGER
    // SET { SEQUENCE { OID, INTEGER 2 } }
    std::vector<uint8_t> cardAccess = {
        0x31, 0x11,                                                                  // SET OF
        0x30, 0x0F,                                                                  // SEQUENCE
        0x06, 0x0A,                                                                  // OID (10 bytes)
        0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x02, 0x02, 0x02, 0x01, 0x02 // INTEGER 2 (version only)
    };

    auto entries = parseCardAccessWithParams(cardAccess);
    ASSERT_EQ(entries.size(), 1u);
    EXPECT_EQ(entries[0].first, "0.4.0.127.0.7.2.2.4.2.2");
    EXPECT_EQ(entries[0].second, -1); // absent
}

TEST(PACETest, ParseCardAccessWithParamsIgnoresNonPACE)
{
    // Non-PACE OID should not appear in results
    std::vector<uint8_t> cardAccess = {0x31, 0x12, 0x30, 0x10, 0x06, 0x08, 0x04, 0x00, 0x7F, 0x00,
                                       0x07, 0x02, 0x02, 0x03, 0x02, 0x01, 0x02, 0x02, 0x01, 0x0D};

    auto entries = parseCardAccessWithParams(cardAccess);
    EXPECT_TRUE(entries.empty());
}

TEST(PACETest, PasswordTypeEnum)
{
    EXPECT_EQ(static_cast<int>(PACEPasswordType::MRZ), 1);
    EXPECT_EQ(static_cast<int>(PACEPasswordType::CAN), 2);
    EXPECT_EQ(static_cast<int>(PACEPasswordType::PIN), 3);
    EXPECT_EQ(static_cast<int>(PACEPasswordType::PUK), 4);
}

TEST(PACETest, OIDToSMAlgorithm)
{
    EXPECT_EQ(paceOIDToSMAlgorithm(pace_oid::ECDH_GM_3DES_CBC_CBC), SMAlgorithm::DES3);
    EXPECT_EQ(paceOIDToSMAlgorithm(pace_oid::ECDH_GM_AES_CBC_CMAC_128), SMAlgorithm::AES);
    EXPECT_EQ(paceOIDToSMAlgorithm(pace_oid::ECDH_GM_AES_CBC_CMAC_192), SMAlgorithm::AES);
    EXPECT_EQ(paceOIDToSMAlgorithm(pace_oid::ECDH_GM_AES_CBC_CMAC_256), SMAlgorithm::AES);
}

// ---------------------------------------------------------------------------
// KDF tests — verify key derivation for PACE K_pi and session keys
// ---------------------------------------------------------------------------

TEST(PACECryptoTest, KdfAes256WithRawCAN)
{
    // CAN "545291" → raw bytes as seed, counter=3, AES-256 (32-byte output)
    std::vector<uint8_t> can = {0x35, 0x34, 0x35, 0x32, 0x39, 0x31};
    auto kPi = detail::kdf(can, 3, /*des3=*/false, /*keyLen=*/32);
    ASSERT_EQ(kPi.size(), 32u);
    // K_pi = SHA-256("545291" || 00 00 00 03)[0:32]
    EXPECT_EQ(kPi[0], 0x8A);
    EXPECT_EQ(kPi[1], 0x37);
    EXPECT_EQ(kPi[31], 0xDC);
}

TEST(PACECryptoTest, KdfAes128)
{
    // Same seed, AES-128 (16-byte output) — truncated SHA-1
    // KDF uses matched security level: SHA-1 for keyLen <= 20 bytes.
    std::vector<uint8_t> seed = {0x35, 0x34, 0x35, 0x32, 0x39, 0x31};
    auto key = detail::kdf(seed, 3, /*des3=*/false, /*keyLen=*/16);
    ASSERT_EQ(key.size(), 16u);
    // First 16 bytes of SHA-1("545291" || 00 00 00 03)
    EXPECT_EQ(key[0], 0xC2);
    EXPECT_EQ(key[15], 0xE3);
}

TEST(PACECryptoTest, KdfDes3WithAdjustedParity)
{
    // 3DES KDF uses SHA-1 and adjusts parity bits
    std::vector<uint8_t> seed = {0x01, 0x02, 0x03};
    auto key = detail::kdf(seed, 3, /*des3=*/true, /*keyLen=*/16);
    ASSERT_EQ(key.size(), 16u);
    // Every byte should have odd parity
    for (auto b : key) {
        int bits = 0;
        for (int i = 0; i < 8; ++i)
            bits += (b >> i) & 1;
        EXPECT_EQ(bits % 2, 1) << "Byte 0x" << std::hex << (int)b << " has even parity";
    }
}

// ---------------------------------------------------------------------------
// AES-CMAC tests — verify no double-padding issue (the critical PACE bug)
// ---------------------------------------------------------------------------

TEST(PACECryptoTest, AesCmac128Rfc4493)
{
    // RFC 4493 Test Vector 2: AES-128-CMAC of 16-byte message
    std::vector<uint8_t> key = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                                0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    std::vector<uint8_t> msg = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
                                0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a};
    auto mac = detail::aesCMAC(key, msg);
    // aesCMAC truncates to 8 bytes per ICAO 9303
    ASSERT_EQ(mac.size(), 8u);
    // Full CMAC = 070A16B46B4D4144F79BDD9DD04A287C, first 8 bytes:
    std::vector<uint8_t> expected = {0x07, 0x0A, 0x16, 0xB4, 0x6B, 0x4D, 0x41, 0x44};
    EXPECT_EQ(mac, expected);
}

TEST(PACECryptoTest, AesCmac256ProducesEightBytes)
{
    // AES-256-CMAC should also produce 8-byte truncated output
    std::vector<uint8_t> key(32, 0xAB);
    std::vector<uint8_t> msg = {0x01, 0x02, 0x03};
    auto mac = detail::aesCMAC(key, msg);
    ASSERT_EQ(mac.size(), 8u);
}

TEST(PACECryptoTest, AesCmacNoPaddingNeeded)
{
    // Verify that AES-CMAC produces DIFFERENT output for raw vs pre-padded input.
    // This is the critical check: PACE must NOT pre-pad before AES-CMAC.
    std::vector<uint8_t> key(32, 0x42);
    std::vector<uint8_t> raw = {0x7F, 0x49, 0x0F, 0x06, 0x0A, 0x04, 0x00, 0x7F, 0x00,
                                0x07, 0x02, 0x02, 0x04, 0x02, 0x04, 0x86, 0x01, 0xFF};
    auto padded = detail::pad(raw, 16);

    auto macRaw = detail::aesCMAC(key, raw);
    auto macPadded = detail::aesCMAC(key, padded);
    // These MUST differ — if they were the same, padding wouldn't matter
    EXPECT_NE(macRaw, macPadded) << "AES-CMAC(raw) must differ from AES-CMAC(padded)";
}

// ---------------------------------------------------------------------------
// ISO 9797-1 Method 2 padding — only for retail MAC (3DES), NOT for AES-CMAC
// ---------------------------------------------------------------------------

TEST(PACECryptoTest, PadAligns8Bytes)
{
    std::vector<uint8_t> data = {0x01, 0x02, 0x03};
    auto padded = detail::pad(data, 8);
    ASSERT_EQ(padded.size(), 8u);
    EXPECT_EQ(padded[3], 0x80);
    for (size_t i = 4; i < 8; ++i)
        EXPECT_EQ(padded[i], 0x00);
}

TEST(PACECryptoTest, PadAligns16Bytes)
{
    std::vector<uint8_t> data(15, 0xAB);
    auto padded = detail::pad(data, 16);
    ASSERT_EQ(padded.size(), 16u);
    EXPECT_EQ(padded[15], 0x80);
}

TEST(PACECryptoTest, PadExactBlockAddsFullBlock)
{
    std::vector<uint8_t> data(16, 0xAB);
    auto padded = detail::pad(data, 16);
    // Exact block → adds 0x80 + 15 zeros = new full block
    ASSERT_EQ(padded.size(), 32u);
    EXPECT_EQ(padded[16], 0x80);
}

TEST(PACECryptoTest, UnpadRoundTrip)
{
    std::vector<uint8_t> data = {0x01, 0x02, 0x03, 0x04, 0x05};
    auto padded = detail::pad(data, 8);
    auto unpadded = detail::unpad(padded);
    EXPECT_EQ(unpadded, data);
}

// ---------------------------------------------------------------------------
// Retail MAC (3DES) — verify basic operation
// ---------------------------------------------------------------------------

TEST(PACECryptoTest, RetailMacProducesEightBytes)
{
    std::vector<uint8_t> key(16, 0x42);
    std::vector<uint8_t> data = detail::pad({0x01, 0x02, 0x03}, 8);
    auto mac = detail::retailMAC(key, data);
    ASSERT_EQ(mac.size(), 8u);
}

TEST(PACECryptoTest, RetailMacDeterministic)
{
    std::vector<uint8_t> key(16, 0x42);
    std::vector<uint8_t> data = detail::pad({0x01, 0x02, 0x03}, 8);
    EXPECT_EQ(detail::retailMAC(key, data), detail::retailMAC(key, data));
}

// ---------------------------------------------------------------------------
// AES encrypt/decrypt roundtrip
// ---------------------------------------------------------------------------

TEST(PACECryptoTest, AesDecryptRoundTrip256)
{
    std::vector<uint8_t> key(32, 0xAB);
    std::vector<uint8_t> plaintext(16, 0x42);
    auto encrypted = detail::aesEncrypt(key, plaintext);
    auto decrypted = detail::aesDecrypt(key, encrypted);
    EXPECT_EQ(decrypted, plaintext);
}
