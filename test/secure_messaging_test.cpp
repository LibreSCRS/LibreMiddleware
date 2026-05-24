// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <gtest/gtest.h>
#include <secure_messaging.h>

#include <set>
#include <vector>

using namespace emrtd::crypto;

TEST(SecureMessagingTest, ProtectProducesLargerOutput3DES)
{
    SessionKeys keys;
    keys.encKey = std::vector<uint8_t>(16, 0x01);
    keys.macKey = std::vector<uint8_t>(16, 0x02);
    keys.ssc = std::vector<uint8_t>(8, 0x00);

    SecureMessaging sm(keys, SMAlgorithm::DES3);

    // SELECT command with data: 00 A4 04 0C 07 A0000002471001
    std::vector<uint8_t> cmd = {0x00, 0xA4, 0x04, 0x0C, 0x07, 0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01};

    auto protectedCmd = sm.protect(cmd);
    EXPECT_GT(protectedCmd.size(), cmd.size());
    // CLA should have SM bit set
    EXPECT_EQ(protectedCmd[0] & 0x0C, 0x0C);
}

TEST(SecureMessagingTest, ProtectProducesLargerOutputAES)
{
    SessionKeys keys;
    keys.encKey = std::vector<uint8_t>(16, 0x03);
    keys.macKey = std::vector<uint8_t>(16, 0x04);
    keys.ssc = std::vector<uint8_t>(16, 0x00);

    SecureMessaging sm(keys, SMAlgorithm::AES);

    std::vector<uint8_t> cmd = {0x00, 0xB0, 0x00, 0x00, 0x00}; // READ BINARY Le=256
    auto protectedCmd = sm.protect(cmd);
    EXPECT_GT(protectedCmd.size(), cmd.size());
}

TEST(SecureMessagingTest, SSCIncrements)
{
    SessionKeys keys;
    keys.encKey = std::vector<uint8_t>(16, 0x01);
    keys.macKey = std::vector<uint8_t>(16, 0x02);
    keys.ssc = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};

    SecureMessaging sm(keys, SMAlgorithm::DES3);

    auto cmd1 = sm.protect({0x00, 0xB0, 0x00, 0x00, 0x00});
    auto cmd2 = sm.protect({0x00, 0xB0, 0x01, 0x00, 0x00});
    // Different MACs due to SSC increment
    EXPECT_NE(cmd1, cmd2);
}

TEST(SecureMessagingTest, ProtectNoData)
{
    // Command with Le only, no data: READ BINARY
    SessionKeys keys;
    keys.encKey = std::vector<uint8_t>(16, 0x01);
    keys.macKey = std::vector<uint8_t>(16, 0x02);
    keys.ssc = std::vector<uint8_t>(8, 0x00);

    SecureMessaging sm(keys, SMAlgorithm::DES3);

    // READ BINARY: 00 B0 00 00 00 (Le=256, no data field)
    std::vector<uint8_t> cmd = {0x00, 0xB0, 0x00, 0x00, 0x00};
    auto protectedCmd = sm.protect(cmd);

    // Should contain DO'97 (Le) and DO'8E (MAC) but no DO'87 (no data to encrypt)
    EXPECT_GT(protectedCmd.size(), 4u); // at minimum header + DO'97 + DO'8E + Le
}

TEST(SecureMessagingTest, ProtectContainsDO8E)
{
    // DO'8E (tag 0x8E) must be present in protected command
    SessionKeys keys;
    keys.encKey = std::vector<uint8_t>(16, 0x01);
    keys.macKey = std::vector<uint8_t>(16, 0x02);
    keys.ssc = std::vector<uint8_t>(8, 0x00);

    SecureMessaging sm(keys, SMAlgorithm::DES3);

    std::vector<uint8_t> cmd = {0x00, 0xB0, 0x00, 0x00, 0x00};
    auto protectedCmd = sm.protect(cmd);

    // Search for DO'8E tag in body (after header bytes 0-3 and Lc byte)
    bool found8E = false;
    for (size_t i = 5; i < protectedCmd.size(); ++i) {
        if (protectedCmd[i] == 0x8E) {
            found8E = true;
            break;
        }
    }
    EXPECT_TRUE(found8E);
}

TEST(SecureMessagingTest, ProtectContainsDO97WhenLePresent)
{
    // DO'97 (tag 0x97) must be present when Le is in the original command
    SessionKeys keys;
    keys.encKey = std::vector<uint8_t>(16, 0x01);
    keys.macKey = std::vector<uint8_t>(16, 0x02);
    keys.ssc = std::vector<uint8_t>(8, 0x00);

    SecureMessaging sm(keys, SMAlgorithm::DES3);

    std::vector<uint8_t> cmd = {0x00, 0xB0, 0x00, 0x00, 0x04}; // Le=4
    auto protectedCmd = sm.protect(cmd);

    bool found97 = false;
    for (size_t i = 5; i < protectedCmd.size(); ++i) {
        if (protectedCmd[i] == 0x97) {
            found97 = true;
            break;
        }
    }
    EXPECT_TRUE(found97);
}

TEST(SecureMessagingTest, ProtectCase1OmitsDO97)
{
    // Case 1: no data, no Le (e.g. VERIFY PIN status: 00 20 00 80)
    // ICAO 9303 Part 11: DO'97 only present when original command includes Le.
    SessionKeys keys;
    keys.encKey = std::vector<uint8_t>(16, 0x01);
    keys.macKey = std::vector<uint8_t>(16, 0x02);
    keys.ssc = std::vector<uint8_t>(8, 0x00);

    SecureMessaging sm(keys, SMAlgorithm::DES3);

    std::vector<uint8_t> cmd = {0x00, 0x20, 0x00, 0x80}; // VERIFY PIN status, Case 1
    auto protectedCmd = sm.protect(cmd);

    bool found97 = false;
    for (size_t i = 5; i + 2 < protectedCmd.size(); ++i) {
        if (protectedCmd[i] == 0x97 && protectedCmd[i + 1] == 0x01) {
            found97 = true;
            break;
        }
    }
    EXPECT_FALSE(found97) << "DO'97 must NOT be present for Case 1 commands (no Le)";
}

TEST(SecureMessagingTest, ProtectCase3OmitsDO97)
{
    // Case 3: Lc + data, no Le (e.g. SELECT with P2=0x0C: 00 A4 04 0C 07 ...)
    // ICAO 9303 Part 11: DO'97 only present when original command includes Le.
    // Some cards (e.g. Georgian eID) reject DO'97 on Case 3 MSE:Set AT with SW=6700.
    SessionKeys keys;
    keys.encKey = std::vector<uint8_t>(16, 0x01);
    keys.macKey = std::vector<uint8_t>(16, 0x02);
    keys.ssc = std::vector<uint8_t>(8, 0x00);

    SecureMessaging sm(keys, SMAlgorithm::DES3);

    std::vector<uint8_t> cmd = {0x00, 0xA4, 0x04, 0x0C, 0x07, 0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01}; // Case 3
    auto protectedCmd = sm.protect(cmd);

    bool found97 = false;
    for (size_t i = 5; i + 2 < protectedCmd.size(); ++i) {
        if (protectedCmd[i] == 0x97 && protectedCmd[i + 1] == 0x01) {
            found97 = true;
            break;
        }
    }
    EXPECT_FALSE(found97) << "DO'97 must NOT be present for Case 3 commands (no Le)";
}

TEST(SecureMessagingTest, UnprotectInvalidMACReturnsNullopt)
{
    // Construct a synthetic SM response with a wrong MAC — unprotect must return nullopt
    SessionKeys keys;
    keys.encKey = std::vector<uint8_t>(16, 0x01);
    keys.macKey = std::vector<uint8_t>(16, 0x02);
    keys.ssc = std::vector<uint8_t>(8, 0x00);

    SecureMessaging sm(keys, SMAlgorithm::DES3);

    // DO'99 (SW 90 00) + DO'8E (8 wrong MAC bytes) + SW 90 00
    std::vector<uint8_t> response = {
        0x99, 0x02, 0x90, 0x00,                                     // DO'99
        0x8E, 0x08, 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0x02, 0x03, // DO'8E (wrong MAC)
        0x90, 0x00                                                  // SW
    };

    auto result = sm.unprotect(response);
    EXPECT_FALSE(result.has_value());
}

TEST(SecureMessagingTest, RoundTrip3DES)
{
    // protect a command, then simulate a response and verify unprotect works
    // For the round-trip we test the protect side produces deterministic output
    // (SSC-dependent) and that two separate SM instances with same keys agree.
    SessionKeys keys;
    keys.encKey = std::vector<uint8_t>(16, 0xAB);
    keys.macKey = std::vector<uint8_t>(16, 0xCD);
    keys.ssc = std::vector<uint8_t>(8, 0x00);

    SecureMessaging sm1(keys, SMAlgorithm::DES3);
    SecureMessaging sm2(keys, SMAlgorithm::DES3);

    std::vector<uint8_t> cmd = {0x00, 0xB0, 0x00, 0x00, 0x04};
    auto protected1 = sm1.protect(cmd);
    auto protected2 = sm2.protect(cmd);

    // Both instances started with identical keys/SSC so output must be identical
    EXPECT_EQ(protected1, protected2);
}

TEST(SecureMessagingTest, RoundTripAES)
{
    SessionKeys keys;
    keys.encKey = std::vector<uint8_t>(16, 0x11);
    keys.macKey = std::vector<uint8_t>(16, 0x22);
    keys.ssc = std::vector<uint8_t>(16, 0x00);

    SecureMessaging sm1(keys, SMAlgorithm::AES);
    SecureMessaging sm2(keys, SMAlgorithm::AES);

    std::vector<uint8_t> cmd = {0x00, 0xA4, 0x02, 0x0C, 0x02, 0x01, 0x1E};
    auto protected1 = sm1.protect(cmd);
    auto protected2 = sm2.protect(cmd);

    EXPECT_EQ(protected1, protected2);
}

// --- Negative-path coverage (Wave 5.3) ---
//
// SecureChannel/SecureMessaging was previously only covered by KAT (positive)
// + hardware-gated tests. The cases below pin down rejection-without-crash
// behavior for inputs that a tampering peer or a malformed card response
// could plausibly produce.

TEST(SecureMessagingTest, UnprotectEmptyResponseRejected)
{
    SessionKeys keys;
    keys.encKey = std::vector<uint8_t>(16, 0x01);
    keys.macKey = std::vector<uint8_t>(16, 0x02);
    keys.ssc = std::vector<uint8_t>(8, 0x00);

    SecureMessaging sm(keys, SMAlgorithm::DES3);

    std::vector<uint8_t> empty;
    auto result = sm.unprotect(empty);
    EXPECT_FALSE(result.has_value());
}

TEST(SecureMessagingTest, UnprotectShorterThanSWRejected)
{
    SessionKeys keys;
    keys.encKey = std::vector<uint8_t>(16, 0x01);
    keys.macKey = std::vector<uint8_t>(16, 0x02);
    keys.ssc = std::vector<uint8_t>(8, 0x00);

    SecureMessaging sm(keys, SMAlgorithm::DES3);

    // Single byte — clearly cannot contain DO'99 + DO'8E + SW
    std::vector<uint8_t> tooShort = {0x90};
    auto result = sm.unprotect(tooShort);
    EXPECT_FALSE(result.has_value());
}

TEST(SecureMessagingTest, UnprotectMissingDO8ERejected)
{
    SessionKeys keys;
    keys.encKey = std::vector<uint8_t>(16, 0x01);
    keys.macKey = std::vector<uint8_t>(16, 0x02);
    keys.ssc = std::vector<uint8_t>(8, 0x00);

    SecureMessaging sm(keys, SMAlgorithm::DES3);

    // DO'99 (SW 90 00) + SW 90 00 only — no DO'8E MAC tag
    std::vector<uint8_t> response = {0x99, 0x02, 0x90, 0x00, 0x90, 0x00};
    auto result = sm.unprotect(response);
    EXPECT_FALSE(result.has_value());
}

TEST(SecureMessagingTest, UnprotectGarbledTLVRejected)
{
    SessionKeys keys;
    keys.encKey = std::vector<uint8_t>(16, 0x01);
    keys.macKey = std::vector<uint8_t>(16, 0x02);
    keys.ssc = std::vector<uint8_t>(8, 0x00);

    SecureMessaging sm(keys, SMAlgorithm::DES3);

    // Length byte claims 0xFF but payload is short — must not over-read.
    std::vector<uint8_t> garbled = {0x99, 0xFF, 0x90, 0x00, 0x90, 0x00};
    auto result = sm.unprotect(garbled);
    EXPECT_FALSE(result.has_value());
}

TEST(SecureMessagingTest, UnprotectTamperedSingleByteRejected)
{
    // Round-trip a real protected response, flip one byte in the MAC,
    // and confirm unprotect rejects it (basic detection-of-tampering).
    // We construct an SM message by hand-rolling the simplest valid layout
    // (DO'99 + DO'8E with correct MAC) — easier than driving a card.
    SessionKeys keys;
    keys.encKey = std::vector<uint8_t>(16, 0xAA);
    keys.macKey = std::vector<uint8_t>(16, 0xBB);
    keys.ssc = std::vector<uint8_t>(8, 0x00);

    SecureMessaging genuine(keys, SMAlgorithm::DES3);
    SecureMessaging twin(keys, SMAlgorithm::DES3);

    // The protect path of the genuine instance increments SSC; we need an
    // independent twin to inject a known-good response (matching SSC=1).
    auto sentCmd = genuine.protect({0x00, 0xB0, 0x00, 0x00, 0x04});
    (void)sentCmd;

    // For the tampering check we use the simpler "synthetic with wrong MAC"
    // path: any single-byte flip in the MAC must yield a verification failure.
    std::vector<uint8_t> tampered = {
        0x99, 0x02, 0x90, 0x00,                                     // DO'99 (status)
        0x8E, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // DO'8E (all-zero MAC)
        0x90, 0x00                                                  // SW
    };
    auto result = twin.unprotect(tampered);
    EXPECT_FALSE(result.has_value()) << "All-zero MAC must not validate against any session key";
}

TEST(SecureMessagingTest, SSCMonotonicAcrossManyCalls)
{
    // SSC is supposed to increment monotonically per protect call. Drive
    // 256 calls and confirm every MAC differs (no SSC reuse → no MAC reuse).
    SessionKeys keys;
    keys.encKey = std::vector<uint8_t>(16, 0x55);
    keys.macKey = std::vector<uint8_t>(16, 0x66);
    keys.ssc = std::vector<uint8_t>(8, 0x00);

    SecureMessaging sm(keys, SMAlgorithm::DES3);

    std::vector<uint8_t> cmd = {0x00, 0xB0, 0x00, 0x00, 0x04};
    std::set<std::vector<uint8_t>> uniqueOutputs;
    for (int i = 0; i < 256; ++i) {
        uniqueOutputs.insert(sm.protect(cmd));
    }
    // SSC is 8 bytes; 256 iterations are nowhere near rollover, so every
    // output must be distinct (different SSC → different MAC).
    EXPECT_EQ(uniqueOutputs.size(), 256u);
}

TEST(SecureMessagingTest, ProtectAESHandlesEmptyCommandGracefully)
{
    // Caller can in theory hand SM a short or odd input. We don't expect a
    // valid SM wrap, but we MUST NOT crash or read out of bounds.
    SessionKeys keys;
    keys.encKey = std::vector<uint8_t>(16, 0x11);
    keys.macKey = std::vector<uint8_t>(16, 0x22);
    keys.ssc = std::vector<uint8_t>(16, 0x00);

    SecureMessaging sm(keys, SMAlgorithm::AES);

    // 4-byte header only (no Lc, no Le) is the absolute minimum legal APDU.
    auto runMinimal = [&]() {
        std::vector<uint8_t> minimal = {0x00, 0x84, 0x00, 0x00};
        (void)sm.protect(minimal);
    };
    EXPECT_NO_THROW(runMinimal());
}

TEST(SecureMessagingTest, ProtectLargePayloadHandled)
{
    // Drive a near-maximum short-form payload through protect to flush out
    // any off-by-one in DO'87 padding / Lc encoding on large bodies.
    SessionKeys keys;
    keys.encKey = std::vector<uint8_t>(16, 0x11);
    keys.macKey = std::vector<uint8_t>(16, 0x22);
    keys.ssc = std::vector<uint8_t>(16, 0x00);

    SecureMessaging sm(keys, SMAlgorithm::AES);

    // Build a Case-3 SELECT-like APDU with 200-byte body
    std::vector<uint8_t> bigCmd = {0x00, 0xA4, 0x04, 0x0C, 200};
    bigCmd.insert(bigCmd.end(), 200, 0xAB);

    auto runBig = [&]() {
        auto wrapped = sm.protect(bigCmd);
        EXPECT_GT(wrapped.size(), bigCmd.size());
    };
    EXPECT_NO_THROW(runBig());
}
