// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

#include <array>
#include <cstdint>

namespace pkcs15::test_vectors {

// =============================================================================
// EF.ODF — 9 context-tagged entries
// Each entry: [context-tag] 06 30 04 04 02 [FID_HI] [FID_LO]
// Tags A0..A8 map to privateKeys..authObjects
// =============================================================================
// A0 06 30 04 04 02 44 00   -- privateKeys → 4400
// A1 06 30 04 04 02 44 01   -- publicKeys → 4401
// A2 06 30 04 04 02 44 02   -- trustedPublicKeys → 4402
// A3 06 30 04 04 02 44 03   -- secretKeys → 4403
// A4 06 30 04 04 02 44 04   -- certificates → 4404
// A5 06 30 04 04 02 44 05   -- trustedCertificates → 4405
// A6 06 30 04 04 02 44 06   -- usefulCertificates → 4406
// A7 06 30 04 04 02 44 07   -- dataObjects → 4407
// A8 06 30 04 04 02 44 08   -- authObjects → 4408
// Total: 9 * 8 = 72 bytes
constexpr std::array<uint8_t, 72> SAMPLE_ODF = {
    0xA0, 0x06, 0x30, 0x04, 0x04, 0x02, 0x44, 0x00, // privateKeys → 4400
    0xA1, 0x06, 0x30, 0x04, 0x04, 0x02, 0x44, 0x01, // publicKeys → 4401
    0xA2, 0x06, 0x30, 0x04, 0x04, 0x02, 0x44, 0x02, // trustedPublicKeys → 4402
    0xA3, 0x06, 0x30, 0x04, 0x04, 0x02, 0x44, 0x03, // secretKeys → 4403
    0xA4, 0x06, 0x30, 0x04, 0x04, 0x02, 0x44, 0x04, // certificates → 4404
    0xA5, 0x06, 0x30, 0x04, 0x04, 0x02, 0x44, 0x05, // trustedCertificates → 4405
    0xA6, 0x06, 0x30, 0x04, 0x04, 0x02, 0x44, 0x06, // usefulCertificates → 4406
    0xA7, 0x06, 0x30, 0x04, 0x04, 0x02, 0x44, 0x07, // dataObjects → 4407
    0xA8, 0x06, 0x30, 0x04, 0x04, 0x02, 0x44, 0x08, // authObjects → 4408
};

// =============================================================================
// EF.TokenInfo — PKCS#15 TokenInfo SEQUENCE
// SEQUENCE {
//   INTEGER 0                                  -- version v1(0)
//   OCTET STRING "T00000083"                   -- serialNumber (9 bytes)
//   UTF8String "SSCDv1 PACE MD"                -- manufacturerID (14 bytes)
//   [0] IMPLICIT "eID V4.0"                    -- label (8 bytes)
//   BIT STRING 04 70                           -- tokenFlags
// }
// =============================================================================
// Inner:
//   02 01 00                                    = 3 bytes
//   04 09 54 30 30 30 30 30 30 38 33            = 11 bytes
//   0C 0E 53 53 43 44 76 31 20 50 41 43 45 20 4D 44 = 16 bytes
//   80 08 65 49 44 20 56 34 2E 30               = 10 bytes
//   03 02 04 70                                 = 4 bytes
// Total inner = 3 + 11 + 16 + 10 + 4 = 44 = 0x2C
// Outer: 30 2C = 2 bytes
// Grand total: 46 bytes
constexpr std::array<uint8_t, 46> SAMPLE_TOKEN_INFO = {
    0x30, 0x2C,                                                       // SEQUENCE (44 bytes)
    0x02, 0x01, 0x00,                                                 // INTEGER 0 (version)
    0x04, 0x09, 0x54, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x38, 0x33, // OCTET STRING "T00000083"
    0x0C, 0x0E, 0x53, 0x53, 0x43, 0x44, 0x76, 0x31, 0x20, 0x50, 0x41,
    0x43, 0x45, 0x20, 0x4D, 0x44,                               // UTF8String "SSCDv1 PACE MD"
    0x80, 0x08, 0x65, 0x49, 0x44, 0x20, 0x56, 0x34, 0x2E, 0x30, // [0] IMPLICIT "eID V4.0"
    0x03, 0x02, 0x04, 0x70,                                     // BIT STRING tokenFlags
};

// =============================================================================
// EF.CDF — 4 certificate entries
//
// Each CertificateInfoObject:
// SEQUENCE {
//   SEQUENCE { UTF8String label }                    -- CommonObjectAttributes
//   SEQUENCE { OCTET STRING id, BOOLEAN authority }  -- CommonCertificateAttributes
//   [1] CONSTRUCTED {                                -- X509CertificateAttributes
//     SEQUENCE {
//       SEQUENCE { OCTET STRING path }               -- path
//     }
//   }
// }
// =============================================================================

// Certificate IDs (4 bytes each, stored as 4-byte OCTET STRING for simplicity)
// cert0: 15 B8 12 E9
// cert1: F0 3E 78 BB
// cert2: 4F 79 7B 48
// cert3: 26 DA F7 50

// Paths (6 bytes = 3F00/xxxx/yyyy):
// cert0: 3F 00 50 15 44 09
// cert1: 3F 00 50 15 44 0A
// cert2: 3F 00 0D F5 01 15
// cert3: 3F 00 50 15 44 0C

// Cert 0: "Intermediate Sign cert", authority=true, id=15B812E9, path=3F00/5015/4409
// Inner of [1]:
//   SEQUENCE { SEQUENCE { OCTET STRING path(6) } }
//   = 30 0A 30 08 04 06 3F 00 50 15 44 09
//   [1] = A1 0C 30 0A 30 08 04 06 3F 00 50 15 44 09
// CommonCertAttrs:
//   SEQUENCE { 04 04 15 B8 12 E9, 01 01 FF }
//   = 30 09 04 04 15 B8 12 E9 01 01 FF
// CommonObjAttrs:
//   SEQUENCE { 0C 16 "Intermediate Sign cert" }
//   "Intermediate Sign cert" = 22 bytes
//   = 30 18 0C 16 49 6E 74 65 72 6D 65 64 69 61 74 65 20 53 69 67 6E 20 63 65 72 74
// Total cert0 inner = 0x18+2 + 0x09+2 + 0x0C+2 = 26+11+14 = 51 = 0x33
// Cert0: 30 33 ...

// Cert 1: "Intermediate Auth cert", authority=true, id=F03E78BB, path=3F00/5015/440A
// "Intermediate Auth cert" = 22 bytes
// Same structure as cert0 with different id/path

// Cert 2: "Sign", authority=false, id=4F797B48, path=3F00/0DF5/0115
// "Sign" = 4 bytes

// Cert 3: "Auth", authority=false, id=26DAF750, path=3F00/5015/440C
// "Auth" = 4 bytes

// Let me build each cert byte-by-byte:

// --- Cert 0 ---
// CommonObjectAttributes: SEQUENCE { UTF8String "Intermediate Sign cert"(22) }
//   0C 16 [22 bytes] = 24 bytes
//   SEQUENCE: 30 18 [24 bytes] = 26 bytes
// CommonCertificateAttributes: SEQUENCE { OCTET STRING id(4), BOOLEAN true }
//   04 04 15 B8 12 E9 01 01 FF = 9 bytes
//   SEQUENCE: 30 09 [9 bytes] = 11 bytes
// TypeAttributes [1] CONSTRUCTED:
//   inner SEQUENCE { SEQUENCE { OCTET STRING path(6) } }
//   OCTET STRING: 04 06 3F 00 50 15 44 09 = 8 bytes
//   inner SEQUENCE: 30 08 [8 bytes] = 10 bytes
//   outer SEQUENCE: 30 0A [10 bytes] = 12 bytes
//   [1]: A1 0C [12 bytes] = 14 bytes
// Total cert0 = 26 + 11 + 14 = 51 = 0x33
// SEQUENCE: 30 33

// --- Cert 1 ---
// Same as cert0 but label="Intermediate Auth cert"(22), id=F03E78BB, path=3F00/5015/440A
// Total: same size = 0x33

// --- Cert 2 ---
// CommonObjectAttributes: SEQUENCE { UTF8String "Sign"(4) }
//   0C 04 53 69 67 6E = 6 bytes
//   SEQUENCE: 30 06 [6 bytes] = 8 bytes
// CommonCertificateAttributes: SEQUENCE { OCTET STRING id(4), BOOLEAN false }
//   04 04 4F 79 7B 48 01 01 00 = 9 bytes
//   SEQUENCE: 30 09 [9 bytes] = 11 bytes
// TypeAttributes [1] CONSTRUCTED:
//   OCTET STRING: 04 06 3F 00 0D F5 01 15 = 8 bytes
//   inner SEQUENCE: 30 08 [8 bytes] = 10 bytes
//   outer SEQUENCE: 30 0A [10 bytes] = 12 bytes
//   [1]: A1 0C [12 bytes] = 14 bytes
// Total cert2 = 8 + 11 + 14 = 33 = 0x21
// SEQUENCE: 30 21

// --- Cert 3 ---
// CommonObjectAttributes: SEQUENCE { UTF8String "Auth"(4) }
//   0C 04 41 75 74 68 = 6 bytes
//   SEQUENCE: 30 06 [6 bytes] = 8 bytes
// CommonCertificateAttributes: SEQUENCE { OCTET STRING id(4), BOOLEAN false }
//   04 04 26 DA F7 50 01 01 00 = 9 bytes
//   SEQUENCE: 30 09 [9 bytes] = 11 bytes
// TypeAttributes [1] CONSTRUCTED:
//   OCTET STRING: 04 06 3F 00 50 15 44 0C = 8 bytes
//   inner SEQUENCE: 30 08 [8 bytes] = 10 bytes
//   outer SEQUENCE: 30 0A [10 bytes] = 12 bytes
//   [1]: A1 0C [12 bytes] = 14 bytes
// Total cert3 = 8 + 11 + 14 = 33 = 0x21
// SEQUENCE: 30 21

// Grand total CDF = (2+51) + (2+51) + (2+33) + (2+33) = 53+53+35+35 = 176 bytes
constexpr std::array<uint8_t, 176> SAMPLE_CDF = {
    // --- Cert 0: "Intermediate Sign cert", authority=true ---
    0x30,
    0x33, // SEQUENCE (51 bytes)
    0x30,
    0x18, // CommonObjectAttributes SEQUENCE (24 bytes)
    0x0C,
    0x16, // UTF8String (22 bytes) "Intermediate Sign cert"
    0x49,
    0x6E,
    0x74,
    0x65,
    0x72,
    0x6D,
    0x65,
    0x64,
    0x69,
    0x61,
    0x74,
    0x65,
    0x20,
    0x53,
    0x69,
    0x67,
    0x6E,
    0x20,
    0x63,
    0x65,
    0x72,
    0x74,
    0x30,
    0x09, // CommonCertificateAttributes SEQUENCE (9 bytes)
    0x04,
    0x04,
    0x15,
    0xB8,
    0x12,
    0xE9, // OCTET STRING id (4 bytes)
    0x01,
    0x01,
    0xFF, // BOOLEAN TRUE (authority)
    0xA1,
    0x0C, // [1] CONSTRUCTED (12 bytes)
    0x30,
    0x0A, // SEQUENCE (10 bytes)
    0x30,
    0x08, // SEQUENCE (8 bytes) — path
    0x04,
    0x06,
    0x3F,
    0x00,
    0x50,
    0x15,
    0x44,
    0x09, // OCTET STRING path (6 bytes)

    // --- Cert 1: "Intermediate Auth cert", authority=true ---
    0x30,
    0x33, // SEQUENCE (51 bytes)
    0x30,
    0x18, // CommonObjectAttributes SEQUENCE (24 bytes)
    0x0C,
    0x16, // UTF8String (22 bytes) "Intermediate Auth cert"
    0x49,
    0x6E,
    0x74,
    0x65,
    0x72,
    0x6D,
    0x65,
    0x64,
    0x69,
    0x61,
    0x74,
    0x65,
    0x20,
    0x41,
    0x75,
    0x74,
    0x68,
    0x20,
    0x63,
    0x65,
    0x72,
    0x74,
    0x30,
    0x09, // CommonCertificateAttributes SEQUENCE (9 bytes)
    0x04,
    0x04,
    0xF0,
    0x3E,
    0x78,
    0xBB, // OCTET STRING id (4 bytes)
    0x01,
    0x01,
    0xFF, // BOOLEAN TRUE (authority)
    0xA1,
    0x0C, // [1] CONSTRUCTED (12 bytes)
    0x30,
    0x0A, // SEQUENCE (10 bytes)
    0x30,
    0x08, // SEQUENCE (8 bytes) — path
    0x04,
    0x06,
    0x3F,
    0x00,
    0x50,
    0x15,
    0x44,
    0x0A, // OCTET STRING path (6 bytes)

    // --- Cert 2: "Sign", authority=false ---
    0x30,
    0x21, // SEQUENCE (33 bytes)
    0x30,
    0x06, // CommonObjectAttributes SEQUENCE (6 bytes)
    0x0C,
    0x04,
    0x53,
    0x69,
    0x67,
    0x6E, // UTF8String "Sign" (4 bytes)
    0x30,
    0x09, // CommonCertificateAttributes SEQUENCE (9 bytes)
    0x04,
    0x04,
    0x4F,
    0x79,
    0x7B,
    0x48, // OCTET STRING id (4 bytes)
    0x01,
    0x01,
    0x00, // BOOLEAN FALSE (not authority)
    0xA1,
    0x0C, // [1] CONSTRUCTED (12 bytes)
    0x30,
    0x0A, // SEQUENCE (10 bytes)
    0x30,
    0x08, // SEQUENCE (8 bytes) — path
    0x04,
    0x06,
    0x3F,
    0x00,
    0x0D,
    0xF5,
    0x01,
    0x15, // OCTET STRING path (6 bytes)

    // --- Cert 3: "Auth", authority=false ---
    0x30,
    0x21, // SEQUENCE (33 bytes)
    0x30,
    0x06, // CommonObjectAttributes SEQUENCE (6 bytes)
    0x0C,
    0x04,
    0x41,
    0x75,
    0x74,
    0x68, // UTF8String "Auth" (4 bytes)
    0x30,
    0x09, // CommonCertificateAttributes SEQUENCE (9 bytes)
    0x04,
    0x04,
    0x26,
    0xDA,
    0xF7,
    0x50, // OCTET STRING id (4 bytes)
    0x01,
    0x01,
    0x00, // BOOLEAN FALSE (not authority)
    0xA1,
    0x0C, // [1] CONSTRUCTED (12 bytes)
    0x30,
    0x0A, // SEQUENCE (10 bytes)
    0x30,
    0x08, // SEQUENCE (8 bytes) — path
    0x04,
    0x06,
    0x3F,
    0x00,
    0x50,
    0x15,
    0x44,
    0x0C, // OCTET STRING path (6 bytes)
};

// =============================================================================
// EF.PrKDF — 2 private key entries
//
// Each PrivateKeyInfoObject:
// SEQUENCE {
//   SEQUENCE { UTF8String label }                     -- CommonObjectAttributes
//   SEQUENCE { OCTET STRING id, BIT STRING usage }    -- CommonKeyAttributes
//   [1] CONSTRUCTED {                                 -- typeAttributes
//     SEQUENCE {
//       SEQUENCE { OCTET STRING path }                -- path
//       INTEGER keySizeBits                           -- 3072 = 0x0C00
//     }
//   }
// }
// =============================================================================

// Key 0: label="Sign Key", id=4F797B48 (matches cert2), keySize=3072, path=3F00/0DF5/0116
// CommonObjectAttributes: SEQUENCE { UTF8String "Sign Key"(8) }
//   0C 08 53 69 67 6E 20 4B 65 79 = 10 bytes
//   SEQUENCE: 30 0A [10 bytes] = 12 bytes
// CommonKeyAttributes: SEQUENCE { OCTET STRING id(4), BIT STRING usage }
//   usage BIT STRING: Let's use 03 03 06 20 40 (3 bytes, 6 unused bits, nonRepudiation+digitalSignature)
//   Actually let's keep it simple: 03 02 06 C0 = nonRepudiation(bit0) + digitalSignature(bit1) = 0xC0, 6 unused bits
//   04 04 4F 79 7B 48 03 02 06 C0 = 10 bytes
//   SEQUENCE: 30 0A [10 bytes] = 12 bytes
// TypeAttributes [1]:
//   OCTET STRING path: 04 06 3F 00 0D F5 01 16 = 8 bytes
//   inner SEQUENCE: 30 08 [8 bytes] = 10 bytes
//   INTEGER 3072 = 02 02 0C 00 = 4 bytes
//   outer SEQUENCE: 30 0E [14 bytes] = 16 bytes
//   [1]: A1 10 [16 bytes] = 18 bytes
// Total key0 = 12 + 12 + 18 = 42 = 0x2A
// SEQUENCE: 30 2A

// Key 1: label="Auth Key", id=26DAF750 (matches cert3), keySize=3072, path=3F00/5015/440D
// CommonObjectAttributes: SEQUENCE { UTF8String "Auth Key"(8) }
//   0C 08 41 75 74 68 20 4B 65 79 = 10 bytes
//   SEQUENCE: 30 0A [10 bytes] = 12 bytes
// CommonKeyAttributes: SEQUENCE { OCTET STRING id(4), BIT STRING usage }
//   04 04 26 DA F7 50 03 02 06 C0 = 10 bytes
//   SEQUENCE: 30 0A [10 bytes] = 12 bytes
// TypeAttributes [1]:
//   OCTET STRING path: 04 06 3F 00 50 15 44 0D = 8 bytes
//   inner SEQUENCE: 30 08 [8 bytes] = 10 bytes
//   INTEGER 3072 = 02 02 0C 00 = 4 bytes
//   outer SEQUENCE: 30 0E [14 bytes] = 16 bytes
//   [1]: A1 10 [16 bytes] = 18 bytes
// Total key1 = 12 + 12 + 18 = 42 = 0x2A
// SEQUENCE: 30 2A

// Grand total PrKDF = (2+42) + (2+42) = 88 bytes
constexpr std::array<uint8_t, 88> SAMPLE_PRKDF = {
    // --- Key 0: "Sign Key", id=4F797B48, 3072 bits, path=3F00/0DF5/0116 ---
    0x30,
    0x2A, // SEQUENCE (42 bytes)
    0x30,
    0x0A, // CommonObjectAttributes SEQUENCE (10 bytes)
    0x0C,
    0x08, // UTF8String (8 bytes) "Sign Key"
    0x53,
    0x69,
    0x67,
    0x6E,
    0x20,
    0x4B,
    0x65,
    0x79,
    0x30,
    0x0A, // CommonKeyAttributes SEQUENCE (10 bytes)
    0x04,
    0x04,
    0x4F,
    0x79,
    0x7B,
    0x48, // OCTET STRING id (4 bytes)
    0x03,
    0x02,
    0x06,
    0xC0, // BIT STRING usage (6 unused bits, 0xC0)
    0xA1,
    0x10, // [1] CONSTRUCTED (16 bytes)
    0x30,
    0x0E, // SEQUENCE (14 bytes)
    0x30,
    0x08, // SEQUENCE (8 bytes) — path
    0x04,
    0x06,
    0x3F,
    0x00,
    0x0D,
    0xF5,
    0x01,
    0x16, // OCTET STRING path (6 bytes)
    0x02,
    0x02,
    0x0C,
    0x00, // INTEGER 3072

    // --- Key 1: "Auth Key", id=26DAF750, 3072 bits, path=3F00/5015/440D ---
    0x30,
    0x2A, // SEQUENCE (42 bytes)
    0x30,
    0x0A, // CommonObjectAttributes SEQUENCE (10 bytes)
    0x0C,
    0x08, // UTF8String (8 bytes) "Auth Key"
    0x41,
    0x75,
    0x74,
    0x68,
    0x20,
    0x4B,
    0x65,
    0x79,
    0x30,
    0x0A, // CommonKeyAttributes SEQUENCE (10 bytes)
    0x04,
    0x04,
    0x26,
    0xDA,
    0xF7,
    0x50, // OCTET STRING id (4 bytes)
    0x03,
    0x02,
    0x06,
    0xC0, // BIT STRING usage (6 unused bits, 0xC0)
    0xA1,
    0x10, // [1] CONSTRUCTED (16 bytes)
    0x30,
    0x0E, // SEQUENCE (14 bytes)
    0x30,
    0x08, // SEQUENCE (8 bytes) — path
    0x04,
    0x06,
    0x3F,
    0x00,
    0x50,
    0x15,
    0x44,
    0x0D, // OCTET STRING path (6 bytes)
    0x02,
    0x02,
    0x0C,
    0x00, // INTEGER 3072
};

// =============================================================================
// EF.AODF — 4 PIN auth objects
//
// Each AuthenticationObject:
// SEQUENCE {
//   SEQUENCE { UTF8String label, BIT STRING flags }   -- CommonObjectAttributes
//   SEQUENCE { OCTET STRING authId }                  -- CommonAuthObjectAttributes
//   [1] CONSTRUCTED {                                 -- typeAttributes
//     SEQUENCE {                                      -- PinAttributes
//       BIT STRING pinFlags
//       ENUMERATED pinType
//       INTEGER minLength
//       INTEGER storedLength
//       INTEGER maxLength
//       [0] IMPLICIT INTEGER pinReference             -- tag 0x80
//       SEQUENCE { OCTET STRING path }
//     }
//   }
// }
//
// pinFlags BIT STRING encoding (per PKCS#15):
//   bit 5 = initialized (counting from bit 0 at MSB end of first content byte)
//   Actually in PKCS#15, PinFlags is defined as:
//     case-sensitive(0), local(1), change-disabled(2), unblock-disabled(3),
//     initialized(4), needs-padding(5), ...
//   BIT STRING encoding: 03 02 [unused_bits] [flags_byte]
//   initialized only: bit 4 → 0x08, unused=3 → 03 02 03 08
//   local+initialized: bits 1,4 → 0x48, unused=3 → 03 02 03 48
//
// CommonObjectAttributes flags BIT STRING: just for object flags like private(0), modifiable(1)
// We'll omit this for simplicity — the CommonObjectAttributes only needs label.
// =============================================================================

// PIN 0: "PACE CAN", pinRef=0x02, type=Utf8(2), min=4, stored=12, max=12, path=3F00
//   initialized=true → pinFlags 03 02 03 08
// CommonObjectAttributes: 30 0A 0C 08 "PACE CAN" (8 bytes)
//   PACE CAN = 50 41 43 45 20 43 41 4E
// CommonAuthObjectAttributes: 30 03 04 01 01
//   authId = 01
// PinAttributes:
//   03 02 03 08          -- pinFlags (initialized)
//   0A 01 02             -- ENUMERATED Utf8(2)
//   02 01 04             -- INTEGER minLength 4
//   02 01 0C             -- INTEGER storedLength 12
//   02 01 0C             -- INTEGER maxLength 12
//   80 01 02             -- [0] IMPLICIT pinReference 0x02
//   30 04 04 02 3F 00    -- SEQUENCE { OCTET STRING path 3F00 }
// PinAttrs inner = 4+3+3+3+3+3+6 = 25 = 0x19
// SEQUENCE: 30 19 [25 bytes] = 27 bytes
// [1]: A1 1B [27 bytes] = 29 bytes
// Total PIN0 = 12 + 5 + 29 = 46 = 0x2E
// SEQUENCE: 30 2E

// PIN 1: "User PIN", pinRef=0x86, type=Ascii(1), min=6, stored=6, max=6, path=3F00
//   local+initialized → pinFlags 03 02 03 48
// CommonObjectAttributes: 30 0A 0C 08 "User PIN" (8 bytes)
//   User PIN = 55 73 65 72 20 50 49 4E
// CommonAuthObjectAttributes: 30 03 04 01 02
//   authId = 02
// PinAttributes:
//   03 02 03 48          -- pinFlags (local+initialized)
//   0A 01 01             -- ENUMERATED Ascii(1)
//   02 01 06             -- INTEGER minLength 6
//   02 01 06             -- INTEGER storedLength 6
//   02 01 06             -- INTEGER maxLength 6
//   80 01 86             -- [0] IMPLICIT pinReference 0x86
//   30 04 04 02 3F 00    -- SEQUENCE { OCTET STRING path 3F00 }
// PinAttrs inner = 4+3+3+3+3+3+6 = 25 = 0x19
// [1]: A1 1B [27 bytes] = 29 bytes
// Total PIN1 = 12 + 5 + 29 = 46 = 0x2E

// PIN 2: "Global PUK", pinRef=0x93, type=Ascii(1), min=8, stored=8, max=8, path=3F00
//   initialized → pinFlags 03 02 03 08
// CommonObjectAttributes: 30 0C 0C 0A "Global PUK" (10 bytes)
//   Global PUK = 47 6C 6F 62 61 6C 20 50 55 4B
// CommonAuthObjectAttributes: 30 03 04 01 03
//   authId = 03
// PinAttributes:
//   03 02 03 08          -- pinFlags (initialized)
//   0A 01 01             -- ENUMERATED Ascii(1)
//   02 01 08             -- INTEGER minLength 8
//   02 01 08             -- INTEGER storedLength 8
//   02 01 08             -- INTEGER maxLength 8
//   80 01 93             -- [0] IMPLICIT pinReference 0x93
//   30 04 04 02 3F 00    -- SEQUENCE { OCTET STRING path 3F00 }
// PinAttrs inner = 4+3+3+3+3+3+6 = 25 = 0x19
// [1]: A1 1B [27 bytes] = 29 bytes
// Total PIN2 = 14 + 5 + 29 = 48 = 0x30

// PIN 3: "Signature PIN", pinRef=0x92, type=Ascii(1), min=6, stored=6, max=6, path=3F00/0DF5
//   local+initialized → pinFlags 03 02 03 48
// CommonObjectAttributes: 30 0F 0C 0D "Signature PIN" (13 bytes)
//   Signature PIN = 53 69 67 6E 61 74 75 72 65 20 50 49 4E
// CommonAuthObjectAttributes: 30 03 04 01 04
//   authId = 04
// PinAttributes:
//   03 02 03 48          -- pinFlags (local+initialized)
//   0A 01 01             -- ENUMERATED Ascii(1)
//   02 01 06             -- INTEGER minLength 6
//   02 01 06             -- INTEGER storedLength 6
//   02 01 06             -- INTEGER maxLength 6
//   80 01 92             -- [0] IMPLICIT pinReference 0x92
//   30 06 04 04 3F 00 0D F5  -- SEQUENCE { OCTET STRING path 3F00/0DF5 (4 bytes) }
// PinAttrs inner = 4+3+3+3+3+3+8 = 27 = 0x1B
// SEQUENCE: 30 1B [27 bytes] = 29 bytes
// [1]: A1 1D [29 bytes] = 31 bytes
// Total PIN3 = 17 + 5 + 31 = 53 = 0x35

// Grand total AODF = (2+46) + (2+46) + (2+48) + (2+53) = 48+48+50+55 = 201 bytes
constexpr std::array<uint8_t, 201> SAMPLE_AODF = {
    // --- PIN 0: "PACE CAN", pinRef=0x02, Utf8, min=4, stored=12, max=12, initialized ---
    0x30,
    0x2E, // SEQUENCE (46 bytes)
    0x30,
    0x0A, // CommonObjectAttributes SEQUENCE (10 bytes)
    0x0C,
    0x08, // UTF8String (8 bytes) "PACE CAN"
    0x50,
    0x41,
    0x43,
    0x45,
    0x20,
    0x43,
    0x41,
    0x4E,
    0x30,
    0x03, // CommonAuthObjectAttributes SEQUENCE (3 bytes)
    0x04,
    0x01,
    0x01, // OCTET STRING authId = 01
    0xA1,
    0x1B, // [1] CONSTRUCTED (27 bytes)
    0x30,
    0x19, // SEQUENCE PinAttributes (25 bytes)
    0x03,
    0x02,
    0x03,
    0x08, // BIT STRING pinFlags (initialized)
    0x0A,
    0x01,
    0x02, // ENUMERATED pinType Utf8(2)
    0x02,
    0x01,
    0x04, // INTEGER minLength 4
    0x02,
    0x01,
    0x0C, // INTEGER storedLength 12
    0x02,
    0x01,
    0x0C, // INTEGER maxLength 12
    0x80,
    0x01,
    0x02, // [0] IMPLICIT pinReference 0x02
    0x30,
    0x04, // SEQUENCE path
    0x04,
    0x02,
    0x3F,
    0x00, // OCTET STRING path 3F00

    // --- PIN 1: "User PIN", pinRef=0x86, Ascii, min=6, stored=6, max=6, local+initialized ---
    0x30,
    0x2E, // SEQUENCE (46 bytes)
    0x30,
    0x0A, // CommonObjectAttributes SEQUENCE (10 bytes)
    0x0C,
    0x08, // UTF8String (8 bytes) "User PIN"
    0x55,
    0x73,
    0x65,
    0x72,
    0x20,
    0x50,
    0x49,
    0x4E,
    0x30,
    0x03, // CommonAuthObjectAttributes SEQUENCE (3 bytes)
    0x04,
    0x01,
    0x02, // OCTET STRING authId = 02
    0xA1,
    0x1B, // [1] CONSTRUCTED (27 bytes)
    0x30,
    0x19, // SEQUENCE PinAttributes (25 bytes)
    0x03,
    0x02,
    0x03,
    0x48, // BIT STRING pinFlags (local+initialized)
    0x0A,
    0x01,
    0x01, // ENUMERATED pinType Ascii(1)
    0x02,
    0x01,
    0x06, // INTEGER minLength 6
    0x02,
    0x01,
    0x06, // INTEGER storedLength 6
    0x02,
    0x01,
    0x06, // INTEGER maxLength 6
    0x80,
    0x01,
    0x86, // [0] IMPLICIT pinReference 0x86
    0x30,
    0x04, // SEQUENCE path
    0x04,
    0x02,
    0x3F,
    0x00, // OCTET STRING path 3F00

    // --- PIN 2: "Global PUK", pinRef=0x93, Ascii, min=8, stored=8, max=8, initialized ---
    0x30,
    0x30, // SEQUENCE (48 bytes)
    0x30,
    0x0C, // CommonObjectAttributes SEQUENCE (12 bytes)
    0x0C,
    0x0A, // UTF8String (10 bytes) "Global PUK"
    0x47,
    0x6C,
    0x6F,
    0x62,
    0x61,
    0x6C,
    0x20,
    0x50,
    0x55,
    0x4B,
    0x30,
    0x03, // CommonAuthObjectAttributes SEQUENCE (3 bytes)
    0x04,
    0x01,
    0x03, // OCTET STRING authId = 03
    0xA1,
    0x1B, // [1] CONSTRUCTED (27 bytes)
    0x30,
    0x19, // SEQUENCE PinAttributes (25 bytes)
    0x03,
    0x02,
    0x03,
    0x08, // BIT STRING pinFlags (initialized)
    0x0A,
    0x01,
    0x01, // ENUMERATED pinType Ascii(1)
    0x02,
    0x01,
    0x08, // INTEGER minLength 8
    0x02,
    0x01,
    0x08, // INTEGER storedLength 8
    0x02,
    0x01,
    0x08, // INTEGER maxLength 8
    0x80,
    0x01,
    0x93, // [0] IMPLICIT pinReference 0x93
    0x30,
    0x04, // SEQUENCE path
    0x04,
    0x02,
    0x3F,
    0x00, // OCTET STRING path 3F00

    // --- PIN 3: "Signature PIN", pinRef=0x92, Ascii, min=6, stored=6, max=6, local+initialized ---
    0x30,
    0x35, // SEQUENCE (53 bytes)
    0x30,
    0x0F, // CommonObjectAttributes SEQUENCE (15 bytes)
    0x0C,
    0x0D, // UTF8String (13 bytes) "Signature PIN"
    0x53,
    0x69,
    0x67,
    0x6E,
    0x61,
    0x74,
    0x75,
    0x72,
    0x65,
    0x20,
    0x50,
    0x49,
    0x4E,
    0x30,
    0x03, // CommonAuthObjectAttributes SEQUENCE (3 bytes)
    0x04,
    0x01,
    0x04, // OCTET STRING authId = 04
    0xA1,
    0x1D, // [1] CONSTRUCTED (29 bytes)
    0x30,
    0x1B, // SEQUENCE PinAttributes (27 bytes)
    0x03,
    0x02,
    0x03,
    0x48, // BIT STRING pinFlags (local+initialized)
    0x0A,
    0x01,
    0x01, // ENUMERATED pinType Ascii(1)
    0x02,
    0x01,
    0x06, // INTEGER minLength 6
    0x02,
    0x01,
    0x06, // INTEGER storedLength 6
    0x02,
    0x01,
    0x06, // INTEGER maxLength 6
    0x80,
    0x01,
    0x92, // [0] IMPLICIT pinReference 0x92
    0x30,
    0x06, // SEQUENCE path
    0x04,
    0x04,
    0x3F,
    0x00,
    0x0D,
    0xF5, // OCTET STRING path 3F00/0DF5
};

} // namespace pkcs15::test_vectors
