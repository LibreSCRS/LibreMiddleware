// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

// EF.PuKDF holding a single EC public key, hardware-scanned 2026-08-20.
//
// Raw bytes of a PKCS#15 EF.PuKDF (FID 4401), status words stripped. The
// PublicKeyType CHOICE has the same shape as PrivateKeyType, and the same
// trap: publicRSAKey is the untagged SEQUENCE, publicECKey is [0].
//
//   0:d=0  cons: cont [ 0 ]          <- PublicKeyType CHOICE = publicECKey
//   2:d=1  cons:  SEQUENCE            -- CommonObjectAttributes
//   4:d=2  prim:   UTF8STRING  34b8bc40-4afc-4c45-be0f-8524fc10d80f
//  42:d=2  prim:   BIT STRING  06 40
//  46:d=1  cons:  SEQUENCE            -- CommonKeyAttributes
//  48:d=2  prim:   OCTET STRING 34B8BC404AFC4C45BE0F8524FC10D80F  -- id
//  66:d=2  prim:   BIT STRING  00 0B  -- usage: wrap|verify|verifyRecover
//  70:d=2  prim:   BOOLEAN     0      -- native
//  73:d=2  prim:   INTEGER     47     -- keyReference
//  76:d=1  cons:  cont [ 1 ]          -- typeAttributes, [1] for EC too
//  82:d=4  prim:     OCTET STRING 3F005015440D  -- path
//
// The id is the SAME as the private key's in EF.PrKDF, which is what pairs
// them; the path points at the file holding the SubjectPublicKeyInfo. This is
// the only source of the public key that does not require parsing a
// certificate.

#include <cstdint>
#include <vector>

namespace pkcs15::test_vectors {

// EF.PuKDF: one [0] publicECKey record pointing at 3F00/5015/440D.
inline const std::vector<uint8_t> EC_PUKDF_SINGLE_KEY = {
    0xA0, 0x58, 0x30, 0x2A, 0x0C, 0x24, 0x33, 0x34, 0x62, 0x38, 0x62, 0x63, 0x34, 0x30, 0x2D, 0x34, 0x61, 0x66,
    0x63, 0x2D, 0x34, 0x63, 0x34, 0x35, 0x2D, 0x62, 0x65, 0x30, 0x66, 0x2D, 0x38, 0x35, 0x32, 0x34, 0x66, 0x63,
    0x31, 0x30, 0x64, 0x38, 0x30, 0x66, 0x03, 0x02, 0x06, 0x40, 0x30, 0x1C, 0x04, 0x10, 0x34, 0xB8, 0xBC, 0x40,
    0x4A, 0xFC, 0x4C, 0x45, 0xBE, 0x0F, 0x85, 0x24, 0xFC, 0x10, 0xD8, 0x0F, 0x03, 0x02, 0x00, 0x0B, 0x01, 0x01,
    0x00, 0x02, 0x01, 0x47, 0xA1, 0x0C, 0x30, 0x0A, 0x30, 0x08, 0x04, 0x06, 0x3F, 0x00, 0x50, 0x15, 0x44, 0x0D};

} // namespace pkcs15::test_vectors
