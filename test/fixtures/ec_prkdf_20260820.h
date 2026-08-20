// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

// EF.PrKDF holding a single EC private key, hardware-scanned 2026-08-20.
//
// Raw bytes of a PKCS#15 EF.PrKDF (FID 4400), status words stripped. ONE
// record, and the reason this fixture exists is its outer tag:
//
//   0:d=0  cons: cont [ 0 ]          <- PrivateKeyType CHOICE = privateECKey
//   2:d=1  cons:  SEQUENCE            -- CommonObjectAttributes
//   4:d=2  prim:   UTF8STRING  34b8bc40-4afc-4c45-be0f-8524fc10d80f
//  42:d=2  prim:   BIT STRING  06 C0  -- CommonObjectFlags
//  46:d=2  prim:   OCTET STRING 06    -- authId: the PIN protecting this key
//  49:d=2  prim:   INTEGER     01     -- userConsent: PIN per operation
//  52:d=1  cons:  SEQUENCE            -- CommonKeyAttributes
//  54:d=2  prim:   OCTET STRING 34B8BC404AFC4C45BE0F8524FC10D80F  -- id
//  72:d=2  prim:   BIT STRING  02 64  -- usage: decrypt|sign|unwrap
//  76:d=2  prim:   BIT STRING  04 90  -- access flags
//  80:d=2  prim:   INTEGER     47     -- keyReference
//  83:d=1  cons:  cont [ 1 ]          <- typeAttributes: [1] FOR EC TOO
//  87:d=3  cons:    SEQUENCE
//  89:d=4  prim:     OCTET STRING 3F005015  -- path
//
// Two things this record settles, both of which a parser can get wrong while
// looking right:
//
//   * PrivateKeyType is a CHOICE. privateRSAKey is the UNTAGGED SEQUENCE
//     (0x30); privateECKey is [0] (0xA0). A reader that accepts only 0x30
//     silently drops every EC key on the card and returns an empty list --
//     which downstream reads as "this card has no keys", not as a parse
//     failure.
//   * typeAttributes is [1] for BOTH key types (ISO 7816-15). It is NOT a
//     discriminator, and code that infers "has [1] therefore RSA" labels this
//     record RSA. The key type is the OUTER CHOICE tag and nothing else.
//
// The record is fully conformant: ECPrivateKeyAttributes legitimately carries
// no modulusLength, so an absent key size is not evidence of a truncated read.

#include <cstdint>
#include <vector>

namespace pkcs15::test_vectors {

// EF.PrKDF: one [0] privateECKey record (P-384 key, keyReference 0x47).
inline const std::vector<uint8_t> EC_PRKDF_SINGLE_KEY = {
    0xA0, 0x5D, 0x30, 0x30, 0x0C, 0x24, 0x33, 0x34, 0x62, 0x38, 0x62, 0x63, 0x34, 0x30, 0x2D, 0x34, 0x61, 0x66, 0x63,
    0x2D, 0x34, 0x63, 0x34, 0x35, 0x2D, 0x62, 0x65, 0x30, 0x66, 0x2D, 0x38, 0x35, 0x32, 0x34, 0x66, 0x63, 0x31, 0x30,
    0x64, 0x38, 0x30, 0x66, 0x03, 0x02, 0x06, 0xC0, 0x04, 0x01, 0x06, 0x02, 0x01, 0x01, 0x30, 0x1D, 0x04, 0x10, 0x34,
    0xB8, 0xBC, 0x40, 0x4A, 0xFC, 0x4C, 0x45, 0xBE, 0x0F, 0x85, 0x24, 0xFC, 0x10, 0xD8, 0x0F, 0x03, 0x02, 0x02, 0x64,
    0x03, 0x02, 0x04, 0x90, 0x02, 0x01, 0x47, 0xA1, 0x0A, 0x30, 0x08, 0x30, 0x06, 0x04, 0x04, 0x3F, 0x00, 0x50, 0x15};

} // namespace pkcs15::test_vectors
