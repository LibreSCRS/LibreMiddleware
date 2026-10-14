// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

// EF.PrKDF (FID 4400) of a Serbian eID test card, hardware-scanned 2026-09-03,
// status words stripped and the zero tail of the file cut. One record:
//
//   0:d=0  cons: cont [ 0 ]          <- privateECKey
//   2:d=1  cons:  SEQUENCE            -- CommonObjectAttributes
//   4:d=2  prim:   UTF8STRING  f7134b02-7cd6-4557-860a-f54eb9cd1d41
//  42:d=2  prim:   BIT STRING  06 C0  -- CommonObjectFlags
//  46:d=2  prim:   OCTET STRING 06    -- authId
//  49:d=2  prim:   INTEGER     01     -- userConsent
//  52:d=1  cons:  SEQUENCE            -- CommonKeyAttributes
//  54:d=2  prim:   OCTET STRING F7134B027CD64557860AF54EB9CD1D41  -- id
//  72:d=2  prim:   BIT STRING  00 64 81  -- usage: decrypt|sign|unwrap, derive (bit 8),
//                                        -- and bit 15, which PKCS#15 does not define
//  77:d=2  prim:   BIT STRING  04 90  -- access flags
//  81:d=2  prim:   INTEGER     47     -- keyReference
//  84:d=1  cons:  cont [ 1 ]          -- typeAttributes: the path only, no field size
//  88:d=4  prim:     OCTET STRING 3F005015  -- the DF the key lives in, not a key file
//
// What it settles: the derive bit sits in the THIRD byte of the usage BIT
// STRING, next to a bit no standard names; and the key is addressed by its
// reference inside a DF, so the path's last two bytes (5015) are the DF's,
// shared by every key in it.

#include <cstdint>
#include <vector>

namespace pkcs15::test_vectors {

inline const std::vector<uint8_t> RS_EID_EC_PRKDF = {
    0xA0, 0x5E, 0x30, 0x30, 0x0C, 0x24, 0x66, 0x37, 0x31, 0x33, 0x34, 0x62, 0x30, 0x32, 0x2D, 0x37,
    0x63, 0x64, 0x36, 0x2D, 0x34, 0x35, 0x35, 0x37, 0x2D, 0x38, 0x36, 0x30, 0x61, 0x2D, 0x66, 0x35,
    0x34, 0x65, 0x62, 0x39, 0x63, 0x64, 0x31, 0x64, 0x34, 0x31, 0x03, 0x02, 0x06, 0xC0, 0x04, 0x01,
    0x06, 0x02, 0x01, 0x01, 0x30, 0x1E, 0x04, 0x10, 0xF7, 0x13, 0x4B, 0x02, 0x7C, 0xD6, 0x45, 0x57,
    0x86, 0x0A, 0xF5, 0x4E, 0xB9, 0xCD, 0x1D, 0x41, 0x03, 0x03, 0x00, 0x64, 0x81, 0x03, 0x02, 0x04,
    0x90, 0x02, 0x01, 0x47, 0xA1, 0x0A, 0x30, 0x08, 0x30, 0x06, 0x04, 0x04, 0x3F, 0x00, 0x50, 0x15};

} // namespace pkcs15::test_vectors
