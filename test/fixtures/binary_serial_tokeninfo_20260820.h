// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

// EF.TokenInfo whose serialNumber is BINARY, hardware-scanned 2026-08-20.
//
// Raw bytes of a PKCS#15 EF.TokenInfo (FID 5032), status words stripped:
//
//   0:d=0  cons: SEQUENCE
//   2:d=1  prim:  INTEGER      00
//   5:d=1  prim:  OCTET STRING 84 08 2077B202775C2B10   <- serialNumber
//  17:d=1  prim:  UTF8STRING   cv cryptovision gmbh (c) v1.1j
//  49:d=1  prim:  cont [ 0 ]   SSCDv1 PACE MD
//  65:d=1  prim:  BIT STRING
//
// The serialNumber is not text. It carries a nested ISO 7816 `84` TLV whose
// value, 2077B202775C2B10, is the card's ICCSN -- the same eight bytes EF.D003
// returns and the same the CPLC reports as icFabDate/icSerial/batch, so the
// expected reading has two independent confirmations off the same card.
//
// Rendered as characters those bytes are unprintable, and they do not stay
// contained: CK_TOKEN_INFO.serialNumber feeds the `serial` field of every
// pkcs11: URI the token publishes, which p11-kit and every URI consumer parse,
// and the same string reaches generated documentation -- one binary byte makes
// the whole file invalid UTF-8.

#include <cstdint>
#include <vector>

namespace pkcs15::test_vectors {

// EF.TokenInfo with a binary serialNumber wrapped in an ISO 7816 `84` TLV.
inline const std::vector<uint8_t> BINARY_SERIAL_TOKENINFO = {
    0x30, 0x43, 0x02, 0x01, 0x00, 0x04, 0x0A, 0x84, 0x08, 0x20, 0x77, 0xB2, 0x02, 0x77, 0x5C, 0x2B, 0x10, 0x0C,
    0x1E, 0x63, 0x76, 0x20, 0x63, 0x72, 0x79, 0x70, 0x74, 0x6F, 0x76, 0x69, 0x73, 0x69, 0x6F, 0x6E, 0x20, 0x67,
    0x6D, 0x62, 0x68, 0x20, 0x28, 0x63, 0x29, 0x20, 0x76, 0x31, 0x2E, 0x31, 0x6A, 0x80, 0x0E, 0x53, 0x53, 0x43,
    0x44, 0x76, 0x31, 0x20, 0x50, 0x41, 0x43, 0x45, 0x20, 0x4D, 0x44, 0x03, 0x02, 0x04, 0x70};

} // namespace pkcs15::test_vectors
