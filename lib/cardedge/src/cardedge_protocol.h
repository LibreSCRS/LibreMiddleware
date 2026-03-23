// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

#include <cstdint>
#include <vector>

namespace cardedge::protocol {

// CardEdge PKI applet AID — shared by Serbian eID (Gemalto/IF2020), PKS Chamber
// of Commerce card, Serbian health insurance card, and other Gemalto IDPrime-based cards.
inline const std::vector<uint8_t> AID_PKCS15 = {0xA0, 0x00, 0x00, 0x00, 0x63, 0x50, 0x4B, 0x43, 0x53, 0x2D, 0x31, 0x35};

// User PIN slot reference (same across all known CardEdge cards).
constexpr uint8_t PKI_PIN_REFERENCE = 0x80;

// PINs are null-padded to this length before being sent to the card.
constexpr uint8_t PIN_MAX_LENGTH = 8;

// Maximum retry count; a successful verification resets the counter to this value.
constexpr uint8_t PIN_MAX_RETRIES = 3;

// Root directory FID inside the PKI applet filesystem.
constexpr uint16_t PKI_ROOT_DIR_FID = 0x7000;

// Maximum bytes per READ BINARY on the CardEdge applet (internal buffer limit).
constexpr uint8_t PKI_READ_CHUNK = 0x80;

// MSE SET algorithm reference byte for RSA-2048 with PKCS#1 v1.5 padding.
constexpr uint8_t MSE_ALG_RSA2048 = 0x02;

// CardEdge directory file layout.
// Header (10 bytes): LeftFiles(1) LeftDirs(1) NextFileFID(2 LE) NextDirFID(2 LE)
//                    EntriesCount(2 LE) WriteACL(2 LE)
// Entry  (12 bytes): Name(8) FID(2 LE) IsDir(1) pad(1)
constexpr size_t CE_DIR_HEADER_SIZE = 10;
constexpr size_t CE_DIR_ENTRY_SIZE = 12;

// PKCS#15 container map (cmapfile) record layout — 86 bytes per entry.
// Based on Windows CNG cardmod.h CONTAINER_MAP_RECORD:
//   WCHAR wszGuid[40]             = 80 bytes (UTF-16LE, null-padded)
//   BYTE  bFlags                  =  1 byte  (bit 0 = valid, bit 1 = default container)
//   BYTE  bReserved               =  1 byte
//   WORD  wSigKeySizeBits         =  2 bytes LE (0 if no signature key)
//   WORD  wKeyExchangeKeySizeBits =  2 bytes LE (0 if no key-exchange key)
constexpr size_t CMAP_RECORD_SIZE = 86;
constexpr size_t CMAP_FLAGS_OFFSET = 80;
constexpr size_t CMAP_SIG_SIZE_OFFSET = 82;
constexpr size_t CMAP_KX_SIZE_OFFSET = 84;
constexpr uint8_t CMAP_VALID_CONTAINER = 0x01;

// Private key FID formula (CardEdge GET_KEY_FID):
//   FID = CE_KEYS_BASE_FID
//       | ((containerIndex << 4) & 0x0FF0)
//       | ((keyPairId      << 2) & 0x000C)
//       | CE_KEY_KIND_PRIVATE
constexpr uint16_t CE_KEYS_BASE_FID = 0x6000;
constexpr uint16_t CE_KEY_KIND_PRIVATE = 1;
constexpr uint16_t AT_KEYEXCHANGE = 1; // key-exchange (encryption) key pair
constexpr uint16_t AT_SIGNATURE = 2;   // digital-signature key pair

inline uint16_t privateKeyFID(uint8_t containerIndex, uint16_t keyPairId)
{
    return static_cast<uint16_t>(CE_KEYS_BASE_FID | ((static_cast<uint16_t>(containerIndex) << 4) & 0x0FF0u) |
                                 ((keyPairId << 2) & 0x000Cu) | CE_KEY_KIND_PRIVATE);
}

} // namespace cardedge::protocol
