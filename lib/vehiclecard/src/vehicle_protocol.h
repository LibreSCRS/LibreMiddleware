// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright hirashix0@proton.me

#ifndef VEHICLECARD_VEHICLE_PROTOCOL_H
#define VEHICLECARD_VEHICLE_PROTOCOL_H

#include <cstdint>
#include <vector>

namespace vehiclecard::protocol {

// AID selection sequences for vehicle registration cards.
// Three sequences are tried in order. Each sequence has 3 SELECT commands.
// The third command in each sequence uses P2=0x0C instead of P2=0x00.

// Sequence 1
inline const std::vector<uint8_t> SEQ1_CMD1 = {0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00};
inline const std::vector<uint8_t> SEQ1_CMD2 = {0xA0, 0x00, 0x00, 0x00, 0x77, 0x01, 0x08, 0x00,
                                               0x07, 0x00, 0x00, 0xFE, 0x00, 0x00, 0x01, 0x00};
inline const std::vector<uint8_t> SEQ1_CMD3 = {0xA0, 0x00, 0x00, 0x00, 0x77, 0x01, 0x08, 0x00,
                                               0x07, 0x00, 0x00, 0xFE, 0x00, 0x00, 0xAD, 0xF2};

// Sequence 2
inline const std::vector<uint8_t> SEQ2_CMD1 = {0xA0, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00};
inline const std::vector<uint8_t> SEQ2_CMD2 = {0xF3, 0x81, 0x00, 0x00, 0x02, 0x53, 0x45,
                                               0x52, 0x56, 0x4C, 0x04, 0x02, 0x01};
// SEQ2_CMD3 is the same as SEQ1_CMD3

// Sequence 3
inline const std::vector<uint8_t> SEQ3_CMD1 = {0xA0, 0x00, 0x00, 0x00, 0x18, 0x43, 0x4D, 0x00};
inline const std::vector<uint8_t> SEQ3_CMD2 = {0xA0, 0x00, 0x00, 0x00, 0x18, 0x34, 0x14, 0x01,
                                               0x00, 0x65, 0x56, 0x4C, 0x2D, 0x30, 0x30, 0x31};
inline const std::vector<uint8_t> SEQ3_CMD3 = {0xA0, 0x00, 0x00, 0x00, 0x18, 0x65, 0x56, 0x4C, 0x2D, 0x30, 0x30, 0x31};

// File IDs for vehicle registration data (4 files)
inline const std::vector<uint8_t> FILE_DOCUMENT_0 = {0xD0, 0x01};
inline const std::vector<uint8_t> FILE_DOCUMENT_1 = {0xD0, 0x11};
inline const std::vector<uint8_t> FILE_DOCUMENT_2 = {0xD0, 0x21};
inline const std::vector<uint8_t> FILE_DOCUMENT_3 = {0xD0, 0x31};

// File header size to read
constexpr uint8_t FILE_HEADER_SIZE = 0x20;

// Read chunk size for vehicle cards
constexpr uint8_t READ_CHUNK_SIZE = 0x64; // 100 bytes

} // namespace vehiclecard::protocol

#endif // VEHICLECARD_VEHICLE_PROTOCOL_H
