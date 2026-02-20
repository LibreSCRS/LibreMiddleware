// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright hirashix0@proton.me

#ifndef SMARTCARD_TLV_H
#define SMARTCARD_TLV_H

#include <cstdint>
#include <string>
#include <vector>

namespace smartcard {

// Custom Little-Endian 16-bit TLV used by Serbian cards (eID, vehicle, health)
struct TLVField {
    uint16_t tag;
    std::vector<uint8_t> value;
    std::string asString() const;  // UTF-8 decode
};

std::vector<TLVField> parseTLV(const uint8_t* data, size_t length);

// Convenience: find field by tag, return value as UTF-8 string (empty if not found)
std::string findString(const std::vector<TLVField>& fields, uint16_t tag);
std::vector<uint8_t> findBytes(const std::vector<TLVField>& fields, uint16_t tag);

} // namespace smartcard

#endif // SMARTCARD_TLV_H
