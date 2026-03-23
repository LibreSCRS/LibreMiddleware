// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright hirashix0@proton.me

#pragma once

#include <cstdint>
#include <initializer_list>
#include <string>
#include <vector>

namespace smartcard {

// ISO 7816-4 BER-TLV field (used by Serbian vehicle registration cards)
struct BERField
{
    uint32_t tag = 0;
    bool constructed = false;
    std::vector<uint8_t> value;     // raw value (for primitive fields)
    std::vector<BERField> children; // nested fields (for constructed fields)

    std::string asString() const;
};

// Parse BER-TLV data. Returns a synthetic root node containing all top-level fields as children.
BERField parseBER(const uint8_t* data, size_t length);

// Merge two BER trees: appends src's children into dst
void mergeBER(BERField& dst, const BERField& src);

// Access nested field by tag path, e.g. {0x71, 0xA3, 0x87}
std::string berFindString(const BERField& root, std::initializer_list<uint32_t> path);
std::vector<uint8_t> berFindBytes(const BERField& root, std::initializer_list<uint32_t> path);

} // namespace smartcard
