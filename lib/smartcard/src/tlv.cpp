// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright hirashix0@proton.me

#include "smartcard/tlv.h"

namespace smartcard {

std::string TLVField::asString() const
{
    return std::string(value.begin(), value.end());
}

std::vector<TLVField> parseTLV(const uint8_t* data, size_t length)
{
    std::vector<TLVField> fields;
    size_t offset = 0;

    while (offset + 4 <= length) {
        // Little-endian 16-bit tag
        uint16_t tag = static_cast<uint16_t>(data[offset]) |
                       (static_cast<uint16_t>(data[offset + 1]) << 8);
        offset += 2;

        // Little-endian 16-bit length
        uint16_t valueLen = static_cast<uint16_t>(data[offset]) |
                            (static_cast<uint16_t>(data[offset + 1]) << 8);
        offset += 2;

        if (offset + valueLen > length) {
            break;
        }

        TLVField field;
        field.tag = tag;
        field.value.assign(data + offset, data + offset + valueLen);
        fields.push_back(std::move(field));

        offset += valueLen;
    }

    return fields;
}

std::string findString(const std::vector<TLVField>& fields, uint16_t tag)
{
    for (const auto& field : fields) {
        if (field.tag == tag) {
            return field.asString();
        }
    }
    return {};
}

std::vector<uint8_t> findBytes(const std::vector<TLVField>& fields, uint16_t tag)
{
    for (const auto& field : fields) {
        if (field.tag == tag) {
            return field.value;
        }
    }
    return {};
}

} // namespace smartcard
