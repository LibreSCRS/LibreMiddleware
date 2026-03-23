// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright hirashix0@proton.me

#include "smartcard/ber.h"
#include <stdexcept>

namespace smartcard {

std::string BERField::asString() const
{
    return std::string(value.begin(), value.end());
}

namespace {

// Parse a BER tag (1, 2, or 3 bytes). Returns tag value and advances offset.
uint32_t parseTag(const uint8_t* data, size_t length, size_t& offset)
{
    if (offset >= length) {
        throw std::runtime_error("BER: unexpected end of data parsing tag");
    }

    uint8_t firstByte = data[offset++];
    if ((firstByte & 0x1F) != 0x1F) {
        // Single-byte tag
        return firstByte;
    }

    // Multi-byte tag: subsequent bytes have bit 7 set (continuation)
    // ISO 7816 tags are at most 3 bytes total — limit continuation bytes to prevent overflow
    uint32_t tag = firstByte;
    int continuationCount = 0;
    do {
        if (offset >= length || ++continuationCount > 3) {
            throw std::runtime_error("BER: tag too long or unexpected end of data");
        }
        tag = (tag << 8) | data[offset];
    } while (data[offset++] & 0x80);

    return tag;
}

// Parse BER length. Returns length value and advances offset.
size_t parseLength(const uint8_t* data, size_t length, size_t& offset)
{
    if (offset >= length) {
        throw std::runtime_error("BER: unexpected end of data parsing length");
    }

    uint8_t firstByte = data[offset++];

    if (firstByte < 0x80) {
        // Short form
        return firstByte;
    }

    if (firstByte == 0x80) {
        // Indefinite length not supported
        throw std::runtime_error("BER: indefinite length not supported");
    }

    // Long form: firstByte & 0x7F = number of subsequent bytes
    size_t numBytes = firstByte & 0x7F;
    if (numBytes > 4 || offset + numBytes > length) {
        throw std::runtime_error("BER: invalid length encoding");
    }

    size_t len = 0;
    for (size_t i = 0; i < numBytes; i++) {
        len = (len << 8) | data[offset++];
    }
    return len;
}

// Recursively parse BER fields
std::vector<BERField> parseFields(const uint8_t* data, size_t length)
{
    std::vector<BERField> fields;
    size_t offset = 0;

    while (offset < length) {
        // Skip padding bytes (0x00 or 0xFF)
        if (data[offset] == 0x00 || data[offset] == 0xFF) {
            offset++;
            continue;
        }

        BERField field;

        // Check if constructed before parsing tag
        bool isConstructed = (data[offset] & 0x20) != 0;

        field.tag = parseTag(data, length, offset);
        field.constructed = isConstructed;

        size_t valueLen = parseLength(data, length, offset);

        if (offset + valueLen > length) {
            break;
        }

        if (field.constructed) {
            field.children = parseFields(data + offset, valueLen);
        } else {
            field.value.assign(data + offset, data + offset + valueLen);
        }

        offset += valueLen;
        fields.push_back(std::move(field));
    }

    return fields;
}

} // anonymous namespace

BERField parseBER(const uint8_t* data, size_t length)
{
    BERField root;
    root.tag = 0;
    root.constructed = true;
    root.children = parseFields(data, length);
    return root;
}

void mergeBER(BERField& dst, const BERField& src)
{
    for (const auto& child : src.children) {
        // Check if a child with same tag already exists
        bool found = false;
        for (auto& existing : dst.children) {
            if (existing.tag == child.tag && existing.constructed && child.constructed) {
                // Merge children of constructed fields with same tag
                for (const auto& grandchild : child.children) {
                    existing.children.push_back(grandchild);
                }
                found = true;
                break;
            }
        }
        if (!found) {
            dst.children.push_back(child);
        }
    }
}

std::string berFindString(const BERField& root, std::initializer_list<uint32_t> path)
{
    const BERField* current = &root;

    for (uint32_t tag : path) {
        bool found = false;
        for (const auto& child : current->children) {
            if (child.tag == tag) {
                current = &child;
                found = true;
                break;
            }
        }
        if (!found) {
            return {};
        }
    }

    return current->asString();
}

std::vector<uint8_t> berFindBytes(const BERField& root, std::initializer_list<uint32_t> path)
{
    const BERField* current = &root;

    for (uint32_t tag : path) {
        bool found = false;
        for (const auto& child : current->children) {
            if (child.tag == tag) {
                current = &child;
                found = true;
                break;
            }
        }
        if (!found) {
            return {};
        }
    }

    return current->value;
}

} // namespace smartcard
