// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "ber.h"
#include <stdexcept>

namespace LibreSCRS::SmartCard::Internal {

std::string BERField::asString() const
{
    return std::string(value.begin(), value.end());
}

// Parse a BER tag (1, 2, or 3 bytes). Reports failure through the result.
TagResult tryParseTag(const uint8_t* data, size_t length, size_t pos) noexcept
{
    TagResult out;
    if (pos >= length) {
        return out;
    }

    const uint8_t firstByte = data[pos++];
    if ((firstByte & 0x1F) != 0x1F) {
        // Single-byte tag
        out.tag = firstByte;
        out.next = pos;
        out.ok = true;
        return out;
    }

    // Multi-byte tag: subsequent bytes have bit 7 set (continuation)
    // ISO 7816 tags are at most 3 bytes total — limit continuation bytes to prevent overflow
    uint32_t tag = firstByte;
    int continuationCount = 0;
    do {
        if (pos >= length || ++continuationCount > 3) {
            return out;
        }
        tag = (tag << 8) | data[pos];
    } while (data[pos++] & 0x80);

    out.tag = tag;
    out.next = pos;
    out.ok = true;
    return out;
}

// Parse BER length. Reports failure through the result.
LengthResult tryParseLength(const uint8_t* data, size_t length, size_t pos) noexcept
{
    LengthResult out;
    if (pos >= length) {
        return out;
    }

    const uint8_t firstByte = data[pos++];

    if (firstByte < 0x80) {
        // Short form
        out.length = firstByte;
        out.next = pos;
        out.ok = true;
        return out;
    }

    if (firstByte == 0x80) {
        // Indefinite length not supported
        return out;
    }

    // Long form: firstByte & 0x7F = number of subsequent bytes
    const size_t numBytes = firstByte & 0x7F;
    if (numBytes > 4 || pos + numBytes > length) {
        return out;
    }

    size_t len = 0;
    for (size_t i = 0; i < numBytes; i++) {
        len = (len << 8) | data[pos++];
    }
    out.length = len;
    out.next = pos;
    out.ok = true;
    return out;
}

// The throwing pair, written over the pair above rather than beside it: one
// decode, and the difference is only what happens when the bytes are wrong.
uint32_t parseTag(const uint8_t* data, size_t length, size_t& offset)
{
    const TagResult res = tryParseTag(data, length, offset);
    if (!res.ok) {
        throw std::runtime_error("BER: tag too long or unexpected end of data");
    }
    offset = res.next;
    return res.tag;
}

size_t parseLength(const uint8_t* data, size_t length, size_t& offset)
{
    const LengthResult res = tryParseLength(data, length, offset);
    if (!res.ok) {
        throw std::runtime_error("BER: invalid, indefinite or truncated length encoding");
    }
    offset = res.next;
    return res.length;
}

namespace {

// Recursively parse BER fields. maxDepth prevents stack exhaustion from malicious card data.
std::vector<BERField> parseFields(const uint8_t* data, size_t length, int maxDepth = 32)
{
    if (maxDepth <= 0)
        return {};
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
            field.children = parseFields(data + offset, valueLen, maxDepth - 1);
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
} // namespace LibreSCRS::SmartCard::Internal
