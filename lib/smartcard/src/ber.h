// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

#include <cstdint>
#include <initializer_list>
#include <string>
#include <vector>

namespace LibreSCRS::SmartCard::Internal {

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

// Parse a single BER tag (1, 2, or 3 bytes) starting at `offset`.
// Returns the tag value and advances `offset` past the tag bytes.
// Throws std::runtime_error on truncated/oversized input.
uint32_t parseTag(const uint8_t* data, size_t length, size_t& offset);

// Parse a BER length (short or long form) starting at `offset`.
// Returns the length value and advances `offset` past the length bytes.
// Throws std::runtime_error on indefinite/oversized/truncated encodings.
size_t parseLength(const uint8_t* data, size_t length, size_t& offset);

// Merge two BER trees: appends src's children into dst
void mergeBER(BERField& dst, const BERField& src);

// Access nested field by tag path, e.g. {0x71, 0xA3, 0x87}
std::string berFindString(const BERField& root, std::initializer_list<uint32_t> path);
std::vector<uint8_t> berFindBytes(const BERField& root, std::initializer_list<uint32_t> path);

} // namespace LibreSCRS::SmartCard::Internal
