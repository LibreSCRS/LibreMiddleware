// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace LibreSCRS::SmartCard::Internal {

// Custom Little-Endian 16-bit TLV used by Serbian cards (eID, vehicle, health)
struct TLVField
{
    uint16_t tag;
    std::vector<uint8_t> value;
    std::string asString() const; // UTF-8 decode
};

std::vector<TLVField> parseTLV(const uint8_t* data, size_t length);

// Convenience: find field by tag, return value as UTF-8 string (empty if not found)
std::string findString(const std::vector<TLVField>& fields, uint16_t tag);
std::vector<uint8_t> findBytes(const std::vector<TLVField>& fields, uint16_t tag);

} // namespace LibreSCRS::SmartCard::Internal
