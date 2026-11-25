// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "text_encoding.h"

namespace LibreSCRS::SmartCard::Internal {

std::string decodeUtf16Le(std::span<const std::uint8_t> bytes)
{
    std::string out;
    out.reserve(bytes.size());
    for (std::size_t i = 0; i + 1 < bytes.size(); i += 2) {
        const auto cp = static_cast<std::uint16_t>(bytes[i] | (bytes[i + 1] << 8));
        if (cp < 0x80) {
            out += static_cast<char>(cp);
        } else if (cp < 0x800) {
            out += static_cast<char>(0xC0 | (cp >> 6));
            out += static_cast<char>(0x80 | (cp & 0x3F));
        } else {
            out += static_cast<char>(0xE0 | (cp >> 12));
            out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
            out += static_cast<char>(0x80 | (cp & 0x3F));
        }
    }
    return out;
}

} // namespace LibreSCRS::SmartCard::Internal
