// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "lib/libresign/src/utf8.h is internal to LibreMiddleware."
#endif

#pragma once

/// @file
/// @brief Internal UTF-8 decode primitive shared by the libresign PDF /
///        PAdES / visual-signature layout passes.
///
/// Single source of truth for the "decode one codepoint at a byte offset,
/// substitute U+FFFD on malformed input" pattern used by every UTF-8
/// consumer inside libresign. The decoder is conservative: it never reads
/// past the end of the string view and never throws — malformed sequences
/// produce U+FFFD with a 1-byte advance, mirroring the WHATWG / Unicode
/// substitution rule (one replacement per maximal subpart). Callers that
/// need stricter validation (e.g. error reporting on invalid input)
/// should layer that on top instead of forking this primitive again.

#include <cstddef>
#include <string_view>
#include <utility>

namespace libresign::utf8 {

/// @brief Decode one UTF-8 codepoint starting at byte index @p i.
///
/// @returns @c {codepoint, byte_count} on success; @c {0xFFFD, 1} on
///          malformed leading byte; @c {0xFFFD, remaining_bytes} on a
///          truncated multi-byte sequence at end of input; @c {0, 0}
///          when @p i is at or past @p s end.
inline std::pair<char32_t, std::size_t> decodeAt(std::string_view s, std::size_t i) noexcept
{
    if (i >= s.size())
        return {0, 0};
    unsigned char c = static_cast<unsigned char>(s[i]);
    char32_t cp = 0;
    std::size_t n = 1;
    if ((c & 0x80) == 0x00) {
        cp = c;
        n = 1;
    } else if ((c & 0xE0) == 0xC0) {
        cp = c & 0x1F;
        n = 2;
    } else if ((c & 0xF0) == 0xE0) {
        cp = c & 0x0F;
        n = 3;
    } else if ((c & 0xF8) == 0xF0) {
        cp = c & 0x07;
        n = 4;
    } else {
        return {0xFFFD, 1};
    }
    if (i + n > s.size())
        return {0xFFFD, s.size() - i};
    for (std::size_t k = 1; k < n; ++k) {
        unsigned char cc = static_cast<unsigned char>(s[i + k]);
        if ((cc & 0xC0) != 0x80)
            return {0xFFFD, 1};
        cp = (cp << 6) | (cc & 0x3F);
    }
    return {cp, n};
}

} // namespace libresign::utf8
