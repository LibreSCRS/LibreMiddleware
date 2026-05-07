// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

/// @file
/// @brief Big-endian SFNT / TrueType byte readers shared between the TTF
///        parser, the TTF subsetter, and any other internal module that
///        decodes raw SFNT bytes. All readers are bounds-checked and return
///        a zero / empty default on out-of-range access — the call sites
///        treat this as a malformed-table signal that surfaces through the
///        parser's `parse()` boolean return.

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>

namespace libresign::sfnt {

/// @brief Read a big-endian uint16 at @p off into @p b. Returns 0 on overflow.
inline uint16_t readU16(std::span<const uint8_t> b, size_t off) noexcept
{
    if (off + 2 > b.size())
        return 0;
    return static_cast<uint16_t>((static_cast<uint16_t>(b[off]) << 8) | static_cast<uint16_t>(b[off + 1]));
}

/// @brief Read a big-endian int16 at @p off into @p b. Returns 0 on overflow.
inline int16_t readI16(std::span<const uint8_t> b, size_t off) noexcept
{
    return static_cast<int16_t>(readU16(b, off));
}

/// @brief Read a big-endian uint32 at @p off into @p b. Returns 0 on overflow.
inline uint32_t readU32(std::span<const uint8_t> b, size_t off) noexcept
{
    if (off + 4 > b.size())
        return 0;
    return (static_cast<uint32_t>(b[off]) << 24) | (static_cast<uint32_t>(b[off + 1]) << 16) |
           (static_cast<uint32_t>(b[off + 2]) << 8) | static_cast<uint32_t>(b[off + 3]);
}

/// @brief Read 4 bytes at @p off into @p b as an SFNT tag string. Returns
///        an empty string on overflow.
inline std::string tagAt(std::span<const uint8_t> b, size_t off)
{
    if (off + 4 > b.size())
        return {};
    return std::string(reinterpret_cast<const char*>(&b[off]), 4);
}

} // namespace libresign::sfnt
