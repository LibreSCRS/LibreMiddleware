// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>

/// @file
/// @brief Byte span to hex text, once.
///
/// Three helpers of this shape were written out in this tree, and the loop was
/// the same in all three; what differed was the case of the digits and who was
/// allowed to include what. The case is a parameter here. The two copies that
/// remain are on the record for reasons that are about include boundaries
/// rather than about the loop: one is a member of a PUBLIC installed header,
/// which may not reach into this one, and one is a shipped example, which
/// stands for what a consumer can write without this repository's internals.

namespace LibreSCRS::Internal {

/// @brief Uppercase hex digit table — `kHexUpper[i]` is the ASCII character for
///        the nibble value @p i (0..15).
inline constexpr std::string_view kHexUpper = "0123456789ABCDEF";
/// @brief The lowercase table, for the renderings a specification spells that
///        way (PDF DSS/VRI keys, ISO 32000-2 §12.8.4.3).
inline constexpr std::string_view kHexLower = "0123456789abcdef";

/// @brief Hex-encode a byte span. Uppercase unless @p lowercase says otherwise.
/// @throws std::bad_alloc on allocation failure.
[[nodiscard]] inline std::string hexEncode(std::span<const std::uint8_t> data, bool lowercase = false)
{
    const std::string_view chars = lowercase ? kHexLower : kHexUpper;
    std::string out;
    out.reserve(data.size() * 2);
    for (const std::uint8_t b : data) {
        out.push_back(chars[(b >> 4) & 0x0F]);
        out.push_back(chars[b & 0x0F]);
    }
    return out;
}

} // namespace LibreSCRS::Internal
