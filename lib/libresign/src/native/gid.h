// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware."
#endif

#pragma once

#include <compare>
#include <cstdint>
#include <functional>

namespace libresign {

/// @brief Strong-typed glyph index. Tag distinguishes glyph-index spaces
///        (e.g. original-font GID vs. subset-renumbered GID) at compile
///        time so the two cannot be silently confused.
///
/// Construction is `explicit` to prevent accidental construction from a
/// bare integer; comparison is defaulted; `raw()` returns the underlying
/// `uint16_t` for cases where an integer is needed (array indexing, hex
/// formatting, byte-level emission).
template <typename Tag>
class GidT
{
public:
    constexpr GidT() = default;
    constexpr explicit GidT(uint16_t value) noexcept : rawValue(value) {}

    /// @brief Return the underlying 16-bit value.
    constexpr uint16_t raw() const noexcept
    {
        return rawValue;
    }

    constexpr auto operator<=>(const GidT&) const noexcept = default;

private:
    uint16_t rawValue = 0;
};

/// @brief Tag for original-font GIDs (as found in the bundled TTF).
struct OldGidTag;
using OldGid = GidT<OldGidTag>;

/// @brief Tag for subset-renumbered GIDs (dense 0..N in the subset output).
using NewGid = GidT<struct NewGidTag>;

} // namespace libresign

namespace std {
template <typename Tag>
struct hash<libresign::GidT<Tag>>
{
    size_t operator()(libresign::GidT<Tag> g) const noexcept
    {
        return std::hash<uint16_t>{}(g.raw());
    }
};
} // namespace std
