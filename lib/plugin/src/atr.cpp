// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

/// @file
/// @brief Out-of-line definition for @ref LibreSCRS::Plugin::Atr::matches.
///
/// Kept in its own translation unit so the byte-compare routine is colocated
/// with the @ref LibreSCRS::Plugin::Atr aggregate it operates on, rather than
/// sharing a TU with @ref LibreSCRS::Plugin::CardPlugin's NVI plumbing.

#include <LibreSCRS/Plugin/PluginTypes.h>

#include <algorithm>
#include <cstddef>

namespace LibreSCRS::Plugin {

bool Atr::matches(std::span<const std::uint8_t> candidate) const noexcept
{
    if (candidate.size() != bytes.size()) {
        return false;
    }
    if (!mask.has_value()) {
        return std::equal(candidate.begin(), candidate.end(), bytes.begin());
    }
    if (mask->size() != bytes.size()) {
        return false;
    }
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        const auto m = (*mask)[i];
        if ((candidate[i] & m) != (bytes[i] & m)) {
            return false;
        }
    }
    return true;
}

} // namespace LibreSCRS::Plugin
