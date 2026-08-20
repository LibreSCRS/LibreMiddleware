// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace LibreSCRS::SmartCard::Internal {

/// @brief One application template (tag 61) from EF.DIR.
///
/// EF.DIR may list several applications, and more than one may share an
/// AID while pointing at different paths — so consumers must select on a
/// verified property, never on position.
struct EfDirEntry
{
    std::vector<uint8_t> aid;  ///< tag 4F
    std::string label;         ///< tag 50, may be empty
    std::vector<uint8_t> path; ///< tag 51, may be empty
};

/// @brief Parse EF.DIR into every application template it carries.
/// Unknown or malformed entries are skipped; the rest are preserved in
/// on-card order.
std::vector<EfDirEntry> parseEfDir(std::span<const uint8_t> data);

} // namespace LibreSCRS::SmartCard::Internal
