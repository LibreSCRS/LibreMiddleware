// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

#include "IAnnexReader.h"

namespace LibreSCRS::Annex {

/// @brief Every annex group this card offers, in EF.DIR order.
///
/// Reads EF.DIR, offers each record to the registered readers, and puts the
/// master file back before returning. Never throws and never reports failure:
/// a card without an annex, or with one that cannot be read, simply yields
/// nothing.
///
/// Call this LAST in a read. Selecting an annex directory displaces whatever
/// application was selected, and the master file is restored rather than that
/// application -- the convention every other reader in the tree follows.
[[nodiscard]] std::vector<LibreSCRS::Plugin::CardFieldGroup> readAllAnnexes(const AnnexContext& ctx) noexcept;

} // namespace LibreSCRS::Annex
