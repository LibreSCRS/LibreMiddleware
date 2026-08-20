// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

#include "IAnnexReader.h"

#include <memory>
#include <span>
#include <vector>

namespace LibreSCRS::Annex {

/// @brief Every annex reader compiled into this build, in a fixed order.
///
/// An explicit list, not self-registration: registering from static
/// initialisers would put mutable global state inside a plugin, which project
/// policy rules out. The cost is that this translation unit knows the countries.
[[nodiscard]] std::span<const std::unique_ptr<IAnnexReader>> annexReaders();

/// @brief Groups produced by whichever reader claims @p entry, or none.
///
/// Never throws and never reports failure: an annex that cannot be read is
/// simply absent, because it must not be able to fail the card read around it.
[[nodiscard]] std::vector<LibreSCRS::Plugin::CardFieldGroup> readAnnexFor(const EfDirEntry& entry,
                                                                          const AnnexContext& ctx) noexcept;

/// @brief As above, over an explicit reader list. Exists so the swallow-and-
/// continue contract can be tested against a reader that deliberately throws.
[[nodiscard]] std::vector<LibreSCRS::Plugin::CardFieldGroup>
readAnnexFor(const EfDirEntry& entry, const AnnexContext& ctx,
             std::span<const std::unique_ptr<IAnnexReader>> readers) noexcept;

} // namespace LibreSCRS::Annex
