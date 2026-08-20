// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

#include "IAnnexReader.h"

namespace LibreSCRS::Annex {

/// @brief Reads the Serbian annex: a manifest, the files it lists, and two
/// signed objects that cover them positionally.
class RsAnnexReader final : public IAnnexReader
{
public:
    [[nodiscard]] std::string_view annexId() const noexcept override
    {
        return "rs";
    }

    [[nodiscard]] bool handles(const EfDirEntry& entry) const override;

    [[nodiscard]] std::vector<LibreSCRS::Plugin::CardFieldGroup> read(const EfDirEntry& entry,
                                                                      const AnnexContext& ctx) const override;
};

/// @brief The annex directory path to address from the master file.
///
/// EF.DIR states the path from the root (`3F00 0FF3`), but a SELECT-by-path is
/// already relative to the master file and the card rejects the redundant
/// leading identifier outright. Exposed for testing.
[[nodiscard]] std::vector<std::uint8_t> annexDfPath(const EfDirEntry& entry);

} // namespace LibreSCRS::Annex
