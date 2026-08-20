// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "AnnexRegistry.h"

#include "RsAnnexReader.h"

namespace LibreSCRS::Annex {

std::span<const std::unique_ptr<IAnnexReader>> annexReaders()
{
    static const std::vector<std::unique_ptr<IAnnexReader>> readers = [] {
        std::vector<std::unique_ptr<IAnnexReader>> v;
        v.push_back(std::make_unique<RsAnnexReader>());
        return v;
    }();
    return readers;
}

std::vector<LibreSCRS::Plugin::CardFieldGroup>
readAnnexFor(const EfDirEntry& entry, const AnnexContext& ctx,
             std::span<const std::unique_ptr<IAnnexReader>> readers) noexcept
{
    for (const auto& reader : readers) {
        try {
            if (reader->handles(entry)) {
                return reader->read(entry, ctx);
            }
        } catch (...) {
            // Swallowed on purpose: see the header. A throwing annex must not
            // take the surrounding card read down with it, and must not stop the
            // remaining readers from being asked either.
        }
    }
    return {};
}

std::vector<LibreSCRS::Plugin::CardFieldGroup> readAnnexFor(const EfDirEntry& entry, const AnnexContext& ctx) noexcept
{
    return readAnnexFor(entry, ctx, annexReaders());
}

} // namespace LibreSCRS::Annex
