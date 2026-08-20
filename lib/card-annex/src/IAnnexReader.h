// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

#include <LibreSCRS/CancelToken.h>
#include <LibreSCRS/Plugin/CardData.h>

#include <ef_dir.h>

#include <string>
#include <string_view>
#include <vector>

namespace LibreSCRS::SecureChannel {
class ISecureChannel;
}
namespace LibreSCRS::SmartCard {
class IConnection;
}

namespace LibreSCRS::Annex {

using LibreSCRS::SmartCard::Internal::EfDirEntry;

/// @brief What a reader needs to talk to the card, and nothing more.
///
/// Mirrors how the rest of the tree reaches a file: over the active channel
/// when one is open, over the bare connection otherwise.
struct AnnexContext
{
    LibreSCRS::SecureChannel::ISecureChannel* channel = nullptr;
    /// The interface rather than the concrete connection: a test drives this
    /// through a fake, and the reader has no business knowing which it got.
    LibreSCRS::SmartCard::IConnection* conn = nullptr;
    LibreSCRS::CancelToken token;
};

/// @brief One country's annex, read from a dedicated file EF.DIR advertises.
///
/// Readers differ in what they hook onto -- one card's annex has a usable AID,
/// another's is reachable only by path -- so the whole EF.DIR record is handed
/// over rather than a name or a path alone.
class IAnnexReader
{
public:
    virtual ~IAnnexReader() = default;

    IAnnexReader(const IAnnexReader&) = delete;
    IAnnexReader& operator=(const IAnnexReader&) = delete;

    /// @brief Short stable id. Group keys are derived from it so two annexes on
    /// one card cannot collide.
    [[nodiscard]] virtual std::string_view annexId() const noexcept = 0;

    /// @brief Whether this reader wants to try @p entry.
    ///
    /// Matching is by AID or by path, and is only an invitation: the reader
    /// confirms on content once it has read the annex. Neither value is stable
    /// enough on its own -- this issuer has already moved its AID once.
    [[nodiscard]] virtual bool handles(const EfDirEntry& entry) const = 0;

    /// @return Zero or more groups. Empty means "nothing to show" and is NOT an
    ///         error: an absent, unreadable or badly signed annex must never
    ///         fail the card read.
    [[nodiscard]] virtual std::vector<LibreSCRS::Plugin::CardFieldGroup> read(const EfDirEntry& entry,
                                                                              const AnnexContext& ctx) const = 0;

protected:
    IAnnexReader() = default;
};

/// @brief Group key for @p suffix belonging to annex @p annexId.
///
/// Derived rather than fixed: a card may carry more than one annex, and two
/// groups sharing a key would leave the second invisible to every consumer that
/// looks a group up by name.
[[nodiscard]] inline std::string annexGroupKey(std::string_view annexId, std::string_view suffix)
{
    return "annex." + std::string{annexId} + "." + std::string{suffix};
}

} // namespace LibreSCRS::Annex
