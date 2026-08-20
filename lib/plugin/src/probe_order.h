// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once

#include <LibreSCRS/Plugin/CardPlugin.h>

#include <memory>

namespace LibreSCRS::Plugin::Internal {

/// @brief Strict weak ordering for probe order: lower @ref
///        CardPlugin::probePriority first, ties broken by @ref
///        CardPlugin::pluginId.
///
/// The tie-break is the point. Probing stops at the first plugin that claims a
/// card, so when two plugins share a priority AND both claim it, whichever
/// sorts first decides what the user sees -- an identity document or a bare
/// certificate list. Comparing priority alone leaves that to std::sort, which
/// is not stable, so the answer would be unspecified for equal keys and could
/// differ between two runs of the same binary on the same card.
///
/// Breaking on the id rather than merely stabilising the sort makes the order
/// independent of the order plugins were LOADED in, which is a property of the
/// filesystem, not of the configuration.
///
/// @since 4.3
[[nodiscard]] inline bool probeOrderBefore(const std::shared_ptr<CardPlugin>& a,
                                           const std::shared_ptr<CardPlugin>& b) noexcept
{
    if (a->probePriority() != b->probePriority()) {
        return a->probePriority() < b->probePriority();
    }
    return a->pluginId() < b->pluginId();
}

} // namespace LibreSCRS::Plugin::Internal
