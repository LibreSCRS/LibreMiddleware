// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "LibreSCRS_internal/Plugin/CardPluginActivationAccessor.h is internal to LibreMiddleware."
#endif

#pragma once

/// @file
/// @brief Friend-only test seam to @ref LibreSCRS::Plugin::CardPlugin's
///        protected @ref CardPlugin::activationProfile.
///
/// @ref CardPlugin::activationProfile is protected — an NVI consumed by the
/// @ref CardPlugin::readCard wrapper and the @ref CardPlugin::preReadAuth
/// derivation — so in-tree (@c LIBRESCRS_INTERNAL_BUILD) tests cannot pin the
/// profile verdict directly. This accessor is the sanctioned mirror of
/// @ref LibreSCRS::SmartCard::Internal::ActiveChannelAccessor: it is
/// befriended by @ref CardPlugin and DEFINED only in this NON-installed
/// internal header, so the protected surface never reaches SDK consumers.
/// Header-only inline: adds no exported symbol and no ABI/vtable change.

#include <LibreSCRS/Plugin/ActivationProfile.h>
#include <LibreSCRS/Plugin/CardPlugin.h>

namespace LibreSCRS::SmartCard {
class CardSession;
} // namespace LibreSCRS::SmartCard

namespace LibreSCRS::Plugin::detail {

struct CardPluginActivationAccessor
{
    /// @brief The activation profile @p plugin declares for @p session — the
    ///        protected @ref CardPlugin::activationProfile, reachable here via
    ///        friendship.
    [[nodiscard]] static ActivationProfile profile(const CardPlugin& plugin, LibreSCRS::SmartCard::CardSession& session)
    {
        return plugin.activationProfile(session);
    }
};

} // namespace LibreSCRS::Plugin::detail
