// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "LibreSCRS_internal/Plugin/ActivationChannel.h is internal to LibreMiddleware."
#endif

#pragma once

/// @file
/// @brief How the @ref LibreSCRS::Plugin::CardPlugin::readCard wrapper turns
///        an @ref LibreSCRS::Plugin::ActivationProfile into a channel. Not
///        installed: the functions are hidden in the library.

#include <LibreSCRS/CancelToken.h>
#include <LibreSCRS/Export.h>
#include <LibreSCRS/Plugin/ActivationProfile.h>
#include <LibreSCRS/SecureChannel/ChannelErrors.h>
#include <LibreSCRS/SmartCard/ActiveChannelHolder.h>
#include <LibreSCRS/SmartCard/CardSession.h>

#include <expected>

namespace LibreSCRS::Plugin {
/// @brief True when, after @p primary failed with @p e, the BAC fallback should
///        be attempted: the profile allows it and @p e is @c PaceUnsupported —
///        the document is structurally without PACE. Any other error (a
///        transient failure, a wrong secret, or a detected downgrade) keeps the
///        walk on the requested credential rather than silently downgrading to
///        the weaker BAC channel.
/// @internal Implementation detail of @ref acquireChannelForProfile; declared
///           only inside the LibreMiddleware build (hidden visibility, not part
///           of the public ABI). Reached by build-tree tests that link the
///           CardPlugin_Impl object archive.
[[nodiscard]] LIBRESCRS_INTERNAL bool shouldTryFallback(const ActivationProfile& profile,
                                                        LibreSCRS::SecureChannel::ChannelActivationError e) noexcept;

/// @brief Acquire a secure-messaging channel per @p profile, with a single
///        BAC fallback when @ref ActivationProfile::allowBacFallback is set.
///        Reuses CardSession's cache-or-provider credential resolution.
/// @pre @p profile.requiresActivation() — callers handle the plain case by
///      dispatching the operation without a channel.
/// @return The active-channel holder on success; on failure the
///         ChannelActivationError from the last attempt (after fallback).
/// @internal Called only by the @ref CardPlugin::readCard NVI wrapper in the
///           same library — internal, hidden, not public ABI.
[[nodiscard]] LIBRESCRS_INTERNAL
    std::expected<LibreSCRS::SmartCard::ActiveChannelHolder, LibreSCRS::SecureChannel::ChannelActivationError>
    acquireChannelForProfile(LibreSCRS::SmartCard::CardSession& session, const ActivationProfile& profile,
                             LibreSCRS::CancelToken token);

} // namespace LibreSCRS::Plugin
