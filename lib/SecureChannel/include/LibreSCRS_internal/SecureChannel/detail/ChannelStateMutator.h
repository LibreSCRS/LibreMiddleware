// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "LibreSCRS_internal/SecureChannel/detail/ChannelStateMutator.h is internal to LibreMiddleware."
#endif

#pragma once

/// @file
/// @brief @ref LibreSCRS::SecureChannel::detail::ChannelStateMutator —
///        friend-only access seam that LM internals use to mutate a live
///        channel's bound AID or rotate its SM session keys.

#include <LibreSCRS/SmartCard/AppletAid.h>
#include <LibreSCRS_internal/SecureChannel/ISecureChannel.h>
#include <LibreSCRS_internal/SecureChannel/SessionKeys.h>

#include <utility>

namespace LibreSCRS::SecureChannel::detail {

/// @brief Friend-only access seam to @ref ISecureChannel's protected
///        mutator surface.
///
/// @ref ISecureChannel::setCurrentApplet and @ref ISecureChannel::replaceKeys
/// are @c protected pure-virtual on the abstract interface so external
/// consumers holding an @ref ISecureChannel pointer (e.g. via
/// @ref LibreSCRS::SmartCard::ActiveChannelHolder::activeChannel) cannot
/// corrupt the channel's bound AID or pin it to attacker-supplied keys.
/// This struct is the LM-internal seam through which:
///
///   - @ref LibreSCRS::SmartCard::CardSession reaches @c setCurrentApplet
///     after a wrapped @c SELECT, and
///   - @ref LibreSCRS::SmartCard::CardSession::performChipAuthentication
///     reaches @c replaceKeys after CA derives fresh session keys inside a
///     tunnel (BSI TR-03110 §4.4).
///
/// All operations are @c noexcept-by-contract; concrete channels must
/// preserve no-throw on their overrides.
///
/// @par Thread-safety
/// Locking is the caller's responsibility — the underlying channel
/// implementations are not internally synchronised against concurrent
/// transmits. Production call sites hold the @ref CardSession mutex or
/// the @ref LibreSCRS::SmartCard::ActiveChannelHolder ownership token for
/// the duration of the call.
///
/// @since 4.1
// Header-only: a card plugin that clears the applet of the channel it reads
// over (the national annex reader) calls it on its own adapter, so it needs
// nothing exported from the library.
struct ChannelStateMutator
{
    static void setCurrentApplet(ISecureChannel& ch, LibreSCRS::SmartCard::AppletAid aid) noexcept
    {
        ch.setCurrentApplet(std::move(aid));
    }

    static void replaceKeys(ISecureChannel& ch, SessionKeys keys) noexcept
    {
        ch.replaceKeys(std::move(keys));
    }
};

} // namespace LibreSCRS::SecureChannel::detail
