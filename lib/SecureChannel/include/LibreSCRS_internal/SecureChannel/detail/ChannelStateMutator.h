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

#include <LibreSCRS/Export.h>
#include <LibreSCRS/SmartCard/AppletAid.h>
#include <LibreSCRS_internal/SecureChannel/ISecureChannel.h>
#include <LibreSCRS_internal/SecureChannel/SessionKeys.h>

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
///   - the Chip-Authentication pipeline reaches @c replaceKeys after CA
///     derives fresh session keys (BSI TR-03110 §4.4).
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
struct LIBRESCRS_PUBLIC_API ChannelStateMutator
{
    /// @brief Update @p ch's bound AID to @p aid.
    ///
    /// Used after a wrapped @c SELECT routes a new applet through a
    /// PACE-class channel's existing SM tunnel. PACE SM is session-scoped
    /// (BSI TR-03110 §3); the channel's @c currentApplet is mutable state
    /// rather than constructor-bound identity.
    /// @since 4.1
    static void setCurrentApplet(ISecureChannel& ch, LibreSCRS::SmartCard::AppletAid aid) noexcept;

    /// @brief Replace @p ch's SM session keys with @p keys.
    ///
    /// The previous SM key material is zeroised through the underlying
    /// primitive's destructor before installation. Idempotent and leaves
    /// the channel in @ref ChannelState::Open on success.
    /// @since 4.1
    static void replaceKeys(ISecureChannel& ch, SessionKeys keys) noexcept;
};

} // namespace LibreSCRS::SecureChannel::detail
