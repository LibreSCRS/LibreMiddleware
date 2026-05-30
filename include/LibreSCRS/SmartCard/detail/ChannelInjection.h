// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "LibreSCRS/SmartCard/detail/ChannelInjection.h is internal to LibreMiddleware"
#endif

/// @file
/// @brief Test-only injection point for installing a synthetic
///        @ref LibreSCRS::SecureChannel::ISecureChannel on an existing
///        @ref LibreSCRS::SmartCard::CardSession without driving the full
///        @ref CardSession::activateChannelFor /
///        @ref CardSession::activateChannelWithSm state machine.
///
/// Used by the cross-provider coordination regression tests to assemble
/// channel-state scenarios (Plain vs Pace, Open vs Closed vs Failed) that
/// would otherwise require a live PC/SC handshake. Not part of any public
/// surface — the friend declaration on @ref CardSession is the only path
/// into the @c Impl::activeChannel slot from outside CardSession.cpp.

#include <LibreSCRS/Export.h>
#include <LibreSCRS/SmartCard/CardSession.h>
#include <LibreSCRS/SmartCard/SmProtocolRequest.h>

#include <memory>
#include <optional>

namespace LibreSCRS::SecureChannel {
class ISecureChannel;
} // namespace LibreSCRS::SecureChannel

namespace LibreSCRS::SmartCard::detail {

/// @brief Friend-only access struct for the test-channel injection seam.
///
/// Forward-declared in the public @ref CardSession header so @c CardSession
/// can befriend it without leaking the helper symbol or its parameter type
/// into the public SDK include tree. The single static method @ref
/// installForTesting has its body in the build-tree-only @c
/// LibreSCRS_SmartCard_TestHelpers archive — production builds of
/// @c libLibreSCRS_SmartCard therefore never carry the symbol in their
/// dynamic export set. Test executables that need this seam link the
/// archive alongside the production target. The `LIBRESCRS_INTERNAL_BUILD`
/// `#error` guard above is the compile-time hardening that blocks external
/// SDK consumers from seeing the declaration at all.
///
/// @par Thread-safety
/// @ref installForTesting takes the session mutex internally so the install
/// is ordered against any concurrent @ref CardSession::hasLiveSecureChannel
/// / @ref CardSession::clearActiveChannel call. Tests that exercise
/// concurrency invariants may still need additional barriers depending on
/// the scenario.
///
/// @since 4.1
struct ChannelInjector
{
    /// @brief Install @p channel as the active secure channel on @p session,
    ///        replacing any previously installed channel. The previously
    ///        installed channel (if any) is dropped without calling
    ///        @c close() — tests that need explicit teardown should arrange
    ///        for it themselves.
    ///
    /// @param recordedProtocol  When set, records it as the session's
    ///        @ref CardSession::activatedProtocol under the same lock,
    ///        mirroring the activation paths that stamp the protocol alongside
    ///        the live channel. Defaults to @c std::nullopt so existing callers
    ///        that only need a channel state are unaffected. Lets the
    ///        @c activatedProtocol-staleness regression construct a session
    ///        whose recorded protocol outlives a non-live channel.
    /// @since 4.1
    LIBRESCRS_INTERNAL static void
    installForTesting(CardSession& session, std::unique_ptr<LibreSCRS::SecureChannel::ISecureChannel> channel,
                      std::optional<SmProtocolRequest> recordedProtocol = std::nullopt) noexcept;
};

} // namespace LibreSCRS::SmartCard::detail
