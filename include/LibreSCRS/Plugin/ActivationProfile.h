// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once

/// @file
/// @brief Declarative activation descriptor a plugin publishes, plus the shared
///        channel-acquisition helper the readCard NVI wrapper drives.

#include <LibreSCRS/CancelToken.h>
#include <LibreSCRS/Export.h>
#include <LibreSCRS/SecureChannel/ChannelErrors.h>
#include <LibreSCRS/SmartCard/ActiveChannelHolder.h>
#include <LibreSCRS/SmartCard/AppletAid.h>
#include <LibreSCRS/SmartCard/CardSession.h>
#include <LibreSCRS/SmartCard/SmProtocolRequest.h>

#include <expected>
#include <optional>

namespace LibreSCRS::Plugin {

/// @brief Declarative description of the secure-messaging (or plain) channel a
///        plugin needs before a card operation. Carries no secret values.
///
/// @par Thread-safety
/// thread-compatible (see API-POLICY §8).
struct ActivationProfile
{
    /// Applet to activate against; empty means "plain channel / no SM".
    std::optional<LibreSCRS::SmartCard::AppletAid> aid;
    /// Primary protocol to try. Read ONLY when @ref requiresActivation().
    LibreSCRS::SmartCard::SmProtocolRequest primary{};
    /// When true and @ref primary fails because the document is structurally
    /// without PACE (PaceUnsupported), retry once with BAC. No other error
    /// triggers the fallback — see @ref shouldTryFallback.
    bool allowBacFallback = false;

    /// @brief A profile that performs no activation (plain channel).
    [[nodiscard]] static ActivationProfile plain() noexcept
    {
        return ActivationProfile{};
    }
    /// @brief True when this profile drives a secure-messaging activation.
    [[nodiscard]] bool requiresActivation() const noexcept
    {
        return aid.has_value();
    }
};

#ifdef LIBRESCRS_INTERNAL_BUILD
/// @brief True when @p e is a terminal error that must abort the walk
///        (no BAC fallback): user/host cancellation or card removal.
/// @internal Implementation detail of @ref acquireChannelForProfile; declared
///           only inside the LibreMiddleware build (hidden visibility, not part
///           of the public ABI). Reached by build-tree tests that link the
///           CardPlugin_Impl object archive.
[[nodiscard]] LIBRESCRS_INTERNAL bool isStopError(LibreSCRS::SecureChannel::ChannelActivationError e) noexcept;

/// @brief True when, after @p primary failed with @p e, the BAC fallback should
///        be attempted: the profile allows it and @p e is @c PaceUnsupported —
///        the document is structurally without PACE. Any other error (a
///        transient failure, a wrong secret, or a detected downgrade) keeps the
///        walk on the requested credential rather than silently downgrading to
///        the weaker BAC channel.
/// @internal See @ref isStopError — internal, hidden, not public ABI.
[[nodiscard]] LIBRESCRS_INTERNAL bool shouldTryFallback(const ActivationProfile& profile,
                                                        LibreSCRS::SecureChannel::ChannelActivationError e) noexcept;
#endif // LIBRESCRS_INTERNAL_BUILD

/// @brief Acquire a secure-messaging channel per @p profile, with a single
///        BAC fallback when @ref ActivationProfile::allowBacFallback is set.
///        Reuses CardSession's cache-or-provider credential resolution.
/// @pre @p profile.requiresActivation() — callers handle the plain case by
///      dispatching the operation without a channel.
/// @return The active-channel holder on success; on failure the
///         ChannelActivationError from the last attempt (after fallback).
[[nodiscard]] LIBRESCRS_PUBLIC_API
    std::expected<LibreSCRS::SmartCard::ActiveChannelHolder, LibreSCRS::SecureChannel::ChannelActivationError>
    acquireChannelForProfile(LibreSCRS::SmartCard::CardSession& session, const ActivationProfile& profile,
                             LibreSCRS::CancelToken token);

} // namespace LibreSCRS::Plugin
