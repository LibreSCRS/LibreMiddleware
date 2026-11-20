// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once

/// @file
/// @brief Declarative activation descriptor a plugin publishes; the readCard
///        NVI wrapper acquires the channel it describes.

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
///
/// @par Example
/// @code
/// ActivationProfile profile;
/// profile.aid = LibreSCRS::SmartCard::AppletAid{0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01};
/// profile.primary = LibreSCRS::SmartCard::PaceRequest{LibreSCRS::Auth::PaceSecretKind::Can};
/// profile.allowBacFallback = true; // retry with BAC if PACE is unsupported
/// @endcode
/// @since 5.0
struct ActivationProfile
{
    /// Applet to activate against; empty means "plain channel / no SM".
    std::optional<LibreSCRS::SmartCard::AppletAid> aid;
    /// Primary protocol to try. Read ONLY when @ref requiresActivation().
    LibreSCRS::SmartCard::SmProtocolRequest primary{};
    /// When true and @ref primary fails because the document is structurally
    /// without PACE (PaceUnsupported), retry once with BAC. No other error
    /// triggers the fallback: a transient failure, a wrong secret or a
    /// detected downgrade keeps the walk on the requested credential.
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

} // namespace LibreSCRS::Plugin
