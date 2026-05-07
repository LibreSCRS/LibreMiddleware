// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

/// @file
/// @brief @ref LibreSCRS::Plugin::PinStatusEntry — per-PIN state record
///        returned by @ref LibreSCRS::Plugin::CardPlugin::getPINList.
/// @since 4.0

#include <LibreSCRS/LocalizedText.h>
#include <LibreSCRS/Export.h>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>

namespace LibreSCRS::Plugin {

/// @brief Per-PIN state entry returned by @ref CardPlugin::getPINList.
///
/// Plugins MUST populate @ref unblockable accurately: when @ref blocked is true
/// and @ref unblockable is false, the host should surface
/// @ref blockedGuidance rather than offering a PUK-unblock action.
struct PinStatusEntry
{
    /// @brief Plugin-defined label, used as the pinLabel in change/unblock flows.
    std::string label;
    /// @brief Card-native PIN reference (where applicable).
    std::uint8_t reference = 0;
    /// @brief Remaining PIN retry count; @c std::nullopt when unknown.
    std::optional<int> retriesLeft;
    /// @brief True when the PIN has been initialised on-card.
    bool initialized = true;
    /// @brief True when the PIN is currently blocked.
    bool blocked = false;
    /// @brief Enforced minimum length; @c std::nullopt when unknown.
    std::optional<std::size_t> minLength;
    /// @brief Enforced maximum length; @c std::nullopt when unknown.
    std::optional<std::size_t> maxLength;
    /// @brief True when the PIN value is user-changeable.
    ///
    /// Conservative default: `false`. A plugin that does support PIN change
    /// MUST set this explicitly. The inverted default (was `true` pre-4.0)
    /// prevented a future plugin that forgets to populate the flag from
    /// accidentally advertising a change capability it does not implement —
    /// a @ref CardPlugin::changePIN call against such a plugin would then
    /// reach the card layer and fail at protocol time instead of being
    /// short-circuited by the host UI.
    bool canChange = false;

    /// @brief True when the plugin supports PUK-based unblock for this PIN.
    bool unblockable = false;
    /// @brief Optional message displayed when @ref blocked is true and unblock is unavailable.
    std::optional<LocalizedText> blockedGuidance;
};

} // namespace LibreSCRS::Plugin
