// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

/// @file
/// @brief @ref LibreSCRS::LocalizedText — translator-friendly text bundle
///        (i18n key + English default) used everywhere
///        middleware surfaces user-visible strings.
///
/// Top-level location: middleware-wide concern, consumed from
/// @c Auth::AuthRequirement, @c SmartCard::OpenError, @c SmartCard::MonitorEvent,
/// @c Plugin::ReadResult, @c Plugin::PinStatusEntry,
/// @c Signing::SigningResult, etc.
///
/// @par Thread-safety
/// All types in this header are plain value aggregates; thread-compatible
/// per API-POLICY §8.
///
/// @since 4.0

#include <LibreSCRS/Export.h>

#include <string>

namespace LibreSCRS {

/// @brief Translator-friendly text bundle exchanged between middleware and host.
///
/// Carries an i18n lookup `key` and an English `defaultText`. The host
/// application looks up `key` in its own translation catalog and falls back
/// to `defaultText` when the key is unknown.
///
/// @code
///   auto text = LocalizedText{
///       .key         = "rs-eid.error.communication",
///       .defaultText = "Failed to communicate with the reader.",
///   };
/// @endcode
struct LIBRESCRS_PUBLIC_API LocalizedText
{
    /// @brief Catalog key the host uses to fetch the translated text.
    /// @details Format: `<domain>.<category>.<id>` lowercase-dot;
    ///          `<domain>` equals the plugin's pluginId or `"core"` for
    ///          middleware-owned strings, so host catalogs partition
    ///          cleanly between plugins.
    std::string key;

    /// @brief English text used when `key` is absent from the host's catalog.
    std::string defaultText;

    /// @brief Value equality (`key`, `defaultText`).
    [[nodiscard]] bool operator==(const LocalizedText&) const noexcept = default;
};

} // namespace LibreSCRS
