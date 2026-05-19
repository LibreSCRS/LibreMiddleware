// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

/// @file
/// @brief @ref LibreSCRS::LocalizedText — translator-friendly text bundle
///        (i18n key + English default + typed placeholders) used everywhere
///        middleware surfaces user-visible strings.
///
/// Top-level location: middleware-wide concern, consumed from
/// @c Auth::AuthRequirement, @c SmartCard::OpenError, @c SmartCard::MonitorEvent,
/// @c Plugin::ReadResult, @c Plugin::AutoReaderError, @c Plugin::PinStatusEntry,
/// @c Signing::SigningResult, etc.
///
/// Design references:
///  - Stroustrup, *A Tour of C++* 3rd ed. §6.4 (concrete classes — value-type
///    aggregate appropriate when impl is final), §15.4 (`std::variant`)
///
/// @since 4.0

#include <LibreSCRS/Export.h>

#include <chrono>
#include <cstdint>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace LibreSCRS {

/// @brief Strongly-typed wrapper around a plural-agreement count.
/// @details Used as `Placeholder::value` payload at variant index 5
///          (`Type::Count`) so consumers can apply their host language's
///          plural rule. Kept distinct from raw `std::int64_t` (which lives at
///          variant index 1, `Type::Int`) so the variant discriminator
///          remains reachable. Aggregate-init: `Count{3}`, `Count{n}`.
struct LIBRESCRS_PUBLIC_API Count
{
    std::int64_t value;
    [[nodiscard]] bool operator==(const Count&) const noexcept = default;
};

/// @brief Tagged-union value for a localised placeholder.
///
/// Constructed via aggregate-init or designated-init. The `value` field's
/// `std::variant` index corresponds to the `Type` enum returned by `type()`.
///
/// @code
///   Placeholder p{.name = "readerName", .value = std::string{"PC/SC Reader"}};
///   Placeholder n{.name = "count",       .value = Count{3}};
/// @endcode
struct LIBRESCRS_PUBLIC_API Placeholder
{
    enum class Type : std::uint8_t {
        String = 0, ///< std::string (name lookup payload)
        Int = 1,    ///< std::int64_t signed integer
        UInt = 2,   ///< std::uint64_t unsigned integer
        Hex = 3,    ///< std::vector<std::uint8_t> formatted as hex
        Date = 4,   ///< std::chrono::system_clock::time_point
        Count = 5,  ///< std::int64_t for plural agreement (consumer's plural rule)
        Bool = 6,   ///< bool (Yes/No semantic)
    };

    std::string name;

    std::variant<std::string,                           // Type::String
                 std::int64_t,                          // Type::Int
                 std::uint64_t,                         // Type::UInt
                 std::vector<std::uint8_t>,             // Type::Hex
                 std::chrono::system_clock::time_point, // Type::Date
                 Count,                                 // Type::Count
                 bool>                                  // Type::Bool
        value;

    /// @brief Returns the variant index as `Type`. O(1).
    [[nodiscard]] Type type() const noexcept
    {
        return static_cast<Type>(value.index());
    }

    /// @brief Render the value as English text (used by `LocalizedText::formattedDefault`
    ///        and consumer-side log fallback).
    /// @details Returns: String → as-is; Int/Count → `std::to_string`; UInt → ditto;
    ///          Hex → uppercase hex bytes joined; Date → ISO 8601 UTC; Bool → "true"/"false".
    /// @throws std::bad_alloc on allocation failure while building the
    ///         returned string.
    [[nodiscard]] std::string formatted() const;

    /// @brief Value equality (default: `name` and `value`).
    [[nodiscard]] bool operator==(const Placeholder&) const noexcept = default;
};

/// @brief Translator-friendly text bundle exchanged between middleware and host.
///
/// Carries an i18n lookup `key`, an English `defaultText`, and a typed
/// `placeholders` array. The host application looks up `key` in its own
/// translation catalog and performs `{name}` substitution using `placeholders`;
/// if the key is unknown it falls back to `defaultText` (still applying
/// substitutions via `interpolate()`).
///
/// @code
///   auto text = LocalizedText{
///       .key         = "rs-eid.error.communication",
///       .defaultText = "Failed to communicate with reader '{readerName}'.",
///       .placeholders = {
///           {.name = "readerName", .value = std::string{"PC/SC Reader"}},
///       },
///   };
/// @endcode
struct LIBRESCRS_PUBLIC_API LocalizedText
{
    /// @brief Catalog key the host uses to fetch the translated template.
    /// @details Format: `<domain>.<category>.<id>` lowercase-dot;
    ///          `<domain>` equals the plugin's pluginId or `"core"` for
    ///          middleware-owned strings, so host catalogs partition
    ///          cleanly between plugins.
    std::string key;

    /// @brief English template used when `key` is absent from the host's catalog.
    /// @details Placeholder substitution syntax: `{name}` matches `placeholders[i].name`;
    ///          `{{` produces literal `{`; unmatched `{name}` is left intact in output.
    std::string defaultText;

    /// @brief Typed substitution values for `{name}` tokens.
    std::vector<Placeholder> placeholders = {};

    /// @brief Domain segment of `key` (everything before the first dot).
    /// @details Returned `string_view` lifetime is `*this`'s; data is null-terminated
    ///          (`key` is a `std::string`).
    [[nodiscard]] std::string_view domain() const noexcept;

    /// @brief Interpolate `placeholders` into the given `format` string.
    /// @details Replaces every `{name}` token in `format` with the corresponding
    ///          `Placeholder::formatted()`. `{{` produces literal `{`. Unmatched
    ///          tokens are left intact.
    ///
    /// Used by consumers to apply their own translated format string:
    /// @code
    ///   auto translated = qtTrId(loctext.key.c_str()).toUtf8();
    ///   auto rendered   = loctext.interpolate(std::string_view{translated.constData(),
    ///                                                          static_cast<size_t>(translated.size())});
    /// @endcode
    /// @throws std::bad_alloc on allocation failure while building the
    ///         returned string.
    [[nodiscard]] std::string interpolate(std::string_view format) const;

    /// @brief Convenience: interpolate placeholders into `defaultText`.
    /// @throws std::bad_alloc on allocation failure (propagated from
    ///         @ref interpolate).
    [[nodiscard]] std::string formattedDefault() const
    {
        return interpolate(defaultText);
    }

    /// @brief Value equality (`key`, `defaultText`, `placeholders` element-wise).
    [[nodiscard]] bool operator==(const LocalizedText&) const noexcept = default;
};

} // namespace LibreSCRS
