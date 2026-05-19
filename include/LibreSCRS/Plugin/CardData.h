// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

/// @file
/// @brief Card-payload vocabulary — @ref LibreSCRS::Plugin::FieldType,
///        @ref LibreSCRS::Plugin::CardField,
///        @ref LibreSCRS::Plugin::CardFieldGroup, and the outer
///        @ref LibreSCRS::Plugin::CardData document returned by plugins.

#include <LibreSCRS/Export.h>

#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace LibreSCRS::Plugin {

/// @brief Presentation-layer data type for a card field.
enum class FieldType : std::uint8_t { Text, Date, Photo, Binary };

// Well-known group keys (convention, not enforced):
// "personal"     — demographic identity data (name, birth, nationality)
// "address"      — address/residence data
// "document"     — document metadata (serial, issuing, expiry)
// "photo"        — portrait/photo data
// "pki"          — PKI-related info (certificate count, key references)
// "vehicle"      — vehicle-specific data
// "insurance"    — health insurance data
// Cards with only PKI (e.g. PKS) may have only a "pki" group.

/// @brief A single card data field with plugin-chosen key, label, and typed value.
struct CardField
{
    /// @brief Stable identifier used by GUI widgets to find the field.
    std::string key;
    /// @brief Human-readable label produced by the plugin.
    std::string label;
    /// @brief Presentation hint used by GUI widgets.
    FieldType type;
    /// @brief Raw value bytes; interpretation depends on @ref type.
    std::vector<std::uint8_t> value;

    /// @brief Interpret @ref value as UTF-8 text when the field is textual.
    ///
    /// Returns the bytes as a `std::string` ONLY when @ref type equals
    /// @c FieldType::Text. For @c FieldType::Date, @c FieldType::Photo and
    /// @c FieldType::Binary it returns `std::nullopt` so callers cannot
    /// accidentally treat raw binary / image bytes as printable text, and
    /// cannot rely on an implicit "dates are strings" assumption that hides
    /// plugin-specific date encodings (YYMMDD vs. YYYY-MM-DD vs. raw BCD).
    ///
    /// Callers that need the raw bytes for any non-Text field (e.g. to parse
    /// a date with a specific format) should read @ref value directly — the
    /// byte sequence is the canonical representation at this API layer.
    ///
    /// @note The raw bytes in @ref value are copied verbatim into the
    /// `std::string`; no UTF-8 validation or transcoding is performed.
    /// Plugins are expected to populate @ref value with well-formed UTF-8 for
    /// fields typed as `FieldType::Text`. If @ref value contains invalid
    /// UTF-8, the returned string still holds the exact byte sequence;
    /// downstream consumers (e.g. Qt's `QString::fromStdString`) may silently
    /// replace invalid sub-sequences with U+FFFD or mis-render them. Callers
    /// that need strict validation should inspect @ref value directly.
    ///
    /// @since 4.0 — replaces the unconditional `asString()` method that
    /// returned binary bytes for Photo/Binary fields as if they were text.
    /// 4.0 tightened the contract further by dropping Date from the
    /// set of Text-compatible types: use @ref value with a date-format
    /// parser of choice instead of relying on a string interpretation.
    [[nodiscard]] std::optional<std::string> textValue() const
    {
        if (type != FieldType::Text) {
            return std::nullopt;
        }
        return std::string{value.begin(), value.end()};
    }
};

/// @brief A labelled collection of related fields (e.g. demographic, PKI).
struct CardFieldGroup
{
    /// @brief Well-known group key (see conventions above).
    std::string groupKey;
    /// @brief Human-readable group label.
    std::string groupLabel;
    /// @brief Fields within the group, in plugin-defined order.
    std::vector<CardField> fields;

    /// @brief Append a text field to @ref fields when @p val is non-empty.
    ///
    /// Convenience used by plugins populating demographic groups. Parameters
    /// are taken by @c std::string_view and copied into the newly constructed
    /// @ref CardField, which keeps call-sites independent of whether the
    /// caller holds a @c std::string, a @c const @c char*, or a view into a
    /// larger buffer.
    ///
    /// @return Reference to the inserted @ref CardField, or to the final
    ///         existing field in @ref fields when @p val is empty (no
    ///         insertion happened) AND @ref fields was already non-empty.
    ///         Check @c result.key against @p key if you must distinguish
    ///         the two cases; typical use chains a follow-up setter
    ///         (e.g. `group.addText(...).label = ...`) only when insertion
    ///         is known to succeed.
    ///
    /// @throws std::invalid_argument if @p key is empty. Per API-POLICY §5.1
    ///         (eager validation): a field without a stable key cannot be
    ///         located by a GUI widget afterwards — silently returning the
    ///         last existing field on an empty-key call hid this caller bug.
    /// @throws std::logic_error if @p val is empty AND @ref fields is empty.
    ///         Returning a reference into an empty vector would be undefined
    ///         behaviour; eager rejection turns the corner case into a
    ///         catchable programmer error.
    ///
    /// @since 4.0 — replaces the `LibreSCRS::Plugin::addTextField`
    /// free function; member form is consistent with the rest of the
    /// `CardFieldGroup` API.
    /// @since 4.0 — empty-key validation per API-POLICY §5.1.
    CardField& addText(std::string_view key, std::string_view label, std::string_view val)
    {
        if (key.empty()) {
            throw std::invalid_argument("CardFieldGroup::addText: key must not be empty");
        }
        if (!val.empty()) {
            fields.push_back(CardField{std::string{key}, std::string{label}, FieldType::Text,
                                       std::vector<std::uint8_t>{val.begin(), val.end()}});
        } else if (fields.empty()) {
            throw std::logic_error("CardFieldGroup::addText: empty value with no prior field — "
                                   "no reference to return; ensure at least one field was inserted before "
                                   "an empty-value addText call, or guard the call site");
        }
        return fields.back();
    }
};

/// @brief Aggregate card read result: a card type identifier and its field groups.
struct CardData
{
    /// @brief Plugin-assigned card-type identifier (matches a plugin id).
    std::string cardType;
    /// @brief Field groups in plugin-defined order.
    std::vector<CardFieldGroup> groups;

    /// @brief Locate a group by key; returns @c std::nullopt when absent.
    ///
    /// Returns the index into @ref groups so callers never hold a reference
    /// that can be silently invalidated by a subsequent mutation. Use
    /// @ref groupAt to fetch the @ref CardFieldGroup itself.
    ///
    /// @note The index is stable only relative to the current @ref groups
    ///       vector. Any mutation that erases or inserts earlier in the
    ///       vector (`insert`/`erase`/`resize`/`clear`) invalidates previously-
    ///       obtained indices. `push_back`/`emplace_back` append at the end
    ///       and never invalidate existing indices.
    /// @since 4.0 — replaces the `optional<reference_wrapper<...>>`
    /// return introduced earlier in 4.0. An index is robust across container
    /// mutation semantics and encodes the lifetime contract explicitly:
    /// callers that want the group pay for the `groupAt` lookup.
    [[nodiscard]] std::optional<std::size_t> findGroup(std::string_view key) const noexcept
    {
        for (std::size_t i = 0; i < groups.size(); ++i) {
            if (groups[i].groupKey == key)
                return i;
        }
        return std::nullopt;
    }

    /// @brief Locate a field by key across all groups; returns @c std::nullopt
    ///        when absent.
    ///
    /// Returns `(groupIndex, fieldIndex)` into `groups[g].fields[f]`. Groups
    /// are searched in order; if multiple groups contain a field with the
    /// same key, the first match wins.
    ///
    /// @note The returned pair is stable only relative to the current
    ///       @ref groups vector and the matched group's @c fields vector.
    ///       Any mutation of either vector that erases or inserts earlier
    ///       elements invalidates the pair.
    /// @since 4.0 — replaces the `optional<reference_wrapper<...>>`
    /// return introduced earlier in 4.0.
    [[nodiscard]] std::optional<std::pair<std::size_t, std::size_t>> findField(std::string_view key) const noexcept
    {
        for (std::size_t g = 0; g < groups.size(); ++g) {
            for (std::size_t f = 0; f < groups[g].fields.size(); ++f) {
                if (groups[g].fields[f].key == key)
                    return std::pair<std::size_t, std::size_t>{g, f};
            }
        }
        return std::nullopt;
    }

    /// @brief Access a group by index, with bounds checking.
    /// @param index Zero-based group index. Must be less than `groups.size()`.
    /// @return Reference to the indexed group.
    /// @throws std::out_of_range if @p index is out of range. The exception
    ///         carries a message identifying the offending index and the
    ///         current `groups.size()`.
    /// @note Indexed lookup with caller-supplied indices is host input —
    ///       per API-POLICY §5.1, callers see a structured failure rather
    ///       than undefined behaviour. Hot-path callers that have already
    ///       bounds-checked may use @ref groupAtUnchecked for the noexcept,
    ///       no-overhead variant.
    /// @since 4.0.
    [[nodiscard]] CardFieldGroup& groupAt(std::size_t index)
    {
        return groups.at(index);
    }
    /// @copydoc groupAt
    [[nodiscard]] const CardFieldGroup& groupAt(std::size_t index) const
    {
        return groups.at(index);
    }

    /// @brief Access a group by index without bounds checking.
    /// @pre @p index must be less than `groups.size()`. Out-of-range access
    ///      is undefined behaviour.
    /// @return Reference to the indexed group.
    /// @note @c noexcept hot-path variant. Use after a programmatic
    ///       bounds-check or with an index returned from @ref findGroup.
    ///       For host-supplied indices use @ref groupAt instead.
    /// @since 4.0.
    [[nodiscard]] CardFieldGroup& groupAtUnchecked(std::size_t index) noexcept
    {
        return groups[index];
    }
    /// @copydoc groupAtUnchecked
    [[nodiscard]] const CardFieldGroup& groupAtUnchecked(std::size_t index) const noexcept
    {
        return groups[index];
    }

    /// @brief Access a field by (group, field) index pair, with bounds checking.
    /// @param g Zero-based group index.
    /// @param f Zero-based field index within the group.
    /// @return Reference to the indexed field.
    /// @throws std::out_of_range if either @p g or @p f is out of range.
    /// @note See @ref groupAt for the host-input rationale.
    /// @since 4.0.
    [[nodiscard]] CardField& fieldAt(std::size_t g, std::size_t f)
    {
        return groups.at(g).fields.at(f);
    }
    /// @copydoc fieldAt
    [[nodiscard]] const CardField& fieldAt(std::size_t g, std::size_t f) const
    {
        return groups.at(g).fields.at(f);
    }
    /// @brief Access a field by (group, field) index pair packed into a
    ///        @c std::pair (matches the @ref findField return shape).
    /// @throws std::out_of_range if @p idx is out of range.
    [[nodiscard]] CardField& fieldAt(std::pair<std::size_t, std::size_t> idx)
    {
        return groups.at(idx.first).fields.at(idx.second);
    }
    /// @brief Const overload of fieldAt accepting a packed index pair.
    /// @param idx (group, field) index pair.
    /// @throws std::out_of_range if @p idx is out of range.
    [[nodiscard]] const CardField& fieldAt(std::pair<std::size_t, std::size_t> idx) const
    {
        return groups.at(idx.first).fields.at(idx.second);
    }

    /// @brief Access a field by (group, field) index pair without bounds checking.
    /// @pre `g < groups.size()` and `f < groups[g].fields.size()`. Out-of-range
    ///      access is undefined behaviour.
    /// @return Reference to the indexed field.
    /// @note @c noexcept hot-path variant. Use after a programmatic bounds
    ///       check or with indices returned from @ref findField. For
    ///       host-supplied indices use @ref fieldAt instead.
    /// @since 4.0.
    [[nodiscard]] CardField& fieldAtUnchecked(std::size_t g, std::size_t f) noexcept
    {
        return groups[g].fields[f];
    }
    /// @copydoc fieldAtUnchecked
    [[nodiscard]] const CardField& fieldAtUnchecked(std::size_t g, std::size_t f) const noexcept
    {
        return groups[g].fields[f];
    }
    /// @copydoc fieldAtUnchecked
    [[nodiscard]] CardField& fieldAtUnchecked(std::pair<std::size_t, std::size_t> idx) noexcept
    {
        return groups[idx.first].fields[idx.second];
    }
    /// @copydoc fieldAtUnchecked
    [[nodiscard]] const CardField& fieldAtUnchecked(std::pair<std::size_t, std::size_t> idx) const noexcept
    {
        return groups[idx.first].fields[idx.second];
    }
};

} // namespace LibreSCRS::Plugin
