// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

/// @file
/// @brief Qt-free convenience accessors over the @ref LibreSCRS::Plugin::CardData
///        vocabulary. Collapses the two-step "findGroup(...) -> groupAt(*idx) ->
///        find field -> textValue()" dance that GUI adapters previously hand-rolled
///        on top of the raw @ref LibreSCRS::Plugin::CardData index API.
///
/// @par Thread-safety
/// Free functions over plain value aggregates; thread-compatible per
/// API-POLICY §8. Concurrent reads of the same @ref LibreSCRS::Plugin::CardData
/// are safe; concurrent read+mutate is not.

#include <LibreSCRS/Export.h>
#include <LibreSCRS/Plugin/CardData.h>

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>

namespace LibreSCRS::Plugin {

/// @brief Look up the UTF-8 text value of a field by `(groupKey, fieldKey)`.
///
/// Collapses the two-step index dance the raw @ref CardData::findGroup /
/// @ref CardData::groupAt API requires:
/// @code
///     auto idx = data.findGroup("personal");
///     if (!idx) return {};
///     const auto& group = data.groupAt(*idx);
///     for (const auto& f : group.fields) {
///         if (f.key == "given_name") {
///             if (auto t = f.textValue()) return *t;
///             return {};
///         }
///     }
///     return {};
/// @endcode
/// into a single call returning `std::optional<std::string>`. GUI adapters
/// (e.g. LibreCelik's `librecelik::plugin::getFieldValue`) become thin
/// `QString` wrappers on top.
///
/// @param data Card payload to query.
/// @param groupKey Well-known group key (see @ref LibreSCRS::Plugin::CardData
///        for the conventional vocabulary).
/// @param fieldKey Stable field identifier within the group.
/// @return Engaged optional carrying the field's UTF-8 text value when the
///         group exists, the field exists within it, and the field's
///         @ref CardField::type is @ref FieldType::Text. `std::nullopt` when
///         any of those conditions is unmet — callers that need to
///         distinguish "missing group" from "missing field" from "field
///         is non-textual" should use the raw @ref CardData::findGroup /
///         @ref CardData::groupAt / @ref CardField::textValue triple
///         directly.
///
/// @note When multiple groups share the same @p groupKey only the first is
///       consulted (matching @ref CardData::findGroup's first-match
///       semantics). Use @ref textValueAt with an explicit group index when
///       a second-or-later group must be queried.
///
/// @par Example
/// @code
/// const auto& data = plugin->readCard(...);
/// if (auto name = LibreSCRS::Plugin::textValue(data, "personal", "given_name")) {
///     std::cout << "Given name: " << *name << '\n';
/// }
/// @endcode
///
/// @since 4.2
[[nodiscard]] LIBRESCRS_PUBLIC_API std::optional<std::string> textValue(const CardData& data, std::string_view groupKey,
                                                                        std::string_view fieldKey) noexcept;

/// @brief Look up the UTF-8 text value of a field by `(groupIndex, fieldKey)`.
///
/// Overload for the case where the caller has already located the desired
/// group via @ref CardData::findGroup (or an explicit index from a card-type
/// schema) and wants to skip the group-key linear search. Useful when a
/// card payload contains multiple groups sharing the same @ref
/// CardFieldGroup::groupKey and the caller needs to target a specific one.
///
/// @param data Card payload to query.
/// @param groupIndex Zero-based index into @ref CardData::groups. Indices
///        beyond `data.groups.size()` yield `std::nullopt`.
/// @param fieldKey Stable field identifier within the indexed group.
/// @return Engaged optional carrying the field's UTF-8 text value when the
///         index is in range, a matching field exists, and the field's
///         @ref CardField::type is @ref FieldType::Text. `std::nullopt`
///         otherwise.
///
/// @par Example
/// @code
/// if (auto idx = data.findGroup("personal")) {
///     if (auto v = LibreSCRS::Plugin::textValueAt(data, *idx, "surname")) {
///         std::cout << "Surname: " << *v << '\n';
///     }
/// }
/// @endcode
///
/// @since 4.2
[[nodiscard]] LIBRESCRS_PUBLIC_API std::optional<std::string> textValueAt(const CardData& data, std::size_t groupIndex,
                                                                          std::string_view fieldKey) noexcept;

} // namespace LibreSCRS::Plugin
