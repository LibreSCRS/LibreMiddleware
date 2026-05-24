// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <LibreSCRS/Plugin/CardDataAccess.h>

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>

namespace LibreSCRS::Plugin {

namespace {

// Linear scan over a group's fields for a matching key. Returns the
// text-decoded value when the matched field is FieldType::Text. Returns
// nullopt on missing field, or on a matched non-text field — the contract
// is "text value or nothing", mirroring CardField::textValue().
//
// noexcept body wraps the std::string copy inside CardField::textValue()
// (the returned std::optional<std::string> moves/copies a std::string)
// per feedback_noexcept_alloc_contract: declared noexcept here, so any
// std::bad_alloc must degrade to std::nullopt rather than propagate and
// call std::terminate. textValueInGroup is the inner helper for the two
// public noexcept entry points below and therefore must hold the same
// contract.
std::optional<std::string> textValueInGroup(const CardFieldGroup& group, std::string_view fieldKey) noexcept
{
    try {
        for (const auto& field : group.fields) {
            if (field.key == fieldKey) {
                return field.textValue();
            }
        }
        return std::nullopt;
    } catch (...) {
        return std::nullopt;
    }
}

} // namespace

std::optional<std::string> textValue(const CardData& data, std::string_view groupKey,
                                     std::string_view fieldKey) noexcept
{
    try {
        // findGroup is noexcept and returns std::nullopt on miss.
        const auto idx = data.findGroup(groupKey);
        if (!idx)
            return std::nullopt;
        // groupAtUnchecked is the noexcept hot-path variant safe to use
        // immediately after findGroup (the returned index is by construction
        // in-range relative to the current `groups` vector).
        return textValueInGroup(data.groupAtUnchecked(*idx), fieldKey);
    } catch (...) {
        // textValueInGroup is itself noexcept now, but keep the guard so a
        // future refactor that adds allocating logic here cannot regress
        // the public-API noexcept contract per feedback_noexcept_alloc_contract.
        return std::nullopt;
    }
}

std::optional<std::string> textValueAt(const CardData& data, std::size_t groupIndex, std::string_view fieldKey) noexcept
{
    try {
        // Caller-supplied index: bounds-check explicitly so an out-of-range
        // host input degrades to nullopt rather than undefined behaviour
        // (groupAtUnchecked is noexcept but its precondition is in-range).
        if (groupIndex >= data.groups.size())
            return std::nullopt;
        return textValueInGroup(data.groupAtUnchecked(groupIndex), fieldKey);
    } catch (...) {
        return std::nullopt;
    }
}

} // namespace LibreSCRS::Plugin
