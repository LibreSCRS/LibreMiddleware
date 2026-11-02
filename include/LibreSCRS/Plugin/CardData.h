// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

/// @file
/// @brief Card-payload vocabulary — @ref LibreSCRS::Plugin::FieldType,
///        @ref LibreSCRS::Plugin::CardField,
///        @ref LibreSCRS::Plugin::CardFieldGroup, and the outer
///        @ref LibreSCRS::Plugin::CardData document returned by plugins.
///
/// @par Thread-safety
/// All types in this header are plain value aggregates; thread-compatible
/// per API-POLICY §8.

#include <LibreSCRS/Export.h>

#include <cstdint>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace LibreSCRS::Plugin {

/// @brief Presentation-layer data type for a card field.
enum class FieldType : std::uint8_t { Text, Date, Photo, Binary };

// Well-known group keys (convention, not enforced). Regenerated from every
// `groupKey = "..."` / `annexGroupKey(...)` assignment across the plugins:
// "additional"            — emrtd-plugin: supplementary optional data
// "address"               — rs-eid-plugin, rs-health-plugin: address/residence data
// "auth_required"         — emrtd-plugin: PACE/BAC-gated data group
// "biometric_fingerprint" — emrtd-plugin: fingerprint biometric data
// "biometric_iris"        — emrtd-plugin: iris biometric data
// "carrier"               — rs-health-plugin: insurance carrier data
// "certificates"          — opensc-plugin, pkcs15-plugin: PKCS#15 certificate objects
// "contacts"              — emrtd-plugin: visa/contact travel data
// "document"              — emrtd-plugin, rs-eid-plugin: document metadata (serial, issuing, expiry)
// "document_extra"        — emrtd-plugin: additional document fields
// "holder"                — eu-vrc-plugin: vehicle registration certificate holder data
// "insurance"             — rs-health-plugin: health insurance data
// "meta"                  — rs-eid-plugin: card/plugin metadata
// "national"              — emrtd-plugin, eu-vrc-plugin: national-specific data
// "owner"                 — eu-vrc-plugin: vehicle owner data
// "personal"              — emrtd-plugin, rs-eid-plugin, rs-health-plugin: demographic
//                           identity data (name, birth, nationality)
// "photo"                 — emrtd-plugin, rs-eid-plugin: portrait/photo data
// "portrait"              — emrtd-plugin: portrait image data
// "presence"              — emrtd-plugin: presence/liveness indicator group
// "registration"          — eu-vrc-plugin: vehicle registration data
// "security_status"       — emrtd-plugin: passive/active authentication verdicts
// "signature"             — emrtd-plugin: holder signature image
// "taxpayer"              — rs-health-plugin: taxpayer identification data
// "token"                 — opensc-plugin, pkcs15-plugin: PKCS#15 token info
//                           (e.g. a PKS card, which has no "pki" group — it
//                           surfaces "token" and "certificates" instead)
// "user"                  — eu-vrc-plugin: vehicle authorized-user data
// "vehicle"               — eu-vrc-plugin: vehicle-specific data
// "verification"          — rs-eid-plugin: verification/check result group
// "annex.<id>.*"          — a national annex the card carries beside its base
//                           application: "annex.<id>.personal" for its data and
//                           "annex.<id>.security" for that annex's own verdict.
//                           The id comes from the reader, so two annexes on one
//                           card cannot collide, and the annex verdict never
//                           merges into the base "security_status" group.

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

    /// @brief Defaulted member-wise equality. Convenient for test fixtures.
    [[nodiscard]] bool operator==(const CardField&) const noexcept = default;
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
    /// @since 4.0
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

    /// @brief Defaulted member-wise equality. Convenient for test fixtures.
    [[nodiscard]] bool operator==(const CardFieldGroup&) const noexcept = default;
};

/// @brief Aggregate card read result: a card type identifier and its field groups.
struct CardData
{
    /// @brief Plugin-assigned card-type identifier (matches a plugin id).
    std::string cardType;
    /// @brief Field groups in plugin-defined order.
    std::vector<CardFieldGroup> groups;
};

} // namespace LibreSCRS::Plugin
