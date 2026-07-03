// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

/// @file
/// @brief @ref LibreSCRS::Auth::FieldDescriptor — describes one input a
///        credential provider must collect — and
///        @ref LibreSCRS::Auth::CredentialFieldType, the input-flavour enum
///        that drives UI validation and masking.
/// @since 4.0

#include <LibreSCRS/LocalizedText.h>
#include <LibreSCRS/Export.h>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>

namespace LibreSCRS::Auth {

/// @brief Semantic flavour of a credential input field.
///
/// Drives input-masking and validation decisions in the host UI: numeric
/// keypads for PINs/CANs, MRZ-style 9303 fields, etc.
enum class CredentialFieldType : std::uint8_t {
    NumericPin,      ///< Numeric PIN (digits only, length governed by min/maxLength).
    NumericCan,      ///< Numeric Card Access Number (PACE).
    Mrz,             ///< ICAO 9303 Machine Readable Zone input (BAC seed material).
    AlphaNumericPuk, ///< Alphanumeric PUK or unblock code.
    GenericSecret,   ///< Catch-all for plugin-defined secret input.
};

/// @brief Describes one input the credential provider must collect.
///
/// A vector of these, in presentation order, forms the input contract for
/// one authentication step. Factories in @ref AuthRequirement guarantee that
/// field ids within a single requirement are unique and that any
/// @ref equalToFieldId references resolve.
///
/// @par Thread-safety
/// thread-compatible (see API-POLICY §8).
struct FieldDescriptor
{
    /// @brief Stable identifier used as the key in CredentialResult::values.
    std::string id;
    /// @brief Field flavour that drives input masking and validation.
    CredentialFieldType type = CredentialFieldType::GenericSecret;
    /// @brief True if the value is sensitive and should be masked in the UI.
    bool secret = true;
    /// @brief Minimum accepted length. @c std::nullopt means "no minimum enforced".
    ///
    /// An explicit @c std::nullopt is the only way to express "no bound";
    /// there is no `0` sentinel overload.
    std::optional<std::size_t> minLength;
    /// @brief Maximum accepted length. @c std::nullopt means "no maximum enforced".
    std::optional<std::size_t> maxLength;
    /// @brief Short user-visible label (e.g. "New PIN").
    LocalizedText label;
    /// @brief Optional helper text rendered alongside the field.
    std::optional<LocalizedText> helpText;
    /// @brief If set, the value must equal the value collected for the referenced
    /// field id. Used for "confirm new PIN" pairs.
    /// @note Resolution is performed by the @ref AuthRequirement factory
    ///       functions (`forChangePin`, `forUnblockPin`, …); direct
    ///       construction of a @ref FieldDescriptor bypassing those
    ///       factories is unsupported and may produce an
    ///       unresolved-reference state the host has no way to detect at
    ///       validation time.
    std::optional<std::string> equalToFieldId;

    /// @brief Value equality over all fields.
    bool operator==(const FieldDescriptor& other) const = default;
};

} // namespace LibreSCRS::Auth
