// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

/// @file
/// @brief @ref LibreSCRS::Auth::FieldDescriptor — the length bounds of one
///        input a credential provider must collect.
/// @since 4.0

#include <cstddef>
#include <optional>

namespace LibreSCRS::Auth {

/// @brief The length bounds of one input the credential provider must collect.
///
/// @par Thread-safety
/// thread-compatible (see API-POLICY §8).
struct FieldDescriptor
{
    /// @brief Minimum accepted length. @c std::nullopt means "no minimum enforced".
    ///
    /// An explicit @c std::nullopt is the only way to express "no bound";
    /// there is no `0` sentinel overload.
    std::optional<std::size_t> minLength;
    /// @brief Maximum accepted length. @c std::nullopt means "no maximum enforced".
    std::optional<std::size_t> maxLength;

    /// @brief Value equality over all fields.
    bool operator==(const FieldDescriptor& other) const = default;
};

} // namespace LibreSCRS::Auth
