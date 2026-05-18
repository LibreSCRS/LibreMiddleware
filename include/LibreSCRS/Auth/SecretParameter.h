// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

/// @file
/// @brief @ref LibreSCRS::Auth::SecretParameter — concept used as a
///        compile-time sentinel that pins credential-bearing parameters to
///        @ref LibreSCRS::Secure::String const&.
///
/// @since 4.1 (promoted to public from `Auth/detail/SecretParameter.h`).
///
/// @par Design rationale
/// Every credential-bearing virtual on @ref LibreSCRS::Plugin::CardPlugin
/// takes @c Secure::String const&; this concept makes the rule
/// machine-checkable. A future maintainer who relaxes a parameter type to
/// @c std::string (e.g. for "convenience") would silently widen the
/// secret-cleansing boundary — the @c std::string copy escapes
/// @ref LibreSCRS::Secure::String's destructor-zero invariant. With the
/// concept asserted at the declaration, the relaxation fails to compile
/// with a friendly error message instead.
///
/// Per Stroustrup, *A Tour of C++* 3e §8.2 (concepts replace SFINAE for
/// template constraints) and Meyers, *Effective Modern C++* Item 18 (use
/// std::unique_ptr / RAII for ownership), the concept is structurally
/// strict: @c Secure::String const& only — no @c Secure::String by value
/// (would copy the secret), no @c Secure::String && (rvalue would leave
/// the caller with a moved-from secret), no widening to @c std::string,
/// @c std::string_view, or any other type.

#include <LibreSCRS/Secure/String.h>

#include <concepts>
#include <type_traits>

namespace LibreSCRS::Auth {

/// @brief True iff @p T is exactly @c LibreSCRS::Secure::String const&.
///
/// Use as `static_assert(SecretParameter<decltype(arg)>, "credential params
/// must be Secure::String const&");` on the relevant entry point so a
/// silent widening to @c std::string fails to compile.
///
/// The constraint chain is:
///   1. The decayed type is exactly @c Secure::String (rules out
///      @c std::string, @c std::string_view, @c QString, @c char*, etc.).
///   2. @p T is a reference type (rules out by-value pass — would copy the
///      secret bytes into the parameter slot).
///   3. @p T is not an rvalue reference (rules out @c Secure::String && —
///      the caller would be left with a moved-from secret).
///   4. The referenced type is @c const (rules out @c Secure::String& —
///      mutable references invite the callee to overwrite the caller's
///      buffer).
///
/// @since 4.1
template <typename T>
concept SecretParameter = std::same_as<std::remove_cvref_t<T>, Secure::String> && std::is_lvalue_reference_v<T> &&
                          std::is_const_v<std::remove_reference_t<T>>;

} // namespace LibreSCRS::Auth
