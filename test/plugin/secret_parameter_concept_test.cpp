// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

/// @file
/// @brief A4 (4.0 hardening): compile-time enforcement of "credential
///        parameters are @c Secure::String const&". The concept reduces to
///        a structural reference test; the meaningful work is at compile
///        time, the runtime test merely confirms the binary builds.

#include <LibreSCRS/Auth/SecretParameter.h>
#include <LibreSCRS/Secure/String.h>

#include <gtest/gtest.h>

#include <string>
#include <string_view>

using LibreSCRS::Auth::detail::SecretParameter;
using LibreSCRS::Secure::String;

// Positive cases.
static_assert(SecretParameter<const String&>, "Secure::String const& must satisfy the concept");

// Negative cases — every shape that should be rejected.
static_assert(!SecretParameter<String>, "Secure::String by value must NOT satisfy (would copy the secret)");
static_assert(!SecretParameter<String&>, "Secure::String& (mutable ref) must NOT satisfy (callee could overwrite)");
static_assert(!SecretParameter<String&&>, "Secure::String && must NOT satisfy (caller left with moved-from secret)");
static_assert(!SecretParameter<const std::string&>,
              "std::string const& must NOT satisfy (escapes Secure::String's zero-on-dtor)");
static_assert(!SecretParameter<std::string_view>, "std::string_view must NOT satisfy (no cleansing semantics)");
static_assert(!SecretParameter<const char*>, "raw pointer must NOT satisfy");

TEST(SecretParameterConcept, RuntimeStubExists)
{
    // Compile-time-only — but include a runtime test so the file builds and
    // GTest discovery picks up at least one case.
    SUCCEED();
}
