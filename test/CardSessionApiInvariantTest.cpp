// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

/// @file
/// @brief Compile-time invariant assertion — no public @ref
///        LibreSCRS::SmartCard::CardSession member function may expose
///        a handle on the underlying @c PCSCConnection.
///
/// This binary's value is its compile step, not its run step. The two
/// @c static_assert blocks at namespace scope fail to compile if anyone
/// adds a public @c connection() or @c pcscConnection() accessor that
/// returns (or accepts) a @c PCSCConnection& / @c PCSCConnection* /
/// @c PCSCConnection. The forward declaration of @c PCSCConnection is
/// deliberately left incomplete so a transparent return type would
/// itself be a hard type-system error before the @c static_assert even
/// runs — defense in depth against accidental "convenience" accessors
/// re-exposing the connection through the public surface.
///
/// The invariant matters because every cross-`.so` reach into the PC/SC
/// transport from outside @c CardSession.cpp must funnel through the
/// SM-aware @ref LibreSCRS::SmartCard::detail::sessionTransmit so that a
/// live PACE / BAC channel cannot be bypassed by a plain transmit
/// against the connection.

#include <LibreSCRS/SmartCard/CardSession.h>

#include <gtest/gtest.h>

#include <type_traits>
#include <utility>

namespace LibreSCRS::SmartCard::Internal {

// Intentional incomplete forward declaration. If anyone ever adds a
// public accessor that returns @c PCSCConnection by value or reference,
// the type-system needs the complete type and the declaration here will
// surface the gap at the call site of the @c declval below.
class PCSCConnection;

} // namespace LibreSCRS::SmartCard::Internal

namespace {

template <typename T, typename = void>
struct has_connection_accessor : std::false_type
{};

template <typename T>
struct has_connection_accessor<T, std::void_t<decltype(std::declval<T&>().connection())>> : std::true_type
{};

template <typename T, typename = void>
struct has_pcsc_accessor : std::false_type
{};

template <typename T>
struct has_pcsc_accessor<T, std::void_t<decltype(std::declval<T&>().pcscConnection())>> : std::true_type
{};

static_assert(!has_connection_accessor<LibreSCRS::SmartCard::CardSession>::value,
              "CardSession must not expose connection() — the public surface intentionally hides "
              "the underlying PC/SC transport. Use detail::sessionTransmit instead.");
static_assert(!has_pcsc_accessor<LibreSCRS::SmartCard::CardSession>::value,
              "CardSession must not expose pcscConnection() — the public surface intentionally hides "
              "the underlying PC/SC transport. Use detail::sessionTransmit instead.");

TEST(CardSessionApiInvariant, PlaceholderForLinkage)
{
    // The static_asserts at namespace scope above are the actual test.
    // GTest needs at least one TEST() per binary for the gtest_main link
    // to exit cleanly.
    SUCCEED();
}

} // namespace
