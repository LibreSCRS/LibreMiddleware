// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

/// @file
/// @brief Compile-time guard that the legacy PKCS#11 attach API stays
///        deleted. The previous SessionAttachment + AttachHook surface
///        was the architectural gap that allowed cross-reader SM-teardown
///        because display-flow CardSessions were never parked. The
///        replacement (SessionPresence + CardSession auto-registration)
///        only holds its invariant if the manual-attach surface is
///        actually unreachable. A future commit that reintroduces the
///        header or any SessionAttachment::attach member fails this
///        translation unit at compile time.

#include <gtest/gtest.h>

#include <type_traits>

// Declare a sentinel namespace that would clash with the real legacy
// SessionAttachment type if it ever came back. The deletion is the
// load-bearing invariant; this TU compiles ONLY against the public LM
// include tree, so it would fail to build if AttachHook.h or
// SessionAttachment.h reappeared as installable headers.
namespace LibreSCRS::Pkcs11 {

struct SessionAttachment_DeletedSentinel
{
    static constexpr bool deleted = true;
};

} // namespace LibreSCRS::Pkcs11

namespace {

template <typename, typename = void>
struct has_attach_member : std::false_type
{};

template <typename T>
struct has_attach_member<T, std::void_t<decltype(&T::attach)>> : std::true_type
{};

static_assert(!has_attach_member<LibreSCRS::Pkcs11::SessionAttachment_DeletedSentinel>::value,
              "SessionAttachment::attach must remain deleted: cross-reader SM "
              "teardown protection depends on the manual-attach surface being "
              "unreachable so consumers cannot bypass auto-registration.");

} // anonymous namespace

TEST(PkcsAttachApiDeletedTest, PlaceholderForLinkage)
{
    // The static_assert at namespace scope above is the load-bearing test.
    // GTest needs at least one TEST() per binary to link.
    SUCCEED();
}
