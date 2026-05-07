// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "LibreSCRS/SmartCard/detail/Unwrap.h is internal to LibreMiddleware"
#endif

/// @file
/// @brief LM-internal access points for unwrapping a @ref
///        LibreSCRS::SmartCard::CardSession into the underlying PC/SC
///        connection primitive.
///
/// The implementation-detail @c smartcard::PCSCConnection type is
/// **deliberately** absent from the public `<LibreSCRS/SmartCard/CardSession.h>`.
/// Internal LM sources that need a concrete reference go through the @ref
/// LibreSCRS::SmartCard::detail::PcscBridge struct declared here. The bridge
/// is the sole friend of @ref LibreSCRS::SmartCard::CardSession's `Impl` for
/// the unwrap path; it routes every LM-internal access through one auditable
/// point.
///
/// @since 4.0

#include <LibreSCRS/SmartCard/CardSession.h>

namespace smartcard {
class PCSCConnection;
} // namespace smartcard

namespace LibreSCRS::SmartCard::detail {

/// @brief Bridge from public @ref CardSession to the LM-internal
///        @c smartcard::PCSCConnection. LM-internal only.
struct PcscBridge
{
    /// @brief Obtain a mutable reference to the underlying PC/SC connection.
    /// @pre @p session must NOT be in the moved-from state.
    [[nodiscard]] static smartcard::PCSCConnection& unwrap(CardSession& session) noexcept;

    /// @brief Obtain a const reference to the underlying PC/SC connection.
    /// @pre @p session must NOT be in the moved-from state.
    [[nodiscard]] static const smartcard::PCSCConnection& unwrap(const CardSession& session) noexcept;
};

/// @brief Convenience: free-function spelling exposed inside @c detail::.
///        Equivalent to @ref PcscBridge::unwrap.
[[nodiscard]] inline smartcard::PCSCConnection& unwrap(CardSession& session) noexcept
{
    return PcscBridge::unwrap(session);
}

/// @brief Convenience: free-function wrapper around @ref PcscBridge::unwrap
///        (const overload).
[[nodiscard]] inline const smartcard::PCSCConnection& unwrap(const CardSession& session) noexcept
{
    return PcscBridge::unwrap(session);
}

} // namespace LibreSCRS::SmartCard::detail
