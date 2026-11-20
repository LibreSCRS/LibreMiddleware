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
/// The implementation-detail @c LibreSCRS::SmartCard::Internal::PCSCConnection type is
/// **deliberately** absent from the public `<LibreSCRS/SmartCard/CardSession.h>`.
/// Internal LM sources that need a concrete reference go through the @ref
/// LibreSCRS::SmartCard::detail::PcscBridge struct declared here. The bridge
/// is the sole friend of @ref LibreSCRS::SmartCard::CardSession's `Impl` for
/// the unwrap path; it routes every LM-internal access through one auditable
/// point.
///
/// @since 4.0

#include <LibreSCRS/SmartCard/CardSession.h>

#include <smartcard/card_connection.h>

namespace LibreSCRS::SmartCard::detail {

/// @brief Bridge from public @ref CardSession to the LM-internal
///        @c LibreSCRS::SmartCard::Internal::PCSCConnection. LM-internal only.
///
/// @note Exported via @ref LIBRESCRS_PUBLIC_API by design: card plugins
/// (libpkcs15-plugin.so, libemrtd-plugin.so, …) load at runtime via dlopen
/// and bind against libLibreSCRS_SmartCard.so, so the unwrap entry point
/// must be reachable as a dynamic symbol. Do NOT move it out of the
/// LibreSCRS namespace that @c cmake/librescrs-public-exports.map exports —
/// the cross-`.so` plugin-reach edge depends on it being globally
/// exported. The internal-only access contract is preserved by the
/// @c #error guard above (consumers outside @c LIBRESCRS_INTERNAL_BUILD
/// cannot include this header).
struct LIBRESCRS_PUBLIC_API PcscBridge
{
    /// @brief Obtain a mutable reference to the underlying PC/SC connection.
    /// @pre @p session must NOT be in the moved-from state.
    ///
    /// Typed as the CardConnection interface, not as the connection's class:
    /// code that sees only the interface neither names the class nor lets the
    /// optimiser devirtualise a call into one of its (hidden) members, and a
    /// sanitizer build references no typeinfo the library keeps hidden.
    [[nodiscard]] static LibreSCRS::SmartCard::CardConnection& unwrap(CardSession& session) noexcept;
};

/// @brief Convenience: free-function spelling exposed inside @c detail::.
///        Equivalent to @ref PcscBridge::unwrap.
[[nodiscard]] inline LibreSCRS::SmartCard::CardConnection& unwrap(CardSession& session) noexcept
{
    return PcscBridge::unwrap(session);
}

} // namespace LibreSCRS::SmartCard::detail
