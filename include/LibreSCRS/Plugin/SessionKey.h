// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

/// @file
/// @brief @ref LibreSCRS::Plugin::SessionKey — the sanctioned per-session map
///        key for a @ref CardPlugin's internal per-session state, plus
///        @ref LibreSCRS::Plugin::makeSessionKey to derive one from a live
///        session.
///
/// @par Rationale
/// A @ref CardPlugin instance is shared across every reader session, so any
/// per-session state (credentials, PACE-gating flags, …) MUST be keyed by an
/// identity that is stable for the lifetime of one session yet definitively
/// distinct from any successor session — even when the OS reissues the same
/// @c PCSCConnection address to a freshly opened reader. Raw-pointer keying
/// used to silently leak state in that scenario. Combining the reader name
/// with the session's monotonic generation counter (see
/// @ref LibreSCRS::SmartCard::detail::sessionGeneration) yields exactly that
/// identity. This is the same pattern documented on
/// @ref CardPlugin::setCredentials.
///
/// @par Thread-safety
/// @ref SessionKey is a plain value aggregate with no internal
/// synchronisation; thread-compatible per API-POLICY §8.
///
/// @since 4.3

#include <LibreSCRS/SmartCard/CardSession.h>

#include <compare>
#include <cstdint>
#include <string>

namespace LibreSCRS::Plugin {

/// @brief Per-session state-map key for @ref CardPlugin implementations.
///
/// @see makeSessionKey
struct SessionKey
{
    /// @brief Reader the session is bound to.
    std::string readerName;
    /// @brief Session's monotonic generation counter (see
    ///        @ref LibreSCRS::SmartCard::detail::sessionGeneration).
    std::uint64_t generation{0};

    /// @brief Defaulted three-way comparison for use as an ordered map key.
    auto operator<=>(const SessionKey&) const = default;
};

/// @brief Derive the @ref SessionKey for a live @p session.
[[nodiscard]] inline SessionKey makeSessionKey(LibreSCRS::SmartCard::CardSession& session)
{
    return SessionKey{session.readerName(), LibreSCRS::SmartCard::detail::sessionGeneration(session)};
}

} // namespace LibreSCRS::Plugin
