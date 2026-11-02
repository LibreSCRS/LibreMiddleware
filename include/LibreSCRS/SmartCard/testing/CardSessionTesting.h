// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

/// @file
/// @brief Test support: card sessions with no card behind them.
///
/// For the tests of projects that build on LibreSCRS — a host that routes
/// card sessions, holds them in a cache, or hands them to plugins — and need
/// a @ref LibreSCRS::SmartCard::CardSession without a reader. Link the static
/// archive @c LibreSCRS::SmartCardTesting, installed with the development
/// files:
///
/// @code
/// find_package(LibreMiddleware 5.0 REQUIRED CONFIG)
/// target_link_libraries(my_tests PRIVATE LibreSCRS::SmartCardTesting)
/// @endcode
///
/// No shipped shared library carries these functions, and production code
/// must not call them. The archive reaches into the session's private state,
/// so it is only valid with the LibreSCRS libraries of the same release —
/// which neither the CMake package's version rule nor the dynamic loader
/// checks: rebuild the tests that link it whenever LibreSCRS is upgraded.
///
/// @since 5.0

#include <LibreSCRS/Export.h>
#include <LibreSCRS/SmartCard/CardSession.h>

#include <cstdint>
#include <memory>
#include <string>

namespace LibreSCRS::SmartCard::Testing {

/// @brief A session that names @p readerName but has no reader, no card and
///        no PC/SC context behind it.
///
/// Its identity is stable for its lifetime, so it serves as a key wherever a
/// session is one (per-session plugin state, a host's session cache). Any
/// card I/O through it fails cleanly: plugins report that they cannot handle
/// it or read nothing; @ref CardSession::atr is empty.
///
/// @since 5.0
[[nodiscard]] LIBRESCRS_TEST_API std::shared_ptr<CardSession> makeDetachedCardSession(std::string readerName);

/// @brief Secure channel a test can place on a session, by the state that
///        decides @ref CardSession::hasLiveSecureChannel.
///
/// @since 5.0
enum class StandInChannel : std::uint8_t {
    /// Open and carrying secure messaging: the session reports a live
    /// secure channel.
    LiveSecureMessaging,
    /// Carrying secure messaging but failed (a broken MAC, a card-side
    /// abort): not live.
    FailedSecureMessaging,
    /// Open but plain, with no secure messaging: not live.
    Plain,
};

/// @brief Install a stand-in secure channel on @p session, replacing any
///        channel it holds.
///
/// Commands sent through the stand-in are answered with status word 6F00
/// and reach no card. The previous channel, if any, is dropped without
/// being closed. No protocol is recorded: @ref CardSession::activatedProtocol
/// stays empty.
///
/// @since 5.0
LIBRESCRS_TEST_API void installStandInChannel(CardSession& session, StandInChannel channel) noexcept;

} // namespace LibreSCRS::SmartCard::Testing
