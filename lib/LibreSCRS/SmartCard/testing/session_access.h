// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "session_access.h is internal to LibreMiddleware tests"
#endif

/// @file
/// @brief @c Testing::SessionAccess — the one friend of @c CardSession that
///        test support may use to reach the session's private state.
///
/// Header-only, so the declared test archive and the build-tree tests share
/// one definition. Not installed and not on the include path of any shipped
/// library: shipped code reaches the card through the public CardSession
/// members only. Internal::connectionOf hands a test the session's connection
/// as its class; a test that calls a member of it links a test copy of the
/// class (LibreSCRS_SmartCard_RawDiagnostic), whose typeinfo the library
/// keeps hidden.

#include <LibreSCRS/SmartCard/CardSession.h>
#include <LibreSCRS_internal/SecureChannel/ISecureChannel.h>
#include <LibreSCRS_internal/SmartCard/CardSessionImpl.h>

#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace LibreSCRS::SmartCard::Testing {

struct SessionAccess
{
    /// A session over a connection that performs no PC/SC call. The private
    /// constructor builds that connection inside the shared library: the
    /// declared test archive names nothing of the connection's class.
    static std::shared_ptr<CardSession> detached(std::string readerName)
    {
        auto session = std::shared_ptr<CardSession>(new CardSession());
        session->d->readerName = std::move(readerName);
        // atr stays empty -- there is no card
        return session;
    }

    /// Sets the ATR the session reports, as a card would have at open.
    static void setAtr(CardSession& session, std::vector<std::uint8_t> atr)
    {
        session.d->atr = std::move(atr);
    }

    /// The session's connection, as its class.
    static LibreSCRS::SmartCard::Internal::PCSCConnection& connection(CardSession& session) noexcept
    {
        return *session.d->ownedConn;
    }

    /// The channel the session holds, or nullptr: what a test inspects after
    /// an activation or a key change. Borrowed; the session owns it.
    static LibreSCRS::SecureChannel::ISecureChannel* activeChannel(CardSession& session) noexcept
    {
        return session.d->activeChannel.get();
    }

    /// Whether some thread holds the session's lock right now, judged from a
    /// thread of its own (a std::mutex cannot be tried on the thread that may
    /// hold it).
    static bool lockIsHeld(CardSession& session)
    {
        bool acquired = false;
        std::thread([&] {
            std::unique_lock lock(session.d->sessionMutex, std::try_to_lock);
            acquired = lock.owns_lock();
        }).join();
        return !acquired;
    }

    /// Drops the session's connection: the state of a session that holds none.
    static void dropConnection(CardSession& session) noexcept
    {
        session.d->ownedConn.reset();
    }
};

} // namespace LibreSCRS::SmartCard::Testing

namespace LibreSCRS::SmartCard::Internal {

/// The session's connection, to arm one of its test seams.
[[nodiscard]] inline PCSCConnection& connectionOf(CardSession& session) noexcept
{
    return Testing::SessionAccess::connection(session);
}

} // namespace LibreSCRS::SmartCard::Internal
