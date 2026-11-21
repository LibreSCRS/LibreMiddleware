// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "LibreSCRS_internal/SecureChannel/SessionChannel.h is internal to LibreMiddleware"
#endif

#pragma once

#include <LibreSCRS/CancelToken.h>
#include <LibreSCRS/SmartCard/ActiveChannelHolder.h>
#include <LibreSCRS/SmartCard/AppletAid.h>
#include <LibreSCRS/SmartCard/CardSession.h>
#include <LibreSCRS_internal/SecureChannel/ISecureChannel.h>

#include <smartcard/session_connection.h>

#include "apdu.h"

#include <optional>

namespace LibreSCRS::SecureChannel {

/// The channel a card session holds, for a card library, through the public
/// calls of the session.
///
/// Header-only and used inside a card plugin: its vtable and typeinfo are the
/// plugin's own. Commands go through CardSession::transmit, so they take the
/// path the session's channel dictates at the time of the call -- the channel
/// that is installed now, also after the session replaced it (Chip
/// Authentication over a plain channel installs a secure-messaging one).
/// state() is the installed channel's; with none installed the session sends
/// plain, which reads as Open. Only forgetting the current applet is passed
/// on: selecting one, closing the channel and its keys are the session's.
class SessionChannel final : public ISecureChannel
{
public:
    explicit SessionChannel(LibreSCRS::SmartCard::CardSession& session) noexcept : session(session) {}

    /// The channel @p holder runs over, or none when the holder no longer
    /// holds the session or the session no longer holds a channel.
    [[nodiscard]] static std::optional<SessionChannel> held(LibreSCRS::SmartCard::CardSession& session,
                                                            const LibreSCRS::SmartCard::ActiveChannelHolder& holder)
    {
        if (!holder.isActive() || !session.channelState().has_value()) {
            return std::nullopt;
        }
        return std::optional<SessionChannel>(std::in_place, session);
    }

    /// Not tracked here: the session's channel records it, and nothing that
    /// reads a card through this adapter asks for it.
    [[nodiscard]] const LibreSCRS::SmartCard::AppletAid& currentApplet() const noexcept override
    {
        return noApplet;
    }

    [[nodiscard]] ChannelState state() const noexcept override
    {
        return session.channelState().value_or(ChannelState::Open);
    }

    [[nodiscard]] LibreSCRS::SmartCard::Internal::APDUResponse
    transmit(const LibreSCRS::SmartCard::Internal::APDUCommand& cmd, LibreSCRS::CancelToken token) override
    {
        return LibreSCRS::SmartCard::SessionConnection::transmitThrough(session, cmd, std::move(token));
    }

    /// The session owns its channel's lifetime: nothing to do here.
    void close() override {}

    [[nodiscard]] bool carriesSm() const noexcept override
    {
        return session.carriesSecureMessaging();
    }

protected:
    void setCurrentApplet(LibreSCRS::SmartCard::AppletAid aid) noexcept override
    {
        if (aid.empty()) {
            session.forgetCurrentApplet();
        }
    }

    void replaceKeys(SessionKeys /*keys*/) noexcept override
    {
        // the keys never leave the library
    }

private:
    LibreSCRS::SmartCard::CardSession& session;
    LibreSCRS::SmartCard::AppletAid noApplet;
};

} // namespace LibreSCRS::SecureChannel
