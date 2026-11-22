// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "LibreSCRS_internal/SmartCard/ChannelDispatch.h is internal to LibreMiddleware."
#endif

#pragma once

/// @file
/// @brief The one place that decides whether a command goes through the
///        installed secure channel or straight to the reader connection.

#include <LibreSCRS/CancelToken.h>
#include <LibreSCRS/SmartCard/TransportError.h>
#include <LibreSCRS_internal/SecureChannel/ISecureChannel.h>

#include <apdu.h>
#include <smartcard/i_connection.h>

#include <expected>
#include <optional>
#include <utility>

namespace LibreSCRS::SmartCard::Internal {

/// Send @p cmd as the session does: a fired @p token sends nothing, an
/// installed channel always gets the command (it answers ChannelUnusable
/// itself when it is not open, a secure-messaging one never falls back to
/// plain), and without a channel the command goes to @p conn.
[[nodiscard]] inline std::expected<APDUResponse, TransportError>
dispatchCommand(LibreSCRS::SecureChannel::ISecureChannel* active, IConnection& conn, const APDUCommand& cmd,
                LibreSCRS::CancelToken token)
{
    if (token.isCancellable() && token.isCancelled()) {
        return std::unexpected(
            TransportError{TransportError::Kind::Cancelled, "cancelled before the command was sent"});
    }
    if (active != nullptr) {
        return active->transmit(cmd, std::move(token));
    }
    return conn.transmit(cmd);
}

/// Why raw bytes may not go to the connection under @p active, or nothing
/// when they may (no channel, or a plain one: raw bytes bypass no secure
/// messaging there).
[[nodiscard]] inline std::optional<TransportError>
refuseRawUnder(const LibreSCRS::SecureChannel::ISecureChannel* active)
{
    if (active == nullptr || !active->carriesSm()) {
        return std::nullopt;
    }
    if (active->state() == LibreSCRS::SecureChannel::ChannelState::Open) {
        return TransportError{TransportError::Kind::SecureChannelActive,
                              "a secure channel is open: transmit through it"};
    }
    return TransportError{TransportError::Kind::ChannelUnusable, "the secure-messaging channel is not open"};
}

} // namespace LibreSCRS::SmartCard::Internal
