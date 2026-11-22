// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error                                                                                                                 \
    "LibreSCRS_internal/SecureChannel/PlainChannel.h is internal to LibreMiddleware. Public API: <LibreSCRS/SecureChannel/...>"
#endif

#pragma once

/// @file
/// @brief @ref LibreSCRS::SecureChannel::PlainChannel — the no-secure-
///        messaging implementation of @ref ISecureChannel. Default for
///        cards that do not require PACE/BAC (contact PKCS#15 and
///        equivalent).

#include <LibreSCRS_internal/SecureChannel/ISecureChannel.h>

#include <smartcard/i_connection.h>

#include "apdu.h"

#include <expected>
#include <utility>

namespace LibreSCRS::SecureChannel {

/// @brief Pass-through channel: forwards APDUs to the underlying
///        @ref LibreSCRS::SmartCard::IConnection without wrapping.
///
/// The current applet AID is recorded at construction time; subsequent
/// applet switches are out of scope — CardSession constructs a new
/// PlainChannel per selected applet. The record can only be cleared, when a
/// caller selects away from the applet, so that the next activation selects
/// it again instead of trusting the channel.
///
/// @since 4.1
class PlainChannel final : public ISecureChannel
{
public:
    /// @note Header-only, like @ref ISecureChannel itself: a plain channel
    ///       holds no secret state, and card plugins build one on their stack.
    ///       Every image that does so carries its own vtable and typeinfo, so
    ///       none needs the shared library to export them -- which a sanitizer
    ///       build (-fsanitize=vptr) would otherwise require of every image
    ///       that so much as calls a member. Nothing compares the typeinfo
    ///       across images (no dynamic_cast, typeid or catch on it).
    PlainChannel(LibreSCRS::SmartCard::IConnection& connection, LibreSCRS::SmartCard::AppletAid currentAppletAid)
        : connection(connection), appletAid(std::move(currentAppletAid))
    {}

    ~PlainChannel() override = default;

    [[nodiscard]] const LibreSCRS::SmartCard::AppletAid& currentApplet() const noexcept override
    {
        return appletAid;
    }

    [[nodiscard]] ChannelState state() const noexcept override
    {
        return channelState;
    }

    [[nodiscard]] std::expected<LibreSCRS::SmartCard::Internal::APDUResponse, LibreSCRS::SmartCard::TransportError>
    transmit(const LibreSCRS::SmartCard::Internal::APDUCommand& cmd, LibreSCRS::CancelToken token) override
    {
        if (channelState != ChannelState::Open) {
            return std::unexpected(LibreSCRS::SmartCard::TransportError{
                LibreSCRS::SmartCard::TransportError::Kind::ChannelUnusable, "the plain channel is closed"});
        }
        if (token.isCancellable() && token.isCancelled()) {
            return std::unexpected(LibreSCRS::SmartCard::TransportError{
                LibreSCRS::SmartCard::TransportError::Kind::Cancelled, "cancelled before the command was sent"});
        }
        return connection.transmit(cmd);
    }

    void close() override
    {
        channelState = ChannelState::Closed;
    }

protected:
    /// @brief Record @p aid as the current applet.
    ///
    /// Reached with an empty AID when a caller selected another file or
    /// application past the channel: a plain channel that kept its AID would
    /// let the next activation for that applet skip the SELECT and read
    /// under whatever the card has selected now.
    /// @since 4.1
    void setCurrentApplet(LibreSCRS::SmartCard::AppletAid aid) noexcept override
    {
        appletAid = std::move(aid);
    }

    /// @brief No-op: @ref PlainChannel has no SM session keys to rotate.
    /// @since 4.1
    void replaceKeys(SessionKeys /*keys*/) noexcept override
    {
        // intentionally empty — no SM key material exists on a plain channel
    }

private:
    LibreSCRS::SmartCard::IConnection& connection;
    LibreSCRS::SmartCard::AppletAid appletAid;
    ChannelState channelState = ChannelState::Open;
};

} // namespace LibreSCRS::SecureChannel
