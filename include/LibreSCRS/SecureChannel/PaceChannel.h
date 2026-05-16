// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

/// @file
/// @brief @ref LibreSCRS::SecureChannel::PaceChannel — secure-messaging
///        channel keyed by a completed PACE handshake (BSI TR-03110).
///
/// PaceChannel encapsulates the SM wrap/unwrap layer that sits between
/// a plugin's @c transmit call and the underlying PC/SC reader. The
/// channel transitions to @ref ChannelState::Failed on SW 6987/6988 or
/// response MAC verification failure; callers should drop the channel
/// and re-activate via @ref LibreSCRS::SmartCard::CardSession.

#include <LibreSCRS/CancelToken.h>
#include <LibreSCRS/Export.h>
#include <LibreSCRS/SecureChannel/ChannelErrors.h>
#include <LibreSCRS/SecureChannel/ISecureChannel.h>
#include <LibreSCRS/SecureChannel/PaceParams.h>
#include <LibreSCRS/SecureChannel/SessionKeys.h>

#include <memory>

namespace LibreSCRS::SmartCard {
class IConnection;
} // namespace LibreSCRS::SmartCard

namespace LibreSCRS::SecureChannel {

namespace detail {
class PaceChannelImpl;
} // namespace detail

/// @brief PACE-derived SM channel. Owns its session keys; zeroises them
///        on @ref close and destruction.
///
/// The channel is session-scoped: PACE session keys derived at MF level
/// bind the card-side SM tunnel for the lifetime of the card session,
/// not for a particular applet. Applet switches go through wrapped
/// `SELECT` issued via @ref transmit and tracked through @ref
/// setCurrentApplet; the channel itself does NOT re-handshake on applet
/// change.
///
/// @since 4.1
class LIBRESCRS_PUBLIC_API PaceChannel final : public ISecureChannel
{
public:
    /// @brief Outcome of @ref PaceChannel::establish.
    ///
    /// On success @ref channel is a constructed @ref PaceChannel and
    /// @ref error is @ref ChannelActivationError::None. On failure the
    /// channel is `nullptr` and @ref error carries the mapped category.
    ///
    /// @since 4.1
    struct LIBRESCRS_PUBLIC_API HandshakeResult
    {
        std::unique_ptr<PaceChannel> channel;
        ChannelActivationError error = ChannelActivationError::None;
    };

    PaceChannel(LibreSCRS::SmartCard::IConnection& connection, LibreSCRS::SmartCard::AppletAid currentAppletAid,
                SessionKeys keys);

    ~PaceChannel() override;

    [[nodiscard]] LibreSCRS::SmartCard::AppletAid currentApplet() const noexcept override;
    [[nodiscard]] ChannelState state() const noexcept override;

    [[nodiscard]] LibreSCRS::SmartCard::Internal::APDUResponse
    transmit(const LibreSCRS::SmartCard::Internal::APDUCommand& cmd, LibreSCRS::CancelToken token) override;

    void close() override;

    /// @brief Update the channel's @ref currentApplet to reflect the AID
    ///        targeted by the most recent successful wrapped SELECT.
    ///
    /// Called by @ref LibreSCRS::SmartCard::CardSession after issuing a
    /// wrapped `SELECT <aid>` through this channel (Cases 2 / 3 of
    /// @ref CardSession::activateChannelWithSm). PACE SM is session-
    /// scoped at the card OS layer; the AID is mutable channel state, not
    /// a constructor-bound identity. Not part of the consumer API.
    ///
    /// @since 4.1
    void setCurrentApplet(LibreSCRS::SmartCard::AppletAid aid) noexcept;

    /// @brief Replace the channel's SM session keys with @p keys.
    ///
    /// Called after Chip Authentication (BSI TR-03110 §4.4) derives fresh
    /// CA-bound keys. The previous SM keys are zeroised through the
    /// underlying primitive's destructor before installation. Idempotent
    /// and leaves the channel in @ref ChannelState::Open on success.
    /// Not part of the consumer API.
    ///
    /// @since 4.1
    void replaceKeys(SessionKeys keys) noexcept override;

    /// @brief Run a PACE handshake at MF level against @p connection.
    ///
    /// The handshake's plain APDUs (MSE:Set AT, General Authenticate
    /// rounds, Mutual Auth) travel through @p connection directly; only
    /// post-handshake APDUs sent via the returned channel are wrapped in
    /// SM. The handshake itself runs at MF and binds session keys to the
    /// card-side SM tunnel for the entire card session — not to any
    /// particular applet (BSI TR-03110 §3). The returned channel reports
    /// an empty @ref currentApplet; the caller (typically
    /// @ref CardSession::activateChannelWithSm) issues a wrapped `SELECT`
    /// through the channel and calls @ref setCurrentApplet to record the
    /// AID. The caller is expected to hold a PC/SC transaction across the
    /// full activation sequence.
    ///
    /// @param connection Concrete connection. The current implementation
    ///        requires a @ref LibreSCRS::SmartCard::Internal::PCSCConnection;
    ///        any other implementation maps to @ref
    ///        ChannelActivationError::Internal.
    /// @param params PACE inputs: OID, password type, password bytes,
    ///        standardised domain parameter id.
    /// @param token Cancellation token honoured before the handshake
    ///        starts.
    /// @return On success a populated @ref HandshakeResult::channel; on
    ///         failure @ref HandshakeResult::error carries the category.
    ///
    /// @since 4.1
    [[nodiscard]] static HandshakeResult establish(LibreSCRS::SmartCard::IConnection& connection,
                                                   const PACEParams& params, LibreSCRS::CancelToken token);

private:
    std::unique_ptr<detail::PaceChannelImpl> pImpl;
};

} // namespace LibreSCRS::SecureChannel
