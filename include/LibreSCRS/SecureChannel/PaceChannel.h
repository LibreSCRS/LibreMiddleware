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

#include <expected>
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
    PaceChannel(LibreSCRS::SmartCard::IConnection& connection, LibreSCRS::SmartCard::AppletAid currentAppletAid,
                SessionKeys keys);

    ~PaceChannel() override;

    [[nodiscard]] const LibreSCRS::SmartCard::AppletAid& currentApplet() const noexcept override;
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
    /// @note Internal helper; consumers should use
    ///       @ref LibreSCRS::SmartCard::CardSession::activateChannelFor or
    ///       @ref LibreSCRS::SmartCard::CardSession::activateChannelWithSm,
    ///       which dispatch to the appropriate channel factory internally.
    ///       The @c IConnection parameter type is not part of the installed
    ///       public surface and this overload is therefore not callable
    ///       from external SDK consumers.
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
    /// @return On success a constructed @ref PaceChannel; on failure the
    ///         unexpected value carries the mapped
    ///         @ref ChannelActivationError category. Mirrors sibling 4.1
    ///         factories so consumers see one unified error idiom.
    ///
    /// @since 4.1
    ///
    /// @note Carries default visibility (not `LIBRESCRS_INTERNAL`) so the
    ///       symbol is exported across LM shared-library boundaries:
    ///       `LibreSCRS_SmartCard` (CardSession) is the in-tree caller and
    ///       lives in a sibling .so under `LIBREMIDDLEWARE_BUILD_SHARED=ON`.
    ///       External consumers cannot construct an `IConnection`
    ///       (header lives outside `include/LibreSCRS/`), so the exported
    ///       symbol remains effectively private to the project.
    [[nodiscard]] LIBRESCRS_PUBLIC_API static std::expected<std::unique_ptr<PaceChannel>, ChannelActivationError>
    establish(LibreSCRS::SmartCard::IConnection& connection, const PACEParams& params,
              LibreSCRS::CancelToken token) noexcept;

private:
    std::unique_ptr<detail::PaceChannelImpl> pImpl;
};

} // namespace LibreSCRS::SecureChannel
