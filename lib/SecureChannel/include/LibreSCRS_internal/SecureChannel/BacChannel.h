// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error                                                                                                                 \
    "LibreSCRS_internal/SecureChannel/BacChannel.h is internal to LibreMiddleware. Public API: <LibreSCRS/SecureChannel/...>"
#endif

#pragma once

/// @file
/// @brief @ref LibreSCRS::SecureChannel::BacChannel — secure-messaging
///        channel keyed by a completed BAC handshake (ICAO Doc 9303
///        Part 11). Used for classical eMRTD passports lacking PACE
///        SecurityInfos.

#include <LibreSCRS/CancelToken.h>
#include <LibreSCRS/Export.h>
#include <LibreSCRS/SecureChannel/BacParams.h>
#include <LibreSCRS/SecureChannel/ChannelErrors.h>
#include <LibreSCRS_internal/SecureChannel/ISecureChannel.h>
#include <LibreSCRS_internal/SecureChannel/SessionKeys.h>

#include <expected>
#include <memory>

namespace LibreSCRS::SmartCard {
class IConnection;
} // namespace LibreSCRS::SmartCard

namespace LibreSCRS::SecureChannel {

namespace detail {
class BacChannelImpl;
} // namespace detail

/// @brief BAC-derived SM channel. Wire-format identical to PACE-SM but
///        cryptography is 3DES + ISO 9797-1 MAC algorithm 3.
///
/// @since 4.1
class LIBRESCRS_PUBLIC_API BacChannel final : public ISecureChannel
{
public:
    BacChannel(LibreSCRS::SmartCard::IConnection& connection, LibreSCRS::SmartCard::AppletAid currentAppletAid,
               SessionKeys keys);

    ~BacChannel() override;

    [[nodiscard]] const LibreSCRS::SmartCard::AppletAid& currentApplet() const noexcept override;
    [[nodiscard]] ChannelState state() const noexcept override;

    [[nodiscard]] LibreSCRS::SmartCard::Internal::APDUResponse
    transmit(const LibreSCRS::SmartCard::Internal::APDUCommand& cmd, LibreSCRS::CancelToken token) override;

    void close() override;

    /// @brief BAC-derived channels maintain a card-side SM tunnel.
    /// @return Always @c true.
    /// @since 4.1
    [[nodiscard]] bool carriesSm() const noexcept override
    {
        return true;
    }

    /// @brief BAC channels do NOT support cross-applet reuse: the BAC card
    ///        matrix (classical eMRTD passports) is single-applet, so the
    ///        AID is constructor-bound and cross-applet switches fall
    ///        through to a fresh handshake.
    /// @return Always @c false (inherited default kept explicit for
    ///         documentation; the base default would suffice).
    /// @since 4.1
    [[nodiscard]] bool supportsCrossAppletReuse() const noexcept override
    {
        return false;
    }

protected:
    /// @brief Update the channel's @ref currentApplet to reflect a new AID.
    ///
    /// Reached through
    /// @ref LibreSCRS::SecureChannel::detail::ChannelStateMutator from
    /// LM-internal sources only.
    /// @since 4.1
    void setCurrentApplet(LibreSCRS::SmartCard::AppletAid aid) noexcept override;

    /// @brief Replace the channel's SM session keys with @p keys.
    ///
    /// BAC has no Chip-Authentication-style key rotation in the classical
    /// ICAO Doc 9303 Part 11 flow, but the override exists so callers can
    /// treat all SM channels uniformly. Symmetric with
    /// @ref PaceChannel::replaceKeys. Reached through
    /// @ref LibreSCRS::SecureChannel::detail::ChannelStateMutator from
    /// LM-internal sources only.
    ///
    /// @since 4.1
    void replaceKeys(SessionKeys keys) noexcept override;

public:
    /// @brief Run a BAC handshake against @p connection and, on success,
    ///        return a ready-to-use @ref BacChannel bound to @p appletAid.
    ///
    /// @note Internal helper; consumers should use
    ///       @ref LibreSCRS::SmartCard::CardSession::activateChannelFor or
    ///       @ref LibreSCRS::SmartCard::CardSession::activateChannelWithSm,
    ///       which dispatch to the appropriate channel factory internally.
    ///       The @c IConnection parameter type is not part of the installed
    ///       public surface and this overload is therefore not callable
    ///       from external SDK consumers.
    ///
    /// BAC keys are derived from the three MRZ-Z field components carried
    /// in @p input (ICAO Doc 9303 Part 11 §4.3). The handshake's mutual-
    /// authentication APDUs travel through @p connection directly; only
    /// post-handshake APDUs sent via the returned channel are wrapped in
    /// SM.
    ///
    /// @param connection Concrete connection. The current implementation
    ///        requires a @ref LibreSCRS::SmartCard::Internal::PCSCConnection;
    ///        any other implementation maps to @ref
    ///        ChannelActivationError::Internal.
    /// @param appletAid AID the channel will be bound to in its public
    ///        surface; the handshake itself targets the active eMRTD applet
    ///        on the card.
    /// @param input MRZ-Z fields (document number, date of birth, date of
    ///        expiry). Check digits are computed internally.
    /// @param token Cancellation token honoured before the handshake
    ///        starts.
    /// @return On success a constructed @ref BacChannel; on failure the
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
    [[nodiscard]] LIBRESCRS_PUBLIC_API static std::expected<std::unique_ptr<BacChannel>, ChannelActivationError>
    establish(LibreSCRS::SmartCard::IConnection& connection, LibreSCRS::SmartCard::AppletAid appletAid,
              const BacInput& input, LibreSCRS::CancelToken token) noexcept;

private:
    std::unique_ptr<detail::BacChannelImpl> pImpl;
};

} // namespace LibreSCRS::SecureChannel
