// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error                                                                                                                 \
    "LibreSCRS_internal/SecureChannel/ChipAuthChannel.h is internal to LibreMiddleware. Public API: <LibreSCRS/SecureChannel/...>"
#endif

#pragma once

/// @file
/// @brief @ref LibreSCRS::SecureChannel::ChipAuthChannel — secure-messaging
///        channel keyed by a completed Chip Authentication key agreement
///        (BSI TR-03110 §4.4 / ICAO Doc 9303 Part 11).
///
/// Unlike PACE/BAC, Chip Authentication carries no explicit result: the chip
/// authenticates itself only by being able to speak SM with the keys both
/// sides derived. @ref ChipAuthChannel::establish therefore treats the first
/// wrapped exchange as part of the protocol — a channel is returned only
/// after that proof exchange succeeds, so a PASSED verdict downstream is
/// always backed by wire evidence.

#include <LibreSCRS/CancelToken.h>
#include <LibreSCRS/Export.h>
#include <LibreSCRS/SecureChannel/ChannelErrors.h>
#include <LibreSCRS_internal/SecureChannel/ISecureChannel.h>
#include <LibreSCRS_internal/SecureChannel/SessionKeys.h>

#include <cstdint>
#include <expected>
#include <memory>
#include <string>
#include <vector>

namespace LibreSCRS::SmartCard {
class IConnection;
} // namespace LibreSCRS::SmartCard

namespace LibreSCRS::SecureChannel {

namespace detail {
class ChipAuthChannelImpl;
} // namespace detail

/// @brief Why @ref ChipAuthChannel::establish could not hand back a channel.
///
/// The kinds are deliberately distinct verdict inputs: a chip that
/// REFUSES the protocol APDUs outside SM has made no genuineness claim,
/// while a chip that answered GENERAL AUTHENTICATE and then cannot speak
/// SM with the derived keys has positively failed the key agreement — the
/// clone signal this protocol exists to catch. A caller-side cancellation
/// is its own kind: an aborted attempt says nothing about the chip, so it
/// must never surface as the clone signal.
///
/// @since 4.4
struct ChipAuthEstablishError
{
    enum class Kind : std::uint8_t {
        NotSupported,       ///< DG14 unparsable or carries no CA key material.
        ProtocolRefused,    ///< MSE:Set AT / GENERAL AUTHENTICATE rejected by SW.
        LocalCryptoFailure, ///< Host-side crypto failed (keygen/ECDH/derive).
        SmProofFailed,      ///< Key agreement completed but the proof exchange
                            ///< with the derived keys failed — clone signal.
        Cancelled,          ///< The caller's CancelToken fired before or during
                            ///< the attempt — no genuineness verdict was earned.
    };
    Kind kind = Kind::LocalCryptoFailure;
    /// CA protocol OID when it was selected before the failure; empty otherwise.
    std::string protocol;
    /// Human-readable detail for the security-check row.
    std::string detail;
};

/// @brief CA-derived SM channel. Owns its session keys; zeroises them on
///        @ref close and destruction.
///
/// Session-scoped exactly like @ref PaceChannel: SM binds at the card OS
/// layer, applet switches ride wrapped `SELECT` through the live tunnel
/// (BSI TR-03110 §3).
///
/// @since 4.4
class LIBRESCRS_PUBLIC_API ChipAuthChannel final : public ISecureChannel
{
public:
    ChipAuthChannel(LibreSCRS::SmartCard::IConnection& connection, LibreSCRS::SmartCard::AppletAid currentAppletAid,
                    SessionKeys keys);

    ~ChipAuthChannel() override;

    [[nodiscard]] const LibreSCRS::SmartCard::AppletAid& currentApplet() const noexcept override;
    [[nodiscard]] ChannelState state() const noexcept override;

    [[nodiscard]] LibreSCRS::SmartCard::Internal::APDUResponse
    transmit(const LibreSCRS::SmartCard::Internal::APDUCommand& cmd, LibreSCRS::CancelToken token) override;

    void close() override;

    /// @brief CA-derived channels maintain a card-side SM tunnel.
    /// @return Always @c true.
    /// @since 4.4
    [[nodiscard]] bool carriesSm() const noexcept override
    {
        return true;
    }

    /// @brief CA SM is session-scoped at the card OS layer (BSI TR-03110
    ///        §3 treats SM uniformly), so a wrapped SELECT routes another
    ///        applet through the existing tunnel without a fresh handshake.
    ///        The annex reader (cross-DF) and the PKCS#15 provider
    ///        (cross-applet) both depend on this.
    /// @return Always @c true.
    /// @since 4.4
    [[nodiscard]] bool supportsCrossAppletReuse() const noexcept override
    {
        return true;
    }

    /// @brief CA protocol OID this channel was established with; empty for
    ///        a directly constructed channel. Consumed by the eMRTD plugin
    ///        for the chip-authentication security-check detail.
    /// @since 4.4
    [[nodiscard]] const std::string& protocolOid() const noexcept
    {
        return caProtocolOid;
    }

protected:
    /// @brief Update the channel's @ref currentApplet after a successful
    ///        wrapped @c SELECT. Reached through
    ///        @ref LibreSCRS::SecureChannel::detail::ChannelStateMutator.
    /// @since 4.4
    void setCurrentApplet(LibreSCRS::SmartCard::AppletAid aid) noexcept override;

    /// @brief Replace the channel's SM session keys with @p keys (a further
    ///        CA run over this channel rotates into fresh keys). Symmetric
    ///        with @ref PaceChannel::replaceKeys.
    /// @since 4.4
    void replaceKeys(SessionKeys keys) noexcept override;

public:
    /// @brief Run Chip Authentication through @p current and return a
    ///        proven SM channel over @p connection keyed by the derived
    ///        session keys.
    ///
    /// Flow: `performChipAuth` (MSE:Set AT + GENERAL AUTHENTICATE + ECDH +
    /// KDF) over @p current — plain on a contact read, wrapped when
    /// @p current already carries SM — then a PROOF exchange (wrapped
    /// SELECT of @p aid) through the freshly keyed channel. Only a channel
    /// that survived the proof is returned; its @ref currentApplet is
    /// already @p aid and @ref protocolOid carries the CA OID.
    ///
    /// The caller must hold the PC/SC transaction for the whole sequence
    /// (the eMRTD read path holds it through its ActiveChannelHolder) and
    /// is responsible for installing the returned channel on the session —
    /// leaving the old plain channel installed after a successful GA would
    /// desynchronise the card-side SM context.
    ///
    /// @note Carries default visibility (not `LIBRESCRS_INTERNAL`): the
    ///       eMRTD plugin .so is the in-tree caller across the shared-
    ///       library boundary. External consumers cannot construct an
    ///       `IConnection`, so the exported symbol remains effectively
    ///       private to the project.
    /// @since 4.4
    [[nodiscard]] LIBRESCRS_PUBLIC_API static std::expected<std::unique_ptr<ChipAuthChannel>, ChipAuthEstablishError>
    establish(LibreSCRS::SmartCard::IConnection& connection, ISecureChannel& current,
              const std::vector<std::uint8_t>& dg14Raw, LibreSCRS::SmartCard::AppletAid aid,
              LibreSCRS::CancelToken token) noexcept;

private:
    std::unique_ptr<detail::ChipAuthChannelImpl> pImpl;
    std::string caProtocolOid;
};

/// @brief Prove a channel's SM keys against the card: one wrapped SELECT of
///        @p aid through @p ch. True iff the exchange round-tripped with a
///        success SW — i.e. the card accepted our MAC and we verified its.
///
/// Shared by @ref ChipAuthChannel::establish (proof step) and by the eMRTD
/// plugin after an in-tunnel Chip Authentication rotates keys via
/// @c replaceKeys: without this exchange a PASSED verdict would rest on
/// nothing but our own arithmetic.
///
/// @note `LIBRESCRS_PUBLIC_API` deliberately — called from the eMRTD
///       plugin .so across the shared-library boundary.
/// @since 4.4
[[nodiscard]] LIBRESCRS_PUBLIC_API bool confirmSmAfterKeyChange(ISecureChannel& ch,
                                                                const LibreSCRS::SmartCard::AppletAid& aid,
                                                                LibreSCRS::CancelToken token) noexcept;

} // namespace LibreSCRS::SecureChannel
