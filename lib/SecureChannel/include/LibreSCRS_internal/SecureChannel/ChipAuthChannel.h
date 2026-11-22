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
#include <LibreSCRS/SmartCard/TransportError.h>
#include <LibreSCRS_internal/SecureChannel/ISecureChannel.h>
#include <LibreSCRS_internal/SecureChannel/SessionKeys.h>

#include <cstdint>
#include <expected>
#include <memory>
#include <optional>
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
        ReaderError,        ///< The reader or connection failed: the chip gave no
                            ///< answer, so there is no verdict about it.
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
/// Hidden: only @ref LibreSCRS::SmartCard::CardSession::performChipAuthentication
/// creates and installs it, inside the library. Tests that construct the
/// channel compile its sources themselves (LibreSCRS_SecureChannel_ForTests).
///
/// @since 4.4
class ChipAuthChannel final : public ISecureChannel
{
public:
    ChipAuthChannel(LibreSCRS::SmartCard::IConnection& connection, LibreSCRS::SmartCard::AppletAid currentAppletAid,
                    SessionKeys keys);

    ~ChipAuthChannel() override;

    [[nodiscard]] const LibreSCRS::SmartCard::AppletAid& currentApplet() const noexcept override;
    [[nodiscard]] ChannelState state() const noexcept override;

    [[nodiscard]] std::expected<LibreSCRS::SmartCard::Internal::APDUResponse, LibreSCRS::SmartCard::TransportError>
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
    /// and is responsible for installing the returned channel on the
    /// session — leaving the old plain channel installed after a successful
    /// GA would desynchronise the card-side SM context.
    ///
    /// A reader or transport failure is @ref ChipAuthEstablishError::Kind::ReaderError
    /// (never a clone signal); @c std::bad_alloc propagates.
    /// @since 4.4
    [[nodiscard]] static std::expected<std::unique_ptr<ChipAuthChannel>, ChipAuthEstablishError>
    establish(LibreSCRS::SmartCard::IConnection& connection, ISecureChannel& current,
              const std::vector<std::uint8_t>& dg14Raw, LibreSCRS::SmartCard::AppletAid aid,
              LibreSCRS::CancelToken token);

private:
    std::unique_ptr<detail::ChipAuthChannelImpl> pImpl;
    std::string caProtocolOid;
};

/// @brief Outcome of @ref confirmSmAfterKeyChange.
/// @since 5.0
struct SmKeyProof
{
    enum class Outcome : std::uint8_t {
        Proven,      ///< The card answered under the keys and the answer unwrapped.
        NotProven,   ///< The card failed the proof: an answer that does not verify,
                     ///< or a card-side secure-messaging abort (6987/6988).
        Cancelled,   ///< The caller's token fired; nothing was proven either way.
        ReaderError, ///< Any other transport error: the reader or connection failed, or
                     ///< the channel was unusable (ChannelUnusable, SecureChannelActive,
                     ///< InvalidCommand). @ref error carries it; callers map by its kind.
    };
    Outcome outcome = Outcome::NotProven;
    /// The transport error behind @ref Outcome::ReaderError; empty otherwise.
    std::optional<LibreSCRS::SmartCard::TransportError> error;
    /// The proof SELECT also succeeded (9000), so @p aid is now selected.
    bool appletSelected = false;
};

/// @brief Prove a channel's SM keys against the card: one wrapped SELECT of
///        @p aid through @p ch.
///
/// A response the channel could unwrap — its MAC verified under the current
/// keys — proves that the card holds them, even when its status word is an
/// error such as 6A82 (no such applet): a card without the keys cannot
/// produce one. A response that does not verify, or a card-side SM abort
/// (6987/6988), proves nothing (@ref SmKeyProof::Outcome::NotProven). A cancel
/// is its own outcome, and wins over any failure seen while the token was
/// cancelled. A reader or connection error is
/// @ref SmKeyProof::Outcome::ReaderError: no answer from the chip, so never a
/// failed proof.
///
/// Shared by @ref ChipAuthChannel::establish (proof step) and by
/// @ref LibreSCRS::SmartCard::CardSession::performChipAuthentication after an
/// in-tunnel Chip Authentication rotates keys via @c replaceKeys: without this
/// exchange a PASSED verdict would rest on nothing but our own arithmetic.
/// @since 4.4
[[nodiscard]] SmKeyProof confirmSmAfterKeyChange(ISecureChannel& ch, const LibreSCRS::SmartCard::AppletAid& aid,
                                                 LibreSCRS::CancelToken token);

/// @brief The verdict input a transport error during Chip Authentication
///        stands for: @c Cancelled, an integrity failure (@c SmProofFailed,
///        the card's answer), a failure on this side (@c LocalCryptoFailure)
///        or a reader failure (@c ReaderError).
/// @since 5.0
[[nodiscard]] ChipAuthEstablishError::Kind chipAuthKindFor(const LibreSCRS::SmartCard::TransportError& error) noexcept;

/// @brief The failure a proof outcome of @ref SmKeyProof::Outcome::ReaderError
///        stands for, with the transport error's own detail.
///
/// @pre @p proof.outcome is @c ReaderError (then @c proof.error is set).
/// @since 5.0
[[nodiscard]] ChipAuthEstablishError proofReaderFailure(const SmKeyProof& proof, std::string protocol);

} // namespace LibreSCRS::SecureChannel
