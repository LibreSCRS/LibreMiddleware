// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

/// @file
/// @brief Error taxonomy and lifecycle state for @ref
///        LibreSCRS::SecureChannel::ISecureChannel and its callers.

#include <cstdint>

namespace LibreSCRS::SecureChannel {

/// @brief Lifecycle state of a secure channel.
///
/// @since 4.1
enum class ChannelState : std::uint8_t {
    /// @brief Ready to wrap and unwrap APDUs.
    Open,
    /// @brief Explicitly closed by the owner. Subsequent transmits fail.
    Closed,
    /// @brief Invalidated by SW 6987/6988 or MAC verification failure.
    ///        Caller should drop this channel and re-activate.
    Failed,
};

/// @brief Error categories surfaced when activating a channel through
///        @ref LibreSCRS::SmartCard::CardSession.
///
/// @since 4.1
enum class ChannelActivationError : std::uint8_t {
    /// @brief Sentinel: no error. Reserved for callers that need a default-
    ///        constructed value; never returned by an activation factory.
    None,
    /// @brief Applet absent or SELECT rejected by the card. Terminal.
    SelectAppletFailed,
    /// @brief Wrong CAN/MRZ/PIN/PUK. Retry-eligible inside activation.
    ///        Protocol-neutral: surfaced by both PACE and BAC activation.
    WrongSecret,
    /// @brief PIN-as-PACE counter exhausted. Terminal (reserved for 4.x).
    PacePinBlocked,
    /// @brief Cryptographic or protocol failure during handshake. Terminal.
    ///        Protocol-neutral: surfaced by both PACE and BAC activation.
    ProtocolFailure,
    /// @brief Card does not support the requested PACE mode. Terminal.
    PaceUnsupported,
    /// @brief Credential provider returned a user-cancel. Terminal.
    UserCancelled,
    /// @brief @ref LibreSCRS::CancelToken tripped. Terminal.
    Cancelled,
    /// @brief Card removal observed mid-operation. Terminal.
    CardRemoved,
    /// @brief PC/SC-level error. Terminal (usually).
    ReaderError,
    /// @brief Cache miss and no credential provider configured. Terminal.
    ///        PKCS#11 path maps to `CKR_USER_NOT_LOGGED_IN`.
    CredentialsRequired,
    /// @brief Caller-visible bug. Terminal.
    Internal,
    /// @brief The calling thread already holds this session's ActiveChannelHolder.
    ///        Re-entering CardSession on the same thread would self-deadlock on
    ///        the non-recursive session mutex. Release the holder first.
    ///        Terminal; indicates a caller bug.
    /// @since 4.x
    ReentrantAccess,
};

/// @brief Error categories surfaced by @ref ISecureChannel::transmit (and
///        by the holder/transmit wrapper layered above it).
///
/// @since 4.1
enum class ChannelOperationError : std::uint8_t {
    /// @brief Sentinel: no error. Reserved for callers that need a default-
    ///        constructed value; never returned by an operation wrapper.
    None,
    /// @brief Channel transitioned to @ref ChannelState::Failed. Caller
    ///        should drop and re-activate.
    ChannelFailed,
    /// @brief Channel was closed before this call. Caller should re-activate.
    ChannelClosed,
    /// @brief Card removal observed mid-operation. Terminal.
    CardRemoved,
    /// @brief @ref LibreSCRS::CancelToken tripped. Terminal.
    Cancelled,
    /// @brief PC/SC-level error. Terminal (usually).
    ReaderError,
    /// @brief Card returned SW 6987 or 6988: SM data missing or incorrect.
    Sw6987Or6988,
    /// @brief Response MAC failed verification (PACE/BAC channels).
    MacVerificationFailed,
    /// @brief Caller-visible bug. Terminal.
    Internal,
};

} // namespace LibreSCRS::SecureChannel
