// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

/// @file TransportError.h
/// @brief @ref LibreSCRS::SmartCard::TransportError — why a card exchange
///        could not complete, as a value.

#include <cstdint>
#include <string>

namespace LibreSCRS::SmartCard {

/// @brief Why an exchange with the card could not complete.
///
/// Every @ref Kind names one action for the caller. The four kinds that also
/// occur when a session is opened (@ref Kind::ReaderUnavailable,
/// @ref Kind::NoCardPresent, @ref Kind::ProtocolError,
/// @ref Kind::SessionRefused) carry the same names and meaning as
/// @ref OpenError::Kind.
///
/// @par Thread-safety
/// A plain value type; distinct instances may be used concurrently.
///
/// @since 5.0
struct TransportError
{
    /// @brief The failure category. New kinds are only ever appended.
    enum class Kind : std::uint8_t {
        /// The reader is gone, the PC/SC service cannot be reached, or the
        /// platform reported a code this library does not know. This
        /// connection cannot continue: drop the session.
        ReaderUnavailable,
        /// The card was removed, or there is none in the reader.
        NoCardPresent,
        /// The card's state was lost (a reset, or on CryptoTokenKit another
        /// client took the session). The link is connected again, but a
        /// verified PIN, a selected applet and secure-messaging keys are
        /// gone: start the operation over.
        CardReset,
        /// The protocol, the reader or the card failed: T=0/T=1 mismatch, a
        /// card that does not answer, a reply from the reader too short to
        /// hold a status word.
        ProtocolError,
        /// Another application holds the card; it may pass, so try later.
        SessionRefused,
        /// The installed secure channel is closed or has failed: discard it
        /// and activate a new one.
        ChannelUnusable,
        /// The card's reply failed the secure-messaging check (MAC). The
        /// channel has failed as a result.
        IntegrityFailure,
        /// A raw transmit was attempted while a secure channel is open: use
        /// the transmit that goes through the channel.
        SecureChannelActive,
        /// The cancel token fired before the next command was sent.
        Cancelled,
        /// The bytes are not a command APDU in an accepted encoding; nothing
        /// was sent to the card.
        InvalidCommand,
    };

    /// @brief The failure category.
    Kind kind;
    /// @brief A short English diagnostic for logs; never parsed, never
    ///        holds a PIN, a key or the body of an APDU.
    std::string detail;

    /// @brief Defaulted equality over @ref kind and @ref detail.
    [[nodiscard]] bool operator==(const TransportError&) const = default;
};

} // namespace LibreSCRS::SmartCard
