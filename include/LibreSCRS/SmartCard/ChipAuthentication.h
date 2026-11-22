// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

/// @file
/// @brief @ref LibreSCRS::SmartCard::ChipAuthOutcome,
///        @ref LibreSCRS::SmartCard::ChipAuthReason and
///        @ref LibreSCRS::SmartCard::ChipAuthReport — the verdict of
///        @ref LibreSCRS::SmartCard::CardSession::performChipAuthentication.

#include <cstdint>
#include <string>

namespace LibreSCRS::SmartCard {

/// @brief Verdict of an eMRTD Chip Authentication run (BSI TR-03110 §3.4,
///        ICAO Doc 9303 Part 11 §6.2).
///
/// Chip Authentication proves that the chip holds the private key whose
/// public half the document's DG14 carries — a cloned chip cannot. Only
/// @ref Failed is evidence against the chip; every other value means the
/// run gave no evidence either way, and @ref ChipAuthReport::reason says why.
///
/// @note Append-only: new enumerators are added at the end; keep a default
///       branch in a @c switch over this type.
/// @since 5.0
enum class ChipAuthOutcome : std::uint8_t {
    /// The key agreement completed and a secure-messaging exchange under the
    /// derived keys verified on both sides.
    Passed,
    /// The chip answered and did not prove that it holds the key. Over a plain
    /// channel: the protected exchange under the derived keys did not verify.
    /// Inside a PACE or BAC tunnel, additionally: the chip refused the
    /// protocol its signed DG14 advertises, or answered a step of it with a
    /// response that failed the tunnel's integrity check (a MAC that does not
    /// verify, or a card-side secure-messaging abort, 6987/6988). Inside the
    /// tunnel these count because a clone that holds the tunnel keys could
    /// otherwise avoid this verdict by answering badly on purpose. A clone
    /// signal. Never the result of a reader error (an integrity failure is an
    /// answer from the card; a reader error is @ref ChipAuthReason::ReaderError),
    /// a cancel or a local failure.
    Failed,
    /// DG14 carries no usable Chip Authentication material.
    NotSupported,
    /// No verdict; @ref ChipAuthReport::reason says why.
    NotPerformed,
};

/// @brief Why a run ended without @ref ChipAuthOutcome::Passed or
///        @ref ChipAuthOutcome::Failed, in a form a program can branch on.
///
/// @note Append-only: new enumerators are added at the end; keep a default
///       branch in a @c switch over this type.
/// @since 5.0
enum class ChipAuthReason : std::uint8_t {
    /// Nothing to explain: the outcome is @ref ChipAuthOutcome::Passed or
    /// @ref ChipAuthOutcome::Failed.
    None,
    /// The caller's cancel token fired before or during the run.
    Cancelled,
    /// The document does not offer the protocol: DG14 has no usable Chip
    /// Authentication material, or the chip refused the protocol on a plain
    /// channel (a contact interface may admit it only under secure
    /// messaging).
    NotOffered,
    /// The session could not run the protocol: the calling thread does not
    /// hold the session's @ref ActiveChannelHolder, or there is no open
    /// channel.
    NoUsableChannel,
    /// A cryptographic step on this side failed (key generation, key
    /// agreement or key derivation in the local library, or a DG14 key it
    /// cannot use); no evidence about the chip.
    LocalCryptoFailure,
    /// The reader or the connection failed during the run (the card went
    /// away, the reader was unplugged, the transport broke): the card gave no
    /// answer, so there is no evidence about the chip, and never a clone
    /// verdict.
    /// @since 5.0
    ReaderError,
};

/// @brief Result of @ref CardSession::performChipAuthentication.
///
/// Carries no key material: the session keys the run derives stay inside
/// the library.
///
/// @par Thread-safety
/// A plain value type; distinct instances may be used concurrently.
///
/// @since 5.0
struct ChipAuthReport
{
    /// @brief The verdict.
    ChipAuthOutcome outcome = ChipAuthOutcome::NotPerformed;
    /// @brief Why there is no verdict; @ref ChipAuthReason::None for
    ///        @ref ChipAuthOutcome::Passed and @ref ChipAuthOutcome::Failed.
    ChipAuthReason reason = ChipAuthReason::None;
    /// @brief Dotted OID of the Chip Authentication protocol the run chose
    ///        from DG14 (for example @c "0.4.0.127.0.7.2.2.3.2.2"); empty
    ///        when the run stopped before choosing one.
    std::string protocolOid;
    /// @brief Short English diagnostic for logs; empty when there is
    ///        nothing to explain. Not a translated user message and not for
    ///        parsing: branch on @ref outcome and @ref reason.
    std::string detail;
};

} // namespace LibreSCRS::SmartCard
