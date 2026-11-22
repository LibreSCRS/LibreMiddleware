// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "LibreSCRS_internal/SmartCard/ActivationError.h is internal to LibreMiddleware."
#endif

#pragma once

/// @file
/// @brief The one mapping from a TransportError to the error channel
///        activation reports.

#include <LibreSCRS/SecureChannel/ChannelErrors.h>
#include <LibreSCRS/SmartCard/TransportError.h>

namespace LibreSCRS::SmartCard::Internal {

/// Where in activation the exchange failed; it decides what a channel that
/// cannot carry the command means.
enum class ActivationStep {
    /// The SELECT of the target applet: a channel that cannot carry it is a
    /// failed SELECT.
    SelectApplet,
    /// A handshake or a read: the channel being unusable is an anomaly of the
    /// reader or the tunnel, not of the applet.
    Other,
    /// The cross-check that no PACE-less verdict was forged, read through the
    /// tunnel just installed: a tunnel that cannot carry it is the anomaly a
    /// forger causes.
    DowngradeCheck,
};

[[nodiscard]] constexpr LibreSCRS::SecureChannel::ChannelActivationError
activationErrorFor(const TransportError& error, ActivationStep step) noexcept
{
    using Kind = TransportError::Kind;
    using Out = LibreSCRS::SecureChannel::ChannelActivationError;
    switch (error.kind) {
    case Kind::Cancelled:
        return Out::Cancelled;
    case Kind::ChannelUnusable:
    case Kind::IntegrityFailure:
        if (step == ActivationStep::SelectApplet)
            return Out::SelectAppletFailed;
        return step == ActivationStep::DowngradeCheck ? Out::PaceDowngradeDetected : Out::ReaderError;
    case Kind::InvalidCommand:
    case Kind::SecureChannelActive:
        return Out::Internal;
    case Kind::ReaderUnavailable:
    case Kind::NoCardPresent:
    case Kind::CardReset:
    case Kind::ProtocolError:
    case Kind::SessionRefused:
        return Out::ReaderError;
    }
    return Out::ReaderError; // not reached: every Kind is listed above
}

} // namespace LibreSCRS::SmartCard::Internal
