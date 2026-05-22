// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

/// @file
/// @brief LM-internal SM-aware transmit helper shared between
///        @c CardSession.cpp and the @c session_transmit.cpp wrapper TU.
///
/// The body chooses between dispatching through a live secure-messaging
/// channel and falling through to the underlying PC/SC connection. The
/// caller (CardSession's activation paths or the public
/// @ref LibreSCRS::SmartCard::detail::sessionTransmit funnel) is
/// responsible for sampling the active-channel slot under whatever
/// synchronisation the call site requires.

#include <LibreSCRS/CancelToken.h>

namespace LibreSCRS::SecureChannel {
class ISecureChannel;
} // namespace LibreSCRS::SecureChannel

namespace LibreSCRS::SmartCard::Internal {

class PCSCConnection;
struct APDUCommand;
struct APDUResponse;

/// @brief SM-aware transmit primitive.
///
/// When @p activeChannel is non-null and reports
/// @c ChannelState::Open the APDU is dispatched through the channel
/// (which wraps + unwraps under the current SM tunnel). Otherwise the
/// APDU is sent plain through @p conn.
///
/// @param activeChannel May be null. When non-null the caller must keep
///        the channel object alive for the duration of the call —
///        @ref sessionTransmit in the public funnel achieves this by
///        snapshotting the session's shared_ptr.
/// @param conn          Underlying PC/SC connection — must be valid.
/// @param cmd           APDU to send.
/// @param token         Cancel token forwarded to the channel /
///                      connection layer.
/// @returns The APDU response.
APDUResponse sessionTransmitImpl(LibreSCRS::SecureChannel::ISecureChannel* activeChannel, PCSCConnection& conn,
                                 const APDUCommand& cmd, LibreSCRS::CancelToken token);

} // namespace LibreSCRS::SmartCard::Internal
