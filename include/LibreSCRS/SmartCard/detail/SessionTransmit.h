// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "LibreSCRS/SmartCard/detail/SessionTransmit.h is internal to LibreMiddleware"
#endif

/// @file
/// @brief SM-aware APDU transmit funnel for an open @ref
///        LibreSCRS::SmartCard::CardSession.
///
/// LM-internal callers (plugins, in-tree LM consumers) use this free
/// function in place of the older "unwrap to PCSCConnection& then call
/// transmit()" pattern. The funnel snapshots the session's active
/// secure-messaging channel under the session mutex, releases the mutex,
/// and dispatches the APDU through the channel when one is live (PACE /
/// BAC); otherwise it falls through to the underlying PC/SC connection.
/// SM correctness is preserved by construction — no caller path can mix
/// plain APDUs against a live SM tunnel by accident.
///
/// @since 4.2

#include <LibreSCRS/CancelToken.h>
#include <LibreSCRS/Export.h>
#include <LibreSCRS/SmartCard/CardSession.h>

namespace LibreSCRS::SmartCard::Internal {
struct APDUCommand;
struct APDUResponse;
} // namespace LibreSCRS::SmartCard::Internal

namespace LibreSCRS::SmartCard::detail {

/// @brief SM-aware APDU transmit funnel for plugin and LM-internal use.
///
/// Routes the APDU through @p session's active secure-messaging channel
/// when one is live (state == Open); otherwise dispatches plain through
/// the underlying PC/SC connection. The active-channel slot is sampled
/// once under the session mutex into a @c shared_ptr snapshot whose
/// lifetime spans the actual transmit — a concurrent teardown on another
/// thread (e.g. via @ref CardSession::clearActiveChannel) cannot dangle
/// the channel object out from under the in-flight dispatch.
///
/// @param session The open @ref CardSession.
/// @param cmd     The APDU to send.
/// @param token   Optional cancel token forwarded to the channel /
///                connection layer.
///
/// @returns The APDU response. When the session has no underlying PC/SC
///          connection (moved-from / detached / never-attached), returns
///          @c SW=0x6F00 without attempting any I/O.
///
/// @pre Callers must serialise concurrent transmits on the same session
///      themselves — the funnel does NOT internally serialise. Violating
///      callers see a defined SM-failure path (channel state goes
///      @c Failed) rather than undefined behaviour. PC/SC
///      @c SCardBeginTransaction already serialises at the connection
///      layer for in-process callers that hold a transaction via
///      @ref LibreSCRS::SmartCard::ActiveChannelHolder.
///
/// @note Exported via @ref LIBRESCRS_PUBLIC_API for cross-`.so` plugin
///       reach (DT_NEEDED edge on libLibreSCRS_SmartCard.so). The
///       internal-only access contract is preserved by the
///       @c LIBRESCRS_INTERNAL_BUILD guard above so external SDK
///       consumers cannot include this header.
///
/// @since 4.2
[[nodiscard]] LIBRESCRS_PUBLIC_API LibreSCRS::SmartCard::Internal::APDUResponse
sessionTransmit(CardSession& session, const LibreSCRS::SmartCard::Internal::APDUCommand& cmd,
                LibreSCRS::CancelToken token = {});

} // namespace LibreSCRS::SmartCard::detail
