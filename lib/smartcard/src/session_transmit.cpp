// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

/// @file
/// @brief Definition of @ref LibreSCRS::SmartCard::detail::sessionTransmit
///        — the SM-aware APDU transmit funnel exposed to LM-internal
///        callers.
///
/// Lives in a dedicated TU (not in @c CardSession.cpp) because the funnel
/// is part of the cross-`.so` plugin reach surface and benefits from a
/// stable, mechanically auditable home: a single grep on this filename
/// finds the entire dispatch path, including the snapshot-release-call
/// pattern that distinguishes a stale-channel-safe transmit from the
/// older "unwrap then transmit" pattern this funnel replaces.
///
/// @see lib/LibreSCRS/SmartCard/CardSession.cpp for the activation paths
///      that mutate the active-channel slot; this TU only reads.
/// @see lib/smartcard/src/session_transmit_internal.h for the shared
///      @ref sessionTransmitImpl primitive used by CardSession.cpp and
///      by the body below.

#include <LibreSCRS/SmartCard/CardSession.h>
#include <LibreSCRS/SmartCard/detail/SessionTransmit.h>
#include <LibreSCRS_internal/SecureChannel/ISecureChannel.h>

#include "apdu.h"
#include "session_transmit_internal.h"
#include "smartcard/pcsc_connection.h"

#include <memory>
#include <mutex>
#include <utility>

namespace LibreSCRS::SmartCard::Internal {

// Definition of the helper declared in session_transmit_internal.h.
// Lives here (not in CardSession.cpp) so the wrapper TU + CardSession.cpp
// share a single body — both translation units link against this archive
// and resolve the symbol without duplicate-definition risk.
APDUResponse sessionTransmitImpl(LibreSCRS::SecureChannel::ISecureChannel* activeChannel, PCSCConnection& conn,
                                 const APDUCommand& cmd, LibreSCRS::CancelToken token)
{
    using LibreSCRS::SecureChannel::ChannelState;
    if (activeChannel != nullptr && activeChannel->state() == ChannelState::Open) {
        return activeChannel->transmit(cmd, std::move(token));
    }
    return conn.transmit(cmd);
}

} // namespace LibreSCRS::SmartCard::Internal

namespace LibreSCRS::SmartCard::detail {

LibreSCRS::SmartCard::Internal::APDUResponse sessionTransmit(CardSession& session,
                                                             const LibreSCRS::SmartCard::Internal::APDUCommand& cmd,
                                                             LibreSCRS::CancelToken token)
{
    // Snapshot the active-channel slot + the underlying PC/SC connection
    // pointer under the session mutex, then release the mutex before
    // dispatching. The shared_ptr snapshot pins the channel object's
    // lifetime for the duration of the call so a concurrent
    // clearActiveChannel on another thread cannot dangle it. The mutex
    // is NOT held across the wire — that would serialise plugin reach
    // through one global lock and turn @ref CardSession into a
    // contention bottleneck.
    std::shared_ptr<LibreSCRS::SecureChannel::ISecureChannel> channelSnap;
    LibreSCRS::SmartCard::Internal::PCSCConnection* connPtr = nullptr;
    {
        std::lock_guard lock(session.implMutex());
        channelSnap = session.implActiveChannelSnapshot();
        connPtr = session.implOwnedConn();
        if (connPtr == nullptr) {
            // Moved-from / detached / never-attached session: surface a
            // defined "no card available" status word rather than
            // emitting UB. Mirrors the ActiveChannelAccessor null-check
            // shape elsewhere in the SmartCard surface.
            return LibreSCRS::SmartCard::Internal::APDUResponse{.data = {}, .sw1 = 0x6F, .sw2 = 0x00};
        }
    }

    try {
        return LibreSCRS::SmartCard::Internal::sessionTransmitImpl(channelSnap.get(), *connPtr, cmd, std::move(token));
    } catch (...) {
        // A bare std::runtime_error from PCSCConnection::transmit (reader
        // gone, card removed mid-transmit, detached test connection)
        // surfaces here. Mirror the null-conn guard above: return a
        // defined "no card" status word rather than propagating the
        // exception across the LM-internal funnel boundary, where
        // plugin callers expect a value-returning shape.
        return LibreSCRS::SmartCard::Internal::APDUResponse{.data = {}, .sw1 = 0x6F, .sw2 = 0x00};
    }
}

} // namespace LibreSCRS::SmartCard::detail
