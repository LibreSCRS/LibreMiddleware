// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware."
#endif

#include <LibreSCRS/CancelToken.h>
#include <LibreSCRS/SmartCard/ActiveChannelHolder.h>

#include "smartcard/pcsc_connection.h"

#include <memory>
#include <mutex>

namespace LibreSCRS::SecureChannel {
class ISecureChannel;
} // namespace LibreSCRS::SecureChannel

namespace LibreSCRS::SmartCard {

class CardSession;

namespace Internal {

/// @brief Cross-TU bridge: CardSession defines this to forward through its
///        active channel without exposing channel internals to the holder.
APDUResponse transmitThroughActiveChannel(CardSession& session, const APDUCommand& cmd, LibreSCRS::CancelToken token);

/// @brief Cross-TU bridge: returns a pointer to the session's currently
///        installed @ref LibreSCRS::SecureChannel::ISecureChannel, or
///        @c nullptr if no channel is active. Used by ActiveChannelHolder
///        to surface the channel through @ref ActiveChannelHolder::activeChannel
///        so that callers can invoke channel-level mutators (notably
///        @ref ISecureChannel::replaceKeys after Chip Authentication).
LibreSCRS::SecureChannel::ISecureChannel* activeChannelOf(CardSession& session) noexcept;

/// @brief Friend-only factory invoked by CardSession to construct a holder
///        with the appropriate lock + transaction it has already acquired.
///        The transaction is taken by unique_ptr so the holder's TU does
///        not need the complete CardTransaction definition for its
///        out-of-line ctor — concrete unique_ptr<CardTransaction>
///        instantiation is confined to this internal-build TU.
ActiveChannelHolder makeActiveChannelHolder(CardSession* session, std::unique_lock<std::mutex> lock,
                                            std::unique_ptr<CardTransaction> tx);

} // namespace Internal

} // namespace LibreSCRS::SmartCard
