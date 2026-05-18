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

/// @brief Friend-only access seam to a @ref CardSession's active channel.
///
/// All cross-TU bridge entry points that need to reach the session's
/// `Impl::activeChannel` slot (the APDU forwarding path and the live-
/// channel pointer surfaced through @ref ActiveChannelHolder::activeChannel)
/// live here as static methods. The struct is forward-declared in the
/// public @ref CardSession header so the @c CardSession class can befriend
/// it without leaking @ref APDUCommand / @ref APDUResponse or the helper
/// symbol names into the public SDK include tree.
///
/// @since 4.1
struct ActiveChannelAccessor
{
    /// @brief Forwards @p cmd through @p session's currently installed
    ///        secure channel and returns the unwrapped response. Returns
    ///        sentinel SW 0x6F00 if no channel is installed.
    [[nodiscard]] static APDUResponse transmit(CardSession& session, const APDUCommand& cmd,
                                               LibreSCRS::CancelToken token);

    /// @brief Returns a pointer to @p session's currently installed
    ///        @ref LibreSCRS::SecureChannel::ISecureChannel, or @c nullptr
    ///        if no channel is active. Used by @ref ActiveChannelHolder to
    ///        expose the channel through @ref ActiveChannelHolder::activeChannel.
    [[nodiscard]] static LibreSCRS::SecureChannel::ISecureChannel* active(CardSession& session) noexcept;
};

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
