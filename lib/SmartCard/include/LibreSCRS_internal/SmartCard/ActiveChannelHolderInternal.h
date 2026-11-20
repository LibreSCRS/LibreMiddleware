// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "LibreSCRS_internal/SmartCard/ActiveChannelHolderInternal.h is internal to LibreMiddleware."
#endif

#pragma once

#include <LibreSCRS/CancelToken.h>
#include <LibreSCRS/SmartCard/ActiveChannelHolder.h>
#include <LibreSCRS/SmartCard/SmProtocolRequest.h>

#include <apdu.h>
#include <smartcard/card_connection.h>

#include <memory>
#include <mutex>
#include <optional>

namespace LibreSCRS::SecureChannel {
class ISecureChannel;
} // namespace LibreSCRS::SecureChannel

namespace LibreSCRS::SmartCard {

class CardSession;

namespace Internal {

/// @brief Friend-only access seam through which @ref ActiveChannelHolder
///        records which thread holds a @ref CardSession's lock.
///
/// Forward-declared in the public @ref CardSession header so the class can
/// befriend it. Nothing here is exported: only the library's own
/// translation units call it.
///
/// @since 4.1
struct ActiveChannelAccessor
{
    /// @brief Records the calling thread as the owner of @p session's
    ///        active-channel lock. Invoked when a holder takes ownership of
    ///        the session mutex (see @ref makeActiveChannelHolder). The
    ///        re-entrancy guard reads this to refuse same-thread re-entry.
    static void markOwner(CardSession& session) noexcept;

    /// @brief Clears the active-channel owner on @p session. Invoked when the
    ///        owning holder releases the lock (see
    ///        @ref ActiveChannelHolder::Impl::release).
    static void clearOwner(CardSession& session) noexcept;
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
