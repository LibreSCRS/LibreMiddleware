// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "LibreSCRS_internal/SmartCard/ActiveChannelHolderInternal.h is internal to LibreMiddleware."
#endif

#pragma once

#include <LibreSCRS/CancelToken.h>
#include <LibreSCRS/SmartCard/ActiveChannelHolder.h>
#include <LibreSCRS/SmartCard/SmProtocolRequest.h>

#include <pcsc_connection.h>

#include <memory>
#include <mutex>
#include <optional>

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
    /// @note Hidden visibility: an LM-internal funnel with no cross-`.so`
    ///       caller. Deliberately NOT exported (the APDU types stay off the
    ///       public ABI surface); only @ref active / @ref activatedProtocol
    ///       (and the owner-marker pair used by the in-tree re-entrancy test)
    ///       carry @ref LIBRESCRS_PUBLIC_API for cross-`.so` reach.
    [[nodiscard]] static APDUResponse transmit(CardSession& session, const APDUCommand& cmd,
                                               LibreSCRS::CancelToken token);

    /// @brief Returns a pointer to @p session's currently installed
    ///        @ref LibreSCRS::SecureChannel::ISecureChannel, or @c nullptr
    ///        if no channel is active.
    [[nodiscard]] LIBRESCRS_PUBLIC_API static LibreSCRS::SecureChannel::ISecureChannel*
    active(CardSession& session) noexcept;

    /// @brief The SM protocol that established @p session's currently-live channel
    ///        (after any BAC fallback), or nullopt if no live SM channel — read
    ///        WITHOUT taking the session mutex, so it is safe to call from a plugin
    ///        running inside a held ActiveChannelHolder (the owner thread). Mirrors
    ///        @ref active in being lock-free and owner-tolerant.
    [[nodiscard]] LIBRESCRS_PUBLIC_API static std::optional<LibreSCRS::SmartCard::SmProtocolRequest>
    activatedProtocol(CardSession& session) noexcept;

    /// @brief Records the calling thread as the owner of @p session's
    ///        active-channel lock. Invoked when a holder takes ownership of
    ///        the session mutex (see @ref makeActiveChannelHolder). The
    ///        re-entrancy guard reads this to refuse same-thread re-entry.
    LIBRESCRS_PUBLIC_API static void markOwner(CardSession& session) noexcept;

    /// @brief Clears the active-channel owner on @p session. Invoked when the
    ///        owning holder releases the lock (see
    ///        @ref ActiveChannelHolder::Impl::release).
    LIBRESCRS_PUBLIC_API static void clearOwner(CardSession& session) noexcept;
};

/// @brief Friend-only access seam reaching a @ref ActiveChannelHolder's
///        underlying secure channel from LM-internal sources.
///
/// The public @ref ActiveChannelHolder surface no longer surfaces the
/// channel pointer because @ref LibreSCRS::SecureChannel::ISecureChannel
/// is internal to LibreMiddleware: implementation headers live under
/// @c lib/<target>/include/LibreSCRS_internal/<Target>/ per API-POLICY §6.
/// LM-internal callers
/// (plugin drivers, PKCS#15 provider, Chip-Authentication pipeline) use
/// this accessor to reach the channel for state mutators routed through
/// @ref LibreSCRS::SecureChannel::detail::ChannelStateMutator.
///
/// @since 4.1
struct LIBRESCRS_PUBLIC_API HolderChannelAccessor
{
    /// @brief Pointer to @p holder's underlying secure channel, or
    ///        @c nullptr if the holder has been released or moved-from.
    ///        The pointer is borrowed; lifetime is tied to the originating
    ///        @ref CardSession.
    [[nodiscard]] static LibreSCRS::SecureChannel::ISecureChannel* channel(ActiveChannelHolder& holder) noexcept;
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
