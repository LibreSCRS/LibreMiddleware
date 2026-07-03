// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

/// @file
/// @brief @ref LibreSCRS::SmartCard::ActiveChannelHolder — RAII guard
///        returned by @ref CardSession::activateChannelFor and
///        @ref CardSession::activateChannelWithSm.
///
/// While the holder is alive:
///   - The session's @c sessionMutex is held (per-process serialisation).
///   - A PC/SC transaction is held on the underlying reader (cross-process
///     atomicity via @c SCardBeginTransaction).
///   - The active secure channel is bound to a specific applet AID; all
///     APDUs sent through the session-owned secure channel go through it.
///
/// Destruction releases the transaction first (RAII), then the mutex
/// (RAII). @ref release ends both immediately rather than at scope exit.

#include <LibreSCRS/Export.h>

#include <memory>
#include <mutex>

namespace LibreSCRS::SmartCard {

class ActiveChannelHolder;
class CardSession;
namespace Internal {
class CardTransaction;
// Forward-decl: defined in the internal-build-guarded header
// <LibreSCRS_internal/SmartCard/ActiveChannelHolderInternal.h>.
// Befriended on @ref ActiveChannelHolder so LM-internal sources can
// reach the holder's underlying secure channel without leaking the
// channel type into the public surface.
struct HolderChannelAccessor;

ActiveChannelHolder makeActiveChannelHolder(CardSession* session, std::unique_lock<std::mutex> lock,
                                            std::unique_ptr<CardTransaction> tx);
} // namespace Internal

/// @brief Move-only RAII guard for an active per-applet secure channel.
///
/// Constructed only by @ref CardSession on successful activation. Holders
/// in scope guarantee that all @ref transmit calls go through the same
/// active channel; the destructor surfaces no errors.
///
/// @warning The holder MUST NOT outlive its originating @ref CardSession.
/// The holder borrows a mutex and PC/SC transaction owned by the session;
/// if the @ref CardSession is destructed or move-assigned-to while a
/// holder is still alive, behaviour is undefined (use-after-free of the
/// borrowed mutex and PC/SC transaction).
///
/// @par Lifetime
/// Hosts must structure code so the @ref CardSession's lifetime strictly
/// exceeds every @ref ActiveChannelHolder it produces:
/// @code
/// auto session = CardSession::open(reader).value();
/// {
///     auto holder = session.activateChannelWithSm(aid, req, tok).value();
///     // ... operate on the session through plugin entry points ...
/// } // holder destructs here, session still alive
/// // session destructs here
/// @endcode
///
/// @par Thread-safety
/// single-threaded (see API-POLICY §8). The holder owns a live PC/SC
/// transaction and holds the originating @ref CardSession's mutex for its
/// entire lifetime; it must be constructed, used, and destroyed on one
/// thread and never shared or accessed concurrently. This is one of the rare
/// LM public types in the single-threaded category, justified by the
/// thread-affine PC/SC transaction it guards.
///
/// @since 4.1
class LIBRESCRS_PUBLIC_API ActiveChannelHolder
{
public:
    ActiveChannelHolder(const ActiveChannelHolder&) = delete;
    ActiveChannelHolder& operator=(const ActiveChannelHolder&) = delete;

    ActiveChannelHolder(ActiveChannelHolder&&) noexcept;
    ActiveChannelHolder& operator=(ActiveChannelHolder&&) noexcept;

    ~ActiveChannelHolder();

    /// @brief End the PC/SC transaction and release the session mutex
    ///        before scope exit.
    ///
    /// Does NOT close the underlying secure channel — the channel's SM
    /// keys persist for the next @ref CardSession::activateChannelFor
    /// fast-path acquisition. Use @ref CardSession::clearCachedPaceCredentials
    /// to force a credentials wipe.
    void release() noexcept;

    /// @brief True while this holder still owns its transaction + mutex.
    [[nodiscard]] bool isActive() const noexcept;

private:
    friend class CardSession;

    /// @cond internal
    /// @brief Internal factory friend. The free function in the
    ///        @c LibreSCRS::SmartCard::Internal namespace is the only
    ///        construction path; declared friend here so it can reach
    ///        the private @ref Impl and ctor.
    class Impl;
    /// @endcond

    std::unique_ptr<Impl> d;

    explicit ActiveChannelHolder(std::unique_ptr<Impl> impl) noexcept;

    friend ActiveChannelHolder Internal::makeActiveChannelHolder(CardSession* session,
                                                                 std::unique_lock<std::mutex> lock,
                                                                 std::unique_ptr<Internal::CardTransaction> tx);

    // LM-internal access to the holder's underlying secure channel goes
    // through @ref Internal::HolderChannelAccessor declared in the
    // internal-build-guarded `ActiveChannelHolderInternal.h`. No public
    // surface exposes the channel pointer.
    friend struct Internal::HolderChannelAccessor;
};

} // namespace LibreSCRS::SmartCard
