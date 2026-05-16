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
///   - The active @c ISecureChannel is bound to a specific applet AID; all
///     APDUs sent via @ref transmit go through it.
///
/// Destruction releases the transaction first (RAII), then the mutex
/// (RAII). @ref release ends both immediately rather than at scope exit.

#include <LibreSCRS/CancelToken.h>
#include <LibreSCRS/Export.h>

#include <memory>
#include <mutex>

namespace LibreSCRS::SecureChannel {
class ISecureChannel;
} // namespace LibreSCRS::SecureChannel

namespace LibreSCRS::SmartCard {

class ActiveChannelHolder;
class CardSession;
namespace Internal {
struct APDUCommand;
struct APDUResponse;
class CardTransaction;

ActiveChannelHolder makeActiveChannelHolder(CardSession* session, std::unique_lock<std::mutex> lock,
                                            std::unique_ptr<CardTransaction> tx);
} // namespace Internal

/// @brief Move-only RAII guard for an active per-applet secure channel.
///
/// Constructed only by @ref CardSession on successful activation. Holders
/// in scope guarantee that all @ref transmit calls go through the same
/// active channel; the destructor surfaces no errors.
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

    /// @brief Send a command APDU through the active channel.
    ///
    /// After @ref release has been called, returns a sentinel response
    /// (SW 0x6F00) without touching the card.
    [[nodiscard]] LibreSCRS::SmartCard::Internal::APDUResponse
    transmit(const LibreSCRS::SmartCard::Internal::APDUCommand& cmd, LibreSCRS::CancelToken token);

    /// @brief Pointer to the underlying secure channel, or @c nullptr after
    ///        @ref release.
    ///
    /// Exposed so callers can invoke channel-level mutators (e.g.
    /// @ref LibreSCRS::SecureChannel::ISecureChannel::replaceKeys after a
    /// successful Chip Authentication). The returned reference is valid
    /// only while this holder is alive and active; subsequent
    /// @ref release calls or destruction invalidate it.
    [[nodiscard]] LibreSCRS::SecureChannel::ISecureChannel* activeChannel() noexcept;

    /// @brief End the PC/SC transaction and release the session mutex
    ///        before scope exit. Subsequent @ref transmit calls return a
    ///        sentinel response.
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

    std::unique_ptr<Impl> pImpl;

    explicit ActiveChannelHolder(std::unique_ptr<Impl> impl) noexcept;

    friend ActiveChannelHolder Internal::makeActiveChannelHolder(CardSession* session,
                                                                 std::unique_lock<std::mutex> lock,
                                                                 std::unique_ptr<Internal::CardTransaction> tx);
};

} // namespace LibreSCRS::SmartCard
