// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error                                                                                                                 \
    "LibreSCRS_internal/SecureChannel/ISecureChannel.h is internal to LibreMiddleware. Public API: <LibreSCRS/SecureChannel/...>"
#endif

#pragma once

/// @file
/// @brief @ref LibreSCRS::SecureChannel::ISecureChannel — the abstract
///        seam between @ref LibreSCRS::SmartCard::CardSession and any
///        concrete channel implementation (plain / PACE / BAC / future).

#include <LibreSCRS/CancelToken.h>
#include <LibreSCRS/SecureChannel/ChannelErrors.h>
#include <LibreSCRS/SmartCard/AppletAid.h>
#include <LibreSCRS_internal/SecureChannel/SessionKeys.h>

namespace LibreSCRS::SmartCard::Internal {
struct APDUCommand;
struct APDUResponse;
} // namespace LibreSCRS::SmartCard::Internal

namespace LibreSCRS::SecureChannel::detail {
struct ChannelStateMutator;
} // namespace LibreSCRS::SecureChannel::detail

namespace LibreSCRS::SecureChannel {

/// @brief Abstract single-applet secure-channel surface.
///
/// Concrete implementations hold protocol-specific state (no-op for
/// @ref PlainChannel, PACE-derived session keys for @c PaceChannel, BAC
/// 3DES keys for @c BacChannel). @ref LibreSCRS::SmartCard::CardSession
/// owns at most one active channel at a time and routes plugin APDUs
/// through it via an `ActiveChannelHolder` RAII guard.
///
/// All implementations are non-copyable. Copy/move semantics are
/// concrete-class concerns; the interface deliberately omits them.
///
/// @since 4.1
class LIBRESCRS_PUBLIC_API ISecureChannel
{
public:
    virtual ~ISecureChannel() = default;

    ISecureChannel(const ISecureChannel&) = delete;
    ISecureChannel& operator=(const ISecureChannel&) = delete;
    ISecureChannel(ISecureChannel&&) = delete;
    ISecureChannel& operator=(ISecureChannel&&) = delete;

    /// @brief The AID this channel is bound to.
    ///
    /// Returned by const reference: the cached AID lives on the channel
    /// body and outlives the call, so a reference-return is truly
    /// `noexcept` (no allocation, no slicing). Consumers needing an
    /// owning copy may `auto x = ch.currentApplet();` at the call site.
    [[nodiscard]] virtual const LibreSCRS::SmartCard::AppletAid& currentApplet() const noexcept = 0;

    /// @brief Current lifecycle state.
    [[nodiscard]] virtual ChannelState state() const noexcept = 0;

    /// @brief Send a command APDU through this channel, returning the
    ///        unwrapped response.
    ///
    /// Implementations may mark the channel @ref ChannelState::Failed on
    /// SW 6987/6988 or response MAC verification failure, depending on
    /// the underlying protocol. Sentinel SW values are used to communicate
    /// channel-level conditions: 0x6F00 (closed), 0x6F01 (cancelled),
    /// 0x6F02 (failed).
    ///
    /// @throws std::bad_alloc on out-of-memory while wrapping the APDU or
    ///         allocating SM scratch buffers. All other failure modes are
    ///         signalled via the returned @c APDUResponse SW bytes or via
    ///         a transition to @ref ChannelState::Failed (followed by the
    ///         sentinel 0x6F02 on the next call). The function is
    ///         deliberately NOT @c noexcept: a top-level catch-and-degrade
    ///         shim would hide allocator pressure from callers that can
    ///         meaningfully react to it.
    [[nodiscard]] virtual LibreSCRS::SmartCard::Internal::APDUResponse
    transmit(const LibreSCRS::SmartCard::Internal::APDUCommand& cmd, LibreSCRS::CancelToken token) = 0;

    /// @brief Explicit teardown. Zeroises session keys (where applicable),
    ///        transitions to @ref ChannelState::Closed. Idempotent.
    virtual void close() = 0;

    /// @brief True when this channel maintains a card-side secure-messaging
    ///        context (PACE / BAC / future EAC). Plain channels return
    ///        false.
    ///
    /// Callers MUST NOT emit plain APDUs through the underlying connection
    /// while a `carriesSm() == true` channel is in @ref ChannelState::Open
    /// — the card-side SM context will desynchronise and the next wrapped
    /// APDU will fail MAC verification. Used by
    /// @ref LibreSCRS::SmartCard::CardSession to gate teardown of a live
    /// SM tunnel and to drive cross-provider coordination predicates.
    ///
    /// @since 4.1
    [[nodiscard]] virtual bool carriesSm() const noexcept
    {
        return false;
    }

    /// @brief True when this channel's SM context survives a wrapped applet
    ///        switch. PACE: yes (BSI TR-03110 §3 — session-scoped). BAC:
    ///        no (single-applet card matrix). Plain: not applicable.
    ///
    /// Used by @ref LibreSCRS::SmartCard::CardSession::activateChannelWithSm
    /// to decide whether to re-use a live channel via wrapped SELECT or
    /// fall through to a fresh handshake.
    ///
    /// @since 4.1
    [[nodiscard]] virtual bool supportsCrossAppletReuse() const noexcept
    {
        return false;
    }

protected:
    ISecureChannel() = default;

    /// @brief LM-internal friend seam through which @ref setCurrentApplet
    ///        and @ref replaceKeys are reached from
    ///        @ref LibreSCRS::SmartCard::CardSession and the Chip-
    ///        Authentication pipeline. External consumers cannot reach
    ///        these mutators through an @ref ISecureChannel pointer.
    friend struct LibreSCRS::SecureChannel::detail::ChannelStateMutator;

    /// @brief Record @p aid as the AID of the most recent successful
    ///        wrapped @c SELECT through this channel.
    ///
    /// Pure-virtual: every concrete channel must declare an explicit
    /// override so the compiler catches future omissions. PACE-class
    /// channels update their cached AID; @ref PlainChannel and
    /// @ref BacChannel ship explicit no-op overrides documenting that the
    /// AID is constructor-bound for their card matrix.
    ///
    /// @par Visibility
    /// Protected so external callers holding an @ref ISecureChannel pointer
    /// cannot corrupt the channel's bound AID without going through a
    /// wrapped @c SELECT. Reachable from LM-internal sources via
    /// @ref LibreSCRS::SecureChannel::detail::ChannelStateMutator.
    ///
    /// @since 4.1
    virtual void setCurrentApplet(LibreSCRS::SmartCard::AppletAid aid) noexcept = 0;

    /// @brief Replace this channel's SM session keys with @p keys.
    ///
    /// Used by Chip Authentication after the protocol derives fresh
    /// CA-bound session keys (BSI TR-03110 §4.4). The card-side SM tunnel
    /// is implicitly upgraded by the protocol's final General Authenticate
    /// step; this call brings the host-side channel state into the same
    /// post-CA mode.
    ///
    /// Pure-virtual: every concrete channel must declare an explicit
    /// override. @ref PlainChannel ships a no-op override documenting that
    /// plain channels have no SM session keys to rotate.
    ///
    /// @par Visibility
    /// Protected so external callers cannot pin a channel to attacker-
    /// supplied key material. Reachable from LM-internal sources via
    /// @ref LibreSCRS::SecureChannel::detail::ChannelStateMutator.
    ///
    /// @since 4.1
    virtual void replaceKeys(SessionKeys keys) noexcept = 0;
};

} // namespace LibreSCRS::SecureChannel
