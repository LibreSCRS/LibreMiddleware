// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware."
#endif

#pragma once

// A plain C++ facade over CryptoTokenKit's smart card API, the one way the
// connection reaches a card on Apple platforms.
//
// Apple PCSC.framework corrupts its in-process handle table when
// SCardReleaseContext overlaps any other PC/SC call; on macOS this library
// therefore reaches cards only through CryptoTokenKit.
//
// No PC/SC and no Objective-C type appears here: <objc/objc.h> and
// <PCSC/wintypes.h> both define BOOL. The only body is ctk_smartcard.mm; tests
// replace it with a scripted fake (test/ctk_fake.cpp) at link time.
//
// @par Queues
// CryptoTokenKit answers on queues of its own. No caller code runs on them:
// a reply handler stores its result and signals a semaphore, and a KVO handler
// refreshes a snapshot and wakes a condition variable. The facade owns two
// serial queues, org.librescrs.ctk.reply and org.librescrs.ctk.kvo, and never
// uses the main or a global queue. The slot watcher and every held CtkCard
// share the kvo queue, so a long snapshot only delays the "card left" flag --
// which is why a sensitive command never depends on that flag. No handler
// calls dispatch_sync.
//
// @par Thread-safety
// CtkCard is thread-safe per object: one mutex per card serialises exchange,
// reopen and the session state. There is no static mutex: two cards never
// wait for each other.

#include <LibreSCRS/Export.h>

#include <chrono>
#include <cstdint>
#include <expected>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace LibreSCRS::SmartCard::Internal::Ctk {

/// Why a CryptoTokenKit operation did not succeed.
enum class CtkStatus {
    Ok,
    NoManager,      ///< no slot manager: the process lacks com.apple.security.smartcard
    UnknownSlot,    ///< no slot of that name
    NoCard,         ///< the slot holds no card
    Mute,           ///< the card in the slot does not answer
    SessionRefused, ///< the exclusive session was refused, or not granted within the deadline
    SessionLost,    ///< the session ended while the card stayed in the slot
    CardGone,       ///< the card left the slot, or another card took its place
    CommError,      ///< the exchange failed for another reason
};

/// What a process without a slot manager is told, when it opens a card and
/// when it follows readers.
inline constexpr const char* kNoManagerDetail =
    "CryptoTokenKit slot manager unavailable: the process is not signed with com.apple.security.smartcard";

/// The transmission protocol of the held session.
enum class CtkProtocol { T0, T1 };

/// The state of a slot, as the slot watcher reports it.
enum class SlotState { Missing, Empty, Probing, MuteCard, ValidCard };

struct CtkFailure
{
    CtkStatus status = CtkStatus::CommError;
    std::string detail;
};

/// A borrowed Objective-C object conforming to the slot-manager selectors, as
/// an untyped pointer; an empty provider means TKSmartCardSlotManager's default
/// manager, taken lazily.
using ManagerProvider = std::function<void*()>;

/// One exclusive CryptoTokenKit session on one card, held for the life of the
/// object.
class LIBRESCRS_INTERNAL CtkCard
{
public:
    /// Begins the exclusive session on @p slotName, waiting up to
    /// @p grantDeadline for another client to release the card.
    [[nodiscard]] static std::expected<std::unique_ptr<CtkCard>, CtkFailure>
    open(const std::string& slotName, std::chrono::milliseconds grantDeadline, const ManagerProvider& manager = {});

    /// Ends the session exactly once.
    ~CtkCard();

    CtkCard(const CtkCard&) = delete;
    CtkCard& operator=(const CtkCard&) = delete;

    /// One APDU out, the full response (data and status word) back.
    [[nodiscard]] std::expected<std::vector<std::uint8_t>, CtkFailure> exchange(std::span<const std::uint8_t> command);

    /// Ends the dead session and begins one on the same slot; CardGone when the
    /// card has left the slot.
    [[nodiscard]] std::expected<void, CtkFailure> reopen(std::chrono::milliseconds grantDeadline);

    /// Whether the session is still valid.
    [[nodiscard]] bool alive() const noexcept;

    /// When !alive(): SessionLost or CardGone, from the slot state only.
    [[nodiscard]] CtkStatus lossKind() const noexcept;

    [[nodiscard]] CtkProtocol protocol() const noexcept;

    /// The slot's ATR; empty when there is none.
    [[nodiscard]] std::vector<std::uint8_t> atr() const;

    struct Impl;
    explicit CtkCard(std::unique_ptr<Impl> impl) noexcept;

private:
    std::unique_ptr<Impl> impl;
};

/// The names of the slots the manager knows; empty without a manager.
[[nodiscard]] LIBRESCRS_INTERNAL std::vector<std::string> slotNames(const ManagerProvider& manager = {});

/// One slot as the watcher last saw it.
struct SlotSnapshot
{
    std::string name;
    SlotState state = SlotState::Empty;
    std::vector<std::uint8_t> atr; ///< when state is ValidCard
    /// The state before the card probe began (Probing is reported as this);
    /// Empty when the slot has known no other state.
    SlotState settled = SlotState::Empty;
    /// Transitions between settled states seen on this slot, counted by the
    /// watcher so a card in and out between two looks still shows.
    std::uint32_t transitions = 0;
};

enum class WaitResult { Changed, TimedOut, Cancelled };

/// Follows the slots without ever opening a card session: the slot list and
/// each slot's state, refreshed on the kvo queue. Waiting happens on the
/// caller's thread.
///
/// @par Thread-safety
/// Thread-safe: any thread may snapshot or wait while another cancels.
class LIBRESCRS_INTERNAL CtkSlots
{
public:
    /// Makes no CryptoTokenKit call; the manager is taken by acquire().
    explicit CtkSlots(ManagerProvider manager = {});
    ~CtkSlots();
    CtkSlots(const CtkSlots&) = delete;
    CtkSlots& operator=(const CtkSlots&) = delete;

    /// Takes the manager (again) and starts watching; NoManager without one.
    /// Clears a pending cancel.
    [[nodiscard]] CtkStatus acquire();
    [[nodiscard]] std::vector<SlotSnapshot> snapshot() const;
    /// Bumped by every change the watcher sees.
    [[nodiscard]] std::uint64_t generation() const noexcept;
    /// Returns when generation() moves past @p seen, the timeout passes, or
    /// cancel() is called (which stays in force until the next acquire()).
    [[nodiscard]] WaitResult waitForChange(std::uint64_t seen, std::optional<std::chrono::milliseconds> timeout);
    void cancel() noexcept;

    struct Impl;

private:
    std::unique_ptr<Impl> impl;
};

} // namespace LibreSCRS::SmartCard::Internal::Ctk
