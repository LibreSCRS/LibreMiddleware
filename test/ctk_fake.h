// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

// A scripted CryptoTokenKit: the test-side body of ctk_smartcard.h. Slots,
// cards and sessions live in process memory; a test sets them up, plays the
// card through a responder, and reads back what the connection asked of it.
// Thread-safe: a test may drive two readers from two threads.

#include "ctk_smartcard.h"

#include <chrono>
#include <cstdint>
#include <expected>
#include <functional>
#include <span>
#include <string>
#include <vector>

namespace LibreSCRS::SmartCard::Internal::Ctk::Fake {

struct Slot
{
    SlotState state = SlotState::ValidCard;
    std::vector<std::uint8_t> atr{0x3B, 0x00};
    CtkProtocol protocol = CtkProtocol::T1;
    /// Plays the card; empty answers {0x90, 0x00}. Runs outside every fake lock.
    std::function<std::expected<std::vector<std::uint8_t>, CtkStatus>(std::span<const std::uint8_t>)> responder;
    /// Any status but Ok refuses every open and reopen with it.
    CtkStatus refuseOpenWith = CtkStatus::Ok;
};

struct Calls
{
    int opens = 0; ///< open and reopen attempts, refused ones included
    int ends = 0;
    int exchanges = 0;
    int liveSessions = 0;
    int maxLiveSessions = 0;
    std::chrono::milliseconds lastDeadline{0};
    /// Every command the card received, in order. A command sent on a session
    /// lost with loseSession() is received (the reply is what is lost); one
    /// sent after the card left or was swapped is not.
    std::vector<std::vector<std::uint8_t>> received;
    /// "open" and "end" in the order they happened.
    std::vector<std::string> order;
};

void reset();
void setManagerPresent(bool present);
/// The slot of that name, created on first use.
Slot& slot(const std::string& name);
void removeSlot(const std::string& name);
/// The session on the slot ends; the card stays.
void loseSession(const std::string& name);
/// The card leaves the slot.
void removeCard(const std::string& name);
/// Another card takes the slot's place: the held session ends with it.
void swapCard(const std::string& name, std::vector<std::uint8_t> atr);
[[nodiscard]] Calls calls(const std::string& name);

/// Changes a slot's state the way CryptoTokenKit would, so a watching
/// CtkSlots sees it: Probing keeps the settled state, any other state that
/// differs from it is one transition.
void setSlotState(const std::string& name, SlotState state);
/// How often a CtkSlots took the manager, and how often it made a card.
[[nodiscard]] int slotsAcquires();
[[nodiscard]] int slotsManagerLookups();

} // namespace LibreSCRS::SmartCard::Internal::Ctk::Fake
