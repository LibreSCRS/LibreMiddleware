// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

// What the CryptoTokenKit hardware checks need from the system that the
// library does not offer: the slots' state and ATR read without a session,
// and a bare session whose length options the test sets itself.
//
// A plain C++ header over Objective-C++ (ctk_hw_probe.mm): the test cases
// include the connection header, whose <PCSC/wintypes.h> and Objective-C's
// <objc/objc.h> both define BOOL. The library's own facade is hidden inside
// the SmartCard library, and a second copy of it in this binary would
// register its Objective-C classes twice.

#include <chrono>
#include <cstdint>
#include <string>
#include <vector>

namespace LibreSCRS::Tests::CtkHw {

/// TKSmartCardSlotState, by value.
enum class SlotState : long { Missing = 0, Empty = 1, Probing = 2, MuteCard = 3, ValidCard = 4 };

/// A slot as the slot manager reports it, read without making a card object
/// and without beginning a session: no command reaches the card.
struct PassiveSlot
{
    std::string name;
    SlotState state = SlotState::Missing;
    std::vector<std::uint8_t> atr; ///< empty unless state == ValidCard
    long maxInputLength = 0;
    long maxOutputLength = 0;
};

/// Every slot the default slot manager knows. Empty when the process has no
/// slot manager (it is not signed with com.apple.security.smartcard).
[[nodiscard]] std::vector<PassiveSlot> passiveSlots();

/// One APDU through a bare session.
struct RawExchange
{
    bool replied = false;            ///< transmitRequest answered with data
    std::vector<std::uint8_t> reply; ///< data and status word
    long errorCode = 0;              ///< NSError code when !replied
    std::string errorDomain;
    double ms = 0;
};

/// The outcome of a bare session on one slot.
struct RawSession
{
    bool began = false;
    long beginErrorCode = 0;
    std::string beginErrorDomain;
    double beginMs = 0;
    int protocol = 0; ///< TKSmartCardProtocol of the session: 1 = T=0, 2 = T=1
    std::vector<RawExchange> exchanges;
};

/// Makes a card object for the card in @p slotName, sets the two length
/// options to the given values before the session, begins an exclusive
/// session (waiting up to @p grantDeadline), sends @p apdus in order and
/// ends the session. Test-only: the library decides these options itself.
[[nodiscard]] RawSession rawSession(const std::string& slotName, bool useExtendedLength, bool useCommandChaining,
                                    const std::vector<std::vector<std::uint8_t>>& apdus,
                                    std::chrono::milliseconds grantDeadline);

} // namespace LibreSCRS::Tests::CtkHw
