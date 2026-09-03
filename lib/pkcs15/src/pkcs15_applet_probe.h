// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once

#include "pkcs15_types.h"

#include <apdu.h>
#include <pcsc_connection.h>

#include <cstdint>
#include <vector>

/// @file
/// @brief The cheap reachability probe against the PKCS#15 AID, and the
///        three-state answer it gives.
///
/// The card plugin and the PKCS#11 card both have to ask the same question
/// before doing anything else -- can this applet be selected in the clear, or
/// does it want PACE first -- and both wrote the same SELECT and the same
/// three-valued answer out for themselves. The two spellings differed only in
/// cosmetics, but they are one decision about one card, and a card that starts
/// answering 6982 differently must not be able to mean two things at once.

namespace pkcs15 {

/// @brief Result of a cheap reachability probe against the AID, used to decide
///        whether PACE is required.
enum class ProbeResult : std::uint8_t {
    Ok,         ///< Plain SELECT succeeded — no SM needed for this card.
    NeedsPace,  ///< Card returned 6982 — PACE must be run first.
    Unreachable ///< Other failure; treat as not-PKCS#15.
};

/// @brief SELECT the PKCS#15 AID in the clear and classify the answer.
///
/// Header-inline rather than a compiled TU because the two callers live in
/// different libraries -- a plugin and the PKCS#11 card -- with no library
/// either could link for this without acquiring the rest of the other.
[[nodiscard]] inline ProbeResult probeApplet(LibreSCRS::SmartCard::Internal::PCSCConnection& conn)
{
    std::vector<std::uint8_t> aid(kPkcs15Aid.begin(), kPkcs15Aid.end());
    const auto aidResp = conn.transmit(LibreSCRS::SmartCard::Internal::selectByAID(aid, 0x0C));
    if (aidResp.isSuccess()) {
        return ProbeResult::Ok;
    }
    if (aidResp.sw1 == 0x69 && aidResp.sw2 == 0x82) {
        return ProbeResult::NeedsPace;
    }
    return ProbeResult::Unreachable;
}

} // namespace pkcs15
