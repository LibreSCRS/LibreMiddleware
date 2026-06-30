// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

/// @file
/// @brief @ref LibreSCRS::Plugin::classifyPinOutcome — the canonical
///        verify/change/unblock outcome ladder shared across the
///        @ref CardPlugin implementations.
///
/// @par Rationale
/// Every plugin that drives a card-side PIN VERIFY / CHANGE arrives at the
/// same point: a success flag plus the card-reported `retriesLeft` / `blocked`
/// state, which must be mapped onto a @ref PINResultOutcome. The *source* of
/// `retriesLeft` / `blocked` differs per driver (libopensc `tries_left`
/// vs. the LM-native `PKCS15Card` result), but the classification itself is
/// identical and was previously copy-pasted. This helper is that one ladder.
///
/// @par Thread-safety
/// Pure function over its arguments; thread-safe (API-POLICY §8).
///
/// @since 4.3

#include <LibreSCRS/Plugin/PluginTypes.h>

namespace LibreSCRS::Plugin {

/// @brief Map an already-populated @ref PINResult onto its @ref PINResultOutcome.
///
/// The caller is responsible for populating @ref PINResult::retriesLeft and
/// @ref PINResult::blocked from the card before calling — only the
/// classification is shared. Precedence: success wins; otherwise a blocked
/// card reports @ref PINResultOutcome::Blocked; otherwise a known retry count
/// means the PIN was simply wrong (@ref PINResultOutcome::InvalidPin); an
/// unknown retry count on a non-blocked failure is a plugin-level error
/// (@ref PINResultOutcome::PluginError).
///
/// @param result  PIN result with @ref PINResult::retriesLeft /
///                @ref PINResult::blocked already populated.
/// @param success @c true when the card accepted the operation.
/// @return The classified outcome.
[[nodiscard]] inline PINResultOutcome classifyPinOutcome(const PINResult& result, bool success) noexcept
{
    if (success)
        return PINResultOutcome::Ok;
    if (result.blocked)
        return PINResultOutcome::Blocked;
    if (result.retriesLeft.has_value())
        return PINResultOutcome::InvalidPin;
    return PINResultOutcome::PluginError;
}

} // namespace LibreSCRS::Plugin
