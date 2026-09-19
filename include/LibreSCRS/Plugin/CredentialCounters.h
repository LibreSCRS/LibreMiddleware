// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <optional>

namespace LibreSCRS::Plugin {

/// Per-credential counters read from a card. Every field is absent unless
/// the card exposed it. `uses*` is the credential's own usage budget
/// (e.g. a PUK good for N unblocks); `unblocksLeft` is the remaining
/// resets of the retry counter.
///
/// @par Thread-safety
/// Plain value aggregate; thread-compatible per API-POLICY §8.
///
/// @par Example
/// @code
/// CredentialCounters counters = plugin->readCounters(session);
/// if (counters.retriesLeft && *counters.retriesLeft <= 1) {
///     // Warn before the next failed attempt blocks the PIN.
/// }
/// @endcode
/// @since 5.0
struct CredentialCounters
{
    std::optional<int> retriesLeft;
    std::optional<int> retriesMax;
    std::optional<int> usesLeft;
    std::optional<int> usesMax;
    std::optional<int> unblocksLeft;
};

} // namespace LibreSCRS::Plugin
