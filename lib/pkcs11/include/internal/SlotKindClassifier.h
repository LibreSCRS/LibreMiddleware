// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

/// @file
/// @brief Heuristic PIN-label → @ref SlotKind classifier shared by every
///        PKCS#15-shaped provider.
///
/// PKCS#15 does not encode a slot-kind concept; we infer it from the PIN
/// label so the FNV-1a stable slot ID is consistent across providers when
/// both can see the same physical card. Centralising the substring set
/// keeps Auth / Sign / Enc classification identical between the in-tree
/// custom PKCS#15 provider and the OpenSC-backed provider — otherwise the
/// two providers would derive different @c CK_SLOT_ID values for the
/// same (reader, PIN) pair and break stable-handle consumers.

#include "SlotIdHash.h"

#include <string>
#include <string_view>

namespace LibreSCRS::Pkcs11::Internal {

/// @brief Classify a PIN label into a @ref SlotKind via substring match.
///
/// Substring priority (deterministic, document by ordering):
///   1. @c "sign" / @c "qscd" / @c "nonrep"  → @ref SlotKind::Sign
///   2. @c "auth"                            → @ref SlotKind::Auth
///   3. @c "enc" / @c "dec"                  → @ref SlotKind::Enc
///   4. otherwise                            → @ref SlotKind::Generic
///
/// A label containing both @c "sign" and @c "auth" (e.g. a card that
/// advertises @c "Signing/Authentication") classifies as
/// @ref SlotKind::Sign because the signing affordance is the
/// retry-counter-bearing one users care about. Documented here so future
/// changes to the priority must edit this function rather than divergent
/// per-provider copies.
///
/// @param lowercaseLabel Label already lower-cased by the caller. Passing
///                       a label with upper-case bytes silently misses
///                       matches; the helper does not allocate to
///                       lower-case its input.
/// @return The derived slot kind; @ref SlotKind::Generic when no
///         substring matches.
/// @par Thread-safety
/// Pure function over its input.
/// @since 4.1
[[nodiscard]] inline SlotKind classifyFromLabel(std::string_view lowercaseLabel) noexcept
{
    if (lowercaseLabel.find("sign") != std::string_view::npos ||
        lowercaseLabel.find("qscd") != std::string_view::npos ||
        lowercaseLabel.find("nonrep") != std::string_view::npos)
        return SlotKind::Sign;
    if (lowercaseLabel.find("auth") != std::string_view::npos)
        return SlotKind::Auth;
    if (lowercaseLabel.find("enc") != std::string_view::npos || lowercaseLabel.find("dec") != std::string_view::npos)
        return SlotKind::Enc;
    return SlotKind::Generic;
}

} // namespace LibreSCRS::Pkcs11::Internal
