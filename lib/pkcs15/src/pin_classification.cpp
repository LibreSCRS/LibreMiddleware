// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <internal/PinClassification.h>

#include "pkcs15_types.h"

#include <algorithm>
#include <cctype>
#include <string>

namespace LibreSCRS::Pkcs15::Internal {

bool isUserPin(const ::pkcs15::PinInfo& pin) noexcept
try {
    if (pin.unblockingPin)
        return false;
    auto label = pin.label;
    std::transform(label.begin(), label.end(), label.begin(), [](unsigned char c) { return std::tolower(c); });
    if (label.find("puk") != std::string::npos)
        return false;
    if (label.find("can") != std::string::npos || label.find("pace") != std::string::npos)
        return false;
    // Security Officer / admin PINs are vendor-personalisation credentials.
    // Surfacing them as additional login slots causes user confusion and
    // accidental retry-counter exhaustion when the user picks the wrong
    // slot for daily sign.
    if (label == "so pin" || label.starts_with("so ") || label.find("security officer") != std::string::npos ||
        label.find("admin") != std::string::npos)
        return false;
    return true;
} catch (...) {
    // API-POLICY §5.1: the body allocates (label copy + std::transform) so
    // the noexcept contract degrades on allocator pressure. Conservative
    // classification: "couldn't classify -> not a user PIN" keeps the PIN
    // off the slot list rather than letting std::terminate run.
    return false;
}

} // namespace LibreSCRS::Pkcs15::Internal
