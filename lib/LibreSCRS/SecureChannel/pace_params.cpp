// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <LibreSCRS/SecureChannel/PaceParams.h>

#include "pace.h"

#include <vector>

namespace LibreSCRS::SecureChannel {

std::vector<std::pair<std::string, int>> parsePaceOidsFromCardAccess(std::span<const std::uint8_t> cardAccess)
{
    std::vector<std::uint8_t> buf(cardAccess.begin(), cardAccess.end());
    return emrtd::crypto::parseCardAccessWithParams(buf);
}

} // namespace LibreSCRS::SecureChannel
