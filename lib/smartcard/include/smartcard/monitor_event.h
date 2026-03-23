// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0 and LibreSCRS contributors

#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace smartcard {

struct MonitorEvent
{
    enum class Type { CardInserted, CardRemoved };
    Type type;
    std::string readerName;
    std::vector<uint8_t> atr; // populated on CardInserted, empty on CardRemoved
};

} // namespace smartcard
