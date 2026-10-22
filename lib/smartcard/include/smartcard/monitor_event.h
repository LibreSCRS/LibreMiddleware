// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0 and LibreSCRS contributors

#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace LibreSCRS::SmartCard::Internal {

struct MonitorEvent
{
    enum class Type { CardInserted, CardRemoved, Error };
    Type type;
    std::string readerName;
    std::vector<uint8_t> atr; // populated on CardInserted, empty otherwise
    std::string detail;       // why, on Error; empty otherwise
};

} // namespace LibreSCRS::SmartCard::Internal
