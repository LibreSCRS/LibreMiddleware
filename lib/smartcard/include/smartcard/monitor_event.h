// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0 and LibreSCRS contributors

#ifndef SMARTCARD_MONITOR_EVENT_H
#define SMARTCARD_MONITOR_EVENT_H

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

#endif // SMARTCARD_MONITOR_EVENT_H
