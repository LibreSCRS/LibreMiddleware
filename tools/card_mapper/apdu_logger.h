// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

#include <smartcard/apdu.h>

#include <string>
#include <vector>

namespace card_mapper {

class ApduLogger
{
public:
    struct Entry
    {
        smartcard::APDUCommand command;
        smartcard::APDUResponse response;
    };

    void log(const smartcard::APDUCommand& cmd, const smartcard::APDUResponse& resp);
    std::string formatTrace() const;
    void clear();

    const std::vector<Entry>& getEntries() const { return entries; }

private:
    std::vector<Entry> entries;
};

} // namespace card_mapper
