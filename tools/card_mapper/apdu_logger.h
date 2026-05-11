// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

#include <apdu.h>

#include <string>
#include <vector>

namespace card_mapper {

class ApduLogger
{
public:
    struct Entry
    {
        LibreSCRS::SmartCard::Internal::APDUCommand command;
        LibreSCRS::SmartCard::Internal::APDUResponse response;
    };

    void log(const LibreSCRS::SmartCard::Internal::APDUCommand& cmd, const LibreSCRS::SmartCard::Internal::APDUResponse& resp);
    std::string formatTrace() const;
    void clear();

    const std::vector<Entry>& getEntries() const
    {
        return entries;
    }

private:
    std::vector<Entry> entries;
};

} // namespace card_mapper
