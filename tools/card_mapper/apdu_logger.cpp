// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "apdu_logger.h"
#include "output_formatter.h"

#include <format>
#include <sstream>

namespace card_mapper {

void ApduLogger::log(const smartcard::APDUCommand& cmd, const smartcard::APDUResponse& resp)
{
    entries.push_back({cmd, resp});
}

std::string ApduLogger::formatTrace() const
{
    std::ostringstream out;

    for (const auto& entry : entries) {
        auto cmdBytes = entry.command.toBytes();
        out << ">> " << formatHex(cmdBytes) << "\n";

        std::vector<uint8_t> respBytes = entry.response.data;
        respBytes.push_back(entry.response.sw1);
        respBytes.push_back(entry.response.sw2);
        out << "<< " << formatHex(respBytes) << "\n";
    }

    return out.str();
}

void ApduLogger::clear()
{
    entries.clear();
}

} // namespace card_mapper
