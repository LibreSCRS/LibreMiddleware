// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "date_format.h"

#include <algorithm>
#include <cctype>

namespace LibreSCRS::SmartCard::Internal {

namespace {

bool isEightDigit(std::string_view raw)
{
    return raw.size() == 8 && std::all_of(raw.begin(), raw.end(), [](unsigned char c) { return std::isdigit(c) != 0; });
}

} // namespace

std::string formatDateDMY(std::string_view raw)
{
    if (isEightDigit(raw))
        return std::string{raw.substr(0, 2)} + "." + std::string{raw.substr(2, 2)} + "." +
               std::string{raw.substr(4, 4)};
    return std::string{raw};
}

std::string formatDateYMD(std::string_view raw)
{
    if (isEightDigit(raw))
        return std::string{raw.substr(6, 2)} + "." + std::string{raw.substr(4, 2)} + "." +
               std::string{raw.substr(0, 4)};
    return std::string{raw};
}

} // namespace LibreSCRS::SmartCard::Internal
