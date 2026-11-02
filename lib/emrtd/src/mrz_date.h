// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

#include <charconv>
#include <cstddef>
#include <chrono>
#include <system_error>
#include <string>

namespace emrtd {

/// Format an MRZ date, `YYMMDD` as it comes off the chip, into `DD.MM.YYYY`.
///
/// ICAO 9303 allows the filler character `<` wherever a component of the date
/// of birth is unknown, so `<<0101` and `74<<27` are conformant document
/// contents and not corruption. Anything this function cannot read as six
/// digits is returned unchanged -- the same answer it already gave for an
/// input that is not six characters long. That is the presentation layer's
/// half of the rule that raw card data is never rewritten on its way through:
/// a date that cannot be formatted is shown as the document spells it.
///
/// Two-digit years are windowed by role around the current year, in UTC (a
/// document does not change its dates with the reader's time zone). A date of
/// birth is in the past: the century is the one that puts it in the hundred
/// years up to and including this year. An expiry date is near: the century is
/// the one that puts it within fifty years either side of this year.
///
/// Header-inline on purpose: the one caller is a plugin built as its own
/// shared object, and a test cannot link into that. Inline emits no exported
/// symbol, so this neither widens the ABI surface nor needs a library of its
/// own.
///
/// @param currentYear the year "now" is in; defaults to the UTC year of the
///        system clock, and is given explicitly by tests.
inline int currentUtcYear()
{
    const auto today = std::chrono::floor<std::chrono::days>(std::chrono::system_clock::now());
    return static_cast<int>(std::chrono::year_month_day{today}.year());
}

inline std::string formatMRZDate(const std::string& yymmdd, bool isExpiry = false, int currentYear = currentUtcYear())
{
    if (yymmdd.size() != 6)
        return yymmdd;

    auto twoDigits = [&](std::size_t pos, int& out) {
        // from_chars accepts a leading sign, so `-1` reads as a number and a
        // six-character input carrying one used to come back as a formatted
        // date. The MRZ character set has no sign in it; requiring both
        // characters to be digits before converting is what the contract above
        // says, rather than what a numeric conversion happens to allow.
        const char* first = yymmdd.data() + pos;
        const char* last = first + 2;
        for (const char* p = first; p != last; ++p) {
            if (*p < '0' || *p > '9') {
                return false;
            }
        }
        auto [ptr, ec] = std::from_chars(first, last, out);
        return ec == std::errc{} && ptr == last;
    };

    int y = 0;
    int m = 0;
    int d = 0;
    if (!twoDigits(0, y) || !twoDigits(2, m) || !twoDigits(4, d)) {
        return yymmdd;
    }

    // The window of a hundred years the date falls in: up to this year for
    // a birth, fifty years either side of it for an expiry.
    const int windowStart = isExpiry ? currentYear - 50 : currentYear - 99;
    int fullYear = windowStart - (windowStart % 100) + y;
    if (fullYear < windowStart)
        fullYear += 100;
    return yymmdd.substr(4, 2) + "." + yymmdd.substr(2, 2) + "." + std::to_string(fullYear);
}

} // namespace emrtd
