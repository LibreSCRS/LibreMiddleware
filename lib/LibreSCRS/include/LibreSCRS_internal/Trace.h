// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

#include <LibreSCRS/Logging.h>

#include <cstdarg>
#include <cstdio>
#include <string>

/// @file
/// @brief printf-shaped front end to @ref LibreSCRS::log::trace for the card
///        code whose diagnostics were written as `fprintf` lines.
///
/// Nothing is formatted while the channel is off. A trailing newline is
/// dropped: the facade terminates every line itself.

namespace LibreSCRS::Internal {

[[gnu::format(printf, 2, 3)]] inline void tracePrintf(LibreSCRS::log::TraceChannel channel, const char* fmt, ...)
{
    if (!LibreSCRS::log::traceEnabled(channel))
        return;
    va_list args;
    va_start(args, fmt);
    va_list copy;
    va_copy(copy, args);
    const int n = std::vsnprintf(nullptr, 0, fmt, copy);
    va_end(copy);
    std::string line;
    if (n > 0) {
        line.resize(static_cast<std::size_t>(n) + 1);
        std::vsnprintf(line.data(), line.size(), fmt, args);
        line.resize(static_cast<std::size_t>(n));
    }
    va_end(args);
    while (!line.empty() && line.back() == '\n')
        line.pop_back();
    LibreSCRS::log::trace(channel, line);
}

[[nodiscard]] inline bool signTraceOn() noexcept
{
    return LibreSCRS::log::traceEnabled(LibreSCRS::log::TraceChannel::Sign);
}

} // namespace LibreSCRS::Internal
