// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

#include <LibreSCRS/Logging.h>

#include <format>
#include <utility>

/// @file
/// @brief @ref LibreSCRS::log::warnf and @ref LibreSCRS::log::errorf for the
///        places nothing may be thrown from: a catch block shielding a thread
///        or a C callback, a destructor.
///
/// Unlike the `std::fprintf(stderr, ...)` such places used to call, the facade
/// formats (which allocates) and then runs the host's sink (which may throw).
/// Both are contained here; a line that cannot be delivered is dropped, since
/// the diagnostic channel is the very thing that failed.

namespace LibreSCRS::Internal {

template <class... Args>
void warnNoexcept(std::format_string<Args...> fmt, Args&&... args) noexcept
{
    try {
        LibreSCRS::log::warnf(fmt, std::forward<Args>(args)...);
    } catch (...) {
    }
}

template <class... Args>
void errorNoexcept(std::format_string<Args...> fmt, Args&&... args) noexcept
{
    try {
        LibreSCRS::log::errorf(fmt, std::forward<Args>(args)...);
    } catch (...) {
    }
}

} // namespace LibreSCRS::Internal
