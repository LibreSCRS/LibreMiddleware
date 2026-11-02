// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware."
#endif

#pragma once

#include <LibreSCRS/Logging.h>
#include <LibreSCRS_internal/Hex.h>

#include <cstdint>
#include <span>
#include <string>
#include <string_view>

namespace LibreSCRS::Internal {

/// Emits `msg`, prefixed "librescrs.probe-quieting: ", on the Probe trace
/// channel of the logging facade, which LIBRESCRS_PROBE_TRACE switches on.
/// Safe to call from any thread; costs one load while the channel is off.
///
/// Never throws: a probe step must not fail because a log sink did.
///
/// LIBRESCRS_INTERNAL: not part of public API.
inline void probeTrace(std::string_view msg) noexcept
{
    if (!LibreSCRS::log::traceEnabled(LibreSCRS::log::TraceChannel::Probe))
        return;
    try {
        std::string line{"librescrs.probe-quieting: "};
        line += msg;
        LibreSCRS::log::trace(LibreSCRS::log::TraceChannel::Probe, line);
    } catch (...) {
        // Dropped: tracing is best-effort.
    }
}

/// Lowercase hex without separators — matches the spec output format
/// "atr=<hex>". Allocation may throw bad_alloc; callers building messages
/// already allocate via std::string, so this is consistent.
inline std::string atrToHex(std::span<const std::uint8_t> atr)
{
    return hexEncode(atr, /*lowercase=*/true);
}

} // namespace LibreSCRS::Internal
