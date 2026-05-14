// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <mutex>
#include <span>
#include <string>
#include <string_view>

namespace LibreSCRS::Internal {

namespace probe_trace_detail {

inline std::atomic<bool>& enabledFlag() noexcept
{
    static std::atomic<bool> flag{false};
    return flag;
}

inline void initOnce() noexcept
{
    static std::once_flag once;
    std::call_once(once, [] {
        const char* v = std::getenv("LIBRESCRS_PROBE_TRACE");
        enabledFlag().store(v != nullptr && std::string_view{v} == "1", std::memory_order_release);
    });
}

} // namespace probe_trace_detail

/// Writes `msg` to stderr with prefix "librescrs.probe-quieting: " IF
/// the env var LIBRESCRS_PROBE_TRACE=1 was set at process start.
/// One-shot per-DSO init via std::call_once; safe to call from any thread.
///
/// Header-only so each translation unit / DSO sees a private vague-linkage
/// definition. State is per-DSO (each .so reads the env var once on first
/// invocation), which is correct: every backend observes the same env var.
///
/// **Set LIBRESCRS_PROBE_TRACE before process launch.** Mutating the env
/// var after a DSO has been loaded is unsupported: that DSO's enabled flag
/// is frozen at first call. A second DSO loaded later will read whatever
/// value is current in its address space, so trace output across DSOs can
/// diverge.
///
/// LIBRESCRS_INTERNAL: not part of public API.
inline void probeTrace(std::string_view msg) noexcept
{
    probe_trace_detail::initOnce();
    if (!probe_trace_detail::enabledFlag().load(std::memory_order_acquire))
        return;

    using namespace std::chrono;
    const auto now = system_clock::now();
    const auto ms = static_cast<long long>(duration_cast<milliseconds>(now.time_since_epoch()).count() % 1000);
    const std::time_t t = system_clock::to_time_t(now);
    std::tm tmbuf{};
    gmtime_r(&t, &tmbuf);

    std::fprintf(stderr, "[%04d-%02d-%02dT%02d:%02d:%02d.%03lldZ] librescrs.probe-quieting: %.*s\n",
                 tmbuf.tm_year + 1900, tmbuf.tm_mon + 1, tmbuf.tm_mday, tmbuf.tm_hour, tmbuf.tm_min, tmbuf.tm_sec, ms,
                 static_cast<int>(msg.size()), msg.data());
}

/// Lowercase hex without separators — matches the spec output format
/// "atr=<hex>". Allocation may throw bad_alloc; callers building messages
/// already allocate via std::string, so this is consistent.
inline std::string atrToHex(std::span<const std::uint8_t> atr)
{
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.resize(atr.size() * 2);
    for (std::size_t i = 0; i < atr.size(); ++i) {
        out[2 * i] = kHex[(atr[i] >> 4) & 0x0F];
        out[2 * i + 1] = kHex[atr[i] & 0x0F];
    }
    return out;
}

} // namespace LibreSCRS::Internal
