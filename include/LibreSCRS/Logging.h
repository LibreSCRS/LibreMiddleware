// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

/// @file
/// @brief Public sink-injected logging facade @ref LibreSCRS::log — the one
///        channel through which LibreMiddleware emits diagnostics that the
///        consumer did not ask for.
/// @since 5.0
///
/// @par Why this exists
/// A library that writes to its consumer's `stderr` with no way to redirect
/// it is a defect on its own terms, not a style question: the consumer owns
/// that stream, and a GUI or a daemon has somewhere better to put the line.
/// Before 5.0 LibreMiddleware had no seam at all — @ref
/// LibreSCRS::SmartCard::MonitorService said so in a comment, calling its
/// `std::fprintf(stderr, ...)` shields "a defense-in-depth fallback because
/// the SDK does not currently inject a logger across the public ABI
/// boundary". This header is that boundary.
///
/// @par Shape
/// Deliberately identical to the facade LibreAgent already ships
/// (`LibreSCRS/Agent/backend/Logging.h`) and LibreLinux and LibreDarwin
/// already consume: one severity enum, one `std::function` sink, one
/// process-wide `init`, three emitters plus their formatting variants. It is
/// not a proposal — it is the shape three of the workspace's components had
/// converged on before LibreMiddleware got one, so a downstream `grep` across
/// the host layer and the core reads the same in both.
///
/// @par Trace
/// Below the three severities sits @ref Level::Trace: wire-level and
/// step-by-step diagnostics for a reader or a card on the desk. It is off by
/// default and nothing is formatted while it is off. Each @ref TraceChannel is
/// switched on by one environment variable, read once per process:
/// `LIBRESCRS_PCSC_TRACE` (every APDU on the wire), `LIBRESCRS_SIGN_TRACE`
/// (PKCS#15 profile reading, PIN verification, signing and card verification
/// steps) and `LIBRESCRS_PROBE_TRACE` (card-recognition probing). A trace line
/// goes to the same sink as every other line. No channel ever carries what a
/// card answered, a PIN or decrypted data: an APDU response is traced as its
/// length and status word, and the data field of a PIN-bearing command is
/// replaced by its length.
///
/// @par Thread-safety
/// Every entry point is safe to call concurrently. A single process-wide
/// mutex is held across the format and the sink call, so lines never
/// interleave and @ref LibreSCRS::log::init cannot race an in-flight emit.
/// The consequence is the usual one and it is not hidden: **a sink must not
/// call back into the facade.** Re-entering @ref LibreSCRS::log::info from
/// inside a @ref LibreSCRS::log::LogSink deadlocks.
///
/// @par Ownership and global state
/// This is the one sanctioned process-global in LibreMiddleware. The
/// workspace convention is constructor dependency injection with no
/// `instance()` and no Meyers singletons; a logging facade is the documented
/// exception, because the alternative — threading a logger reference through
/// every internal type down to a `catch` block inside a poll thread — buys
/// nothing and costs the whole surface. The exception carries an obligation:
/// @ref LibreSCRS::log::resetForTest exists so one test's injected sink
/// cannot leak into the next case in the same binary.
///
/// @par Usage
/// @code
/// #include <LibreSCRS/Logging.h>
///
/// int main()
/// {
///     // Route LibreMiddleware's diagnostics wherever this application
///     // already puts its own; the default writes to std::clog.
///     LibreSCRS::log::init(
///         [](LibreSCRS::log::Level level, std::string_view line) {
///             myAppLogger().write(level, line);
///         },
///         "com.example.myapp");
///
///     LibreSCRS::SmartCard::MonitorService monitor;
///     // ... a subscriber callback that throws now reports through the sink
///     // above instead of through this process's stderr.
/// }
/// @endcode
/// A full worked example ships in `examples/sdk-consumer/`.

#include <LibreSCRS/Export.h>

#include <cstdint>
#include <format>
#include <functional>
#include <string>
#include <string_view>
#include <utility>

namespace LibreSCRS::log {

/// @brief Severity of a single emitted line.
///
/// Three severities plus @c Trace. There is no level that should abort the
/// consumer's process, so @c Fatal would be a lie. @c Info, @c Warn and
/// @c Error mirror `LibreSCRS::Agent::log::Level` value for value; @c Trace
/// is the least severe and is emitted only for a channel that was switched
/// on (see @ref traceEnabled).
enum class Level : std::uint8_t {
    Info,  ///< Normal, expected progress worth recording.
    Warn,  ///< Something degraded, the operation continues.
    Error, ///< An operation failed or a consumer callback threw.
    Trace, ///< Diagnostic detail for one @ref TraceChannel; off by default.
};

/// @brief One switchable source of @ref Level::Trace lines.
enum class TraceChannel : std::uint8_t {
    Pcsc,  ///< Every APDU on the wire; `LIBRESCRS_PCSC_TRACE`.
    Sign,  ///< PKCS#15 reading, PIN verification, signing; `LIBRESCRS_SIGN_TRACE`.
    Probe, ///< Card recognition; `LIBRESCRS_PROBE_TRACE`.
};

/// @brief The consumer-supplied destination for one already-formatted line.
///
/// @param level severity of the line.
/// @param line  the complete line, journald syslog-priority prefixed and
///              newline terminated — see @ref init for the exact layout.
///
/// The sink is called with the facade's mutex held; see the Thread-safety
/// note in the file header before doing anything inside it beyond a write.
using LogSink = std::function<void(Level level, std::string_view line)>;

/// @brief Install the process-wide sink and category. Wire it once, during
///        single-threaded startup, before any LibreMiddleware service runs.
///
/// @param sink     destination for every subsequent line. An **empty** sink
///                 restores the built-in one, which writes to `std::clog`.
/// @param category identifier prefixed to every line. Use a reverse-DNS name
///                 the consumer owns; the default is the LibreSCRS core's.
///
/// Lines are formatted as `<N>category level: message\n`, where `<N>` is the
/// syslog priority journald reads off the front of the line (`<7>` trace,
/// `<6>` info, `<4>` warning, `<3>` error) and ignores nothing else. On a desktop the
/// prefix is inert text; under journald it is what makes the severity
/// survive the transport. This is byte-for-byte the layout LibreAgent,
/// LibreLinux and LibreDarwin already emit.
///
/// Safe to call while other threads emit — the call serialises against them —
/// but calling it repeatedly at runtime means lines land in different places
/// depending on the race, which is why the contract says "once, at startup".
LIBRESCRS_PUBLIC_API void init(LogSink sink, std::string category = "rs.librescrs");

/// @brief Test-only: drop the injected sink and restore the default category.
///
/// The obligation that comes with a process-global. A test that injects a
/// sink and does not call this leaves it installed for every following case
/// in the same binary; the next case then either captures lines it never
/// asked for or, worse, writes into a lambda whose captured state is gone.
/// Call it in `TearDown()`, not at the end of the test body — a failing
/// `ASSERT_*` returns early and skips everything after it.
///
/// It also reads the trace switches from the environment again, so a test
/// can set one, call this, and see the channel on.
LIBRESCRS_PUBLIC_API void resetForTest() noexcept;

/// @brief Whether @p channel was switched on: its environment variable is set
///        to a non-empty value other than `0`. Read once per process.
[[nodiscard]] LIBRESCRS_PUBLIC_API bool traceEnabled(TraceChannel channel) noexcept;

/// @brief Emit one line at @ref Level::Trace if @p channel is on; otherwise
///        do nothing.
LIBRESCRS_PUBLIC_API void trace(TraceChannel channel, std::string_view message);

/// @brief Emit one line at @ref Level::Info.
LIBRESCRS_PUBLIC_API void info(std::string_view message);
/// @brief Emit one line at @ref Level::Warn.
LIBRESCRS_PUBLIC_API void warn(std::string_view message);
/// @brief Emit one line at @ref Level::Error.
LIBRESCRS_PUBLIC_API void error(std::string_view message);

/// @brief Format, then emit at @ref Level::Info. Compile-time checked format
///        string (`std::format_string`), so a mismatched placeholder is a
///        build error rather than a runtime throw inside a `catch` block.
template <class... Args>
void infof(std::format_string<Args...> fmt, Args&&... args)
{
    info(std::format(fmt, std::forward<Args>(args)...));
}
/// @brief Format, then emit at @ref Level::Warn. See @ref infof.
template <class... Args>
void warnf(std::format_string<Args...> fmt, Args&&... args)
{
    warn(std::format(fmt, std::forward<Args>(args)...));
}
/// @brief Format, then emit at @ref Level::Error. See @ref infof.
template <class... Args>
void errorf(std::format_string<Args...> fmt, Args&&... args)
{
    error(std::format(fmt, std::forward<Args>(args)...));
}
/// @brief Format, then emit at @ref Level::Trace. Formats nothing when
///        @p channel is off, so a disabled trace costs one load.
template <class... Args>
void tracef(TraceChannel channel, std::format_string<Args...> fmt, Args&&... args)
{
    if (traceEnabled(channel))
        trace(channel, std::format(fmt, std::forward<Args>(args)...));
}

} // namespace LibreSCRS::log
