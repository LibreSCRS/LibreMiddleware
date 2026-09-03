// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <LibreSCRS/Logging.h>

#include <format>
#include <iostream>
#include <mutex>
#include <string>
#include <string_view>
#include <utility>

namespace LibreSCRS::log {
namespace {

// Serialises emits so a MonitorService poll thread and the caller's thread
// cannot interleave bytes inside one line, and guards g_sink/g_category so
// init() cannot race an in-flight emit.
//
// Not a singleton in the sense the workspace convention bans: a TU-private
// mutex with no accessor and no domain state, doing exactly the job a
// per-object std::mutex would if this facade had an object to hang off. The
// domain state it guards (g_sink, g_category) is the sanctioned exception,
// documented on the public header.
std::mutex& logMutex()
{
    static std::mutex m;
    return m;
}

// journald reads a leading <N> syslog priority off the line and strips it.
// Anywhere else it is inert text. Kept identical to the LibreAgent facade so
// one grep reads the host layer and the core the same way.
const char* priorityPrefix(Level level)
{
    switch (level) {
    case Level::Info:
        return "<6>";
    case Level::Warn:
        return "<4>";
    case Level::Error:
        return "<3>";
    }
    return "<6>";
}

const char* levelText(Level level)
{
    switch (level) {
    case Level::Info:
        return "info";
    case Level::Warn:
        return "warning";
    case Level::Error:
        return "error";
    }
    return "info";
}

// The built-in sink. std::clog, not std::cerr: unit-buffered rather than
// unbuffered, which is what a diagnostic channel wants, and it is the stream
// LibreMiddleware already used for its one categorised line.
void defaultSink(std::string_view line)
{
    std::clog << line << std::flush;
}

// Empty => defaultSink. Guarded by logMutex().
LogSink g_sink;
// Guarded by logMutex().
std::string g_category = "rs.librescrs";

void emit(Level level, std::string_view message)
{
    // The lock spans the g_category/g_sink read, the format and the sink call.
    // That is what keeps a line atomic and what makes init() safe against a
    // concurrent emit; the price is that a sink must not re-enter the facade,
    // which the public header states outright rather than leaving to be
    // discovered by deadlock.
    std::scoped_lock lock(logMutex());
    const auto line = std::format("{}{} {}: {}\n", priorityPrefix(level), g_category, levelText(level), message);
    if (g_sink) {
        g_sink(level, line);
    } else {
        defaultSink(line);
    }
}

} // namespace

void init(LogSink sink, std::string category)
{
    std::scoped_lock lock(logMutex());
    g_sink = std::move(sink);
    g_category = std::move(category);
}

void resetForTest() noexcept
{
    std::scoped_lock lock(logMutex());
    g_sink = nullptr;
    g_category = "rs.librescrs";
}

void info(std::string_view message)
{
    emit(Level::Info, message);
}

void warn(std::string_view message)
{
    emit(Level::Warn, message);
}

void error(std::string_view message)
{
    emit(Level::Error, message);
}

} // namespace LibreSCRS::log
