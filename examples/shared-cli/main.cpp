// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

/// @file
/// @brief Minimal CLI demonstrating LibreSCRS consumption via the SHARED
///        libLibreSCRS_* artefacts.
///
/// Collects PC/SC readers from @ref LibreSCRS::SmartCard::MonitorService events,
/// opens a @ref LibreSCRS::SmartCard::CardSession against the first reader
/// that has a card present, and prints the reader name + ATR hex.
///
/// Exercises the SHARED-library code path:
///   * Public surface only: every include path is under @c <LibreSCRS/...>.
///   * Linked against @c LibreSCRS::SmartCard, the one target whose headers
///     it includes.
///   * No reader required to BUILD or LINK; only required to demonstrate
///     a successful @ref CardSession::open.

#include <LibreSCRS/SmartCard/CardSession.h>
#include <LibreSCRS/SmartCard/MonitorService.h>

#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdio>
#include <iostream>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace {

// MIRROR-OF: LibreMiddleware/lib/LibreSCRS/include/LibreSCRS_internal/Hex.h - an example stands for
// what a consumer can write against the published SDK alone; reaching into an internal header here
// would advertise one nobody outside this repository has.
std::string toHex(const std::vector<std::uint8_t>& bytes)
{
    std::string out;
    out.reserve(bytes.size() * 2);
    static constexpr char kHex[] = "0123456789ABCDEF";
    for (auto b : bytes) {
        out.push_back(kHex[b >> 4]);
        out.push_back(kHex[b & 0x0F]);
    }
    return out;
}

// The monitor reports every reader already attached as a ReaderAdded event
// soon after the first subscribe, and a PC/SC subsystem that refuses this
// process as one Error event. Collect events until they settle; none at all
// within the window means no reader is attached. std::nullopt: refused.
std::optional<std::vector<std::string>> attachedReaders(LibreSCRS::SmartCard::MonitorService& monitor)
{
    using LibreSCRS::SmartCard::MonitorEvent;
    std::mutex mtx;
    std::condition_variable cv;
    std::vector<std::string> names;
    bool refused = false;
    std::size_t seen = 0;
    const auto id = monitor.subscribe([&](const MonitorEvent& event) {
        std::lock_guard lock(mtx);
        if (event.kind == MonitorEvent::Kind::ReaderAdded)
            names.push_back(event.readerName);
        else if (event.kind == MonitorEvent::Kind::Error)
            refused = true;
        else
            return;
        ++seen;
        cv.notify_all();
    });
    {
        std::unique_lock lock(mtx);
        cv.wait_for(lock, std::chrono::seconds(2), [&] { return seen > 0; });
        while (seen > 0 && !refused) {
            const auto before = seen;
            if (!cv.wait_for(lock, std::chrono::milliseconds(300), [&] { return seen != before; }))
                break;
        }
    }
    // Drain: the callback above refers to this frame, so it must not run after
    // the function returns.
    monitor.unsubscribe(id, LibreSCRS::SmartCard::MonitorService::DrainPolicy::Drain);
    std::lock_guard lock(mtx);
    if (refused)
        return std::nullopt;
    return names;
}

} // namespace

int main()
{
    using namespace LibreSCRS::SmartCard;

    // 1. The attached PC/SC readers, as MonitorService reports them.
    MonitorService monitor;
    const auto maybeReaders = attachedReaders(monitor);
    if (!maybeReaders) {
        std::cerr << "The smart-card subsystem refused this process.\n";
        return 1;
    }

    const auto& readers = *maybeReaders;
    if (readers.empty()) {
        std::cout << "No PC/SC readers attached.\n";
        return 0;
    }

    std::cout << "Detected " << readers.size() << " reader(s):\n";
    for (const auto& name : readers) {
        std::cout << "  - " << name << '\n';
    }

    // 2. Walk readers and try to open the first one that has a card.
    //    CardSession::open is noexcept; on failure it returns the typed
    //    std::expected<CardSession, OpenError> error path.
    for (const auto& name : readers) {
        auto result = CardSession::open(name);
        if (!result) {
            std::cout << "  [" << name << "] open failed: ";
            switch (result.error().kind) {
            case OpenError::Kind::ReaderUnavailable:
                std::cout << "reader unavailable\n";
                break;
            case OpenError::Kind::NoCardPresent:
                std::cout << "no card present\n";
                break;
            case OpenError::Kind::ProtocolError:
                std::cout << "protocol error\n";
                break;
            case OpenError::Kind::SessionRefused:
                std::cout << "card held by another client\n";
                break;
            }
            continue;
        }

        const auto& session = *result;
        std::cout << "\nOpened session against reader:\n  " << session.readerName()
                  << "\n  ATR = " << toHex(session.atr()) << '\n';
        return 0;
    }

    std::cout << "\nNo reader produced an open session (likely no card inserted).\n";
    return 0;
}
