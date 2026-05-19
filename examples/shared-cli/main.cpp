// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

/// @file
/// @brief Minimal CLI demonstrating LibreSCRS consumption via the SHARED
///        libLibreSCRS_* artefacts.
///
/// Enumerates PC/SC readers via @ref LibreSCRS::SmartCard::MonitorService,
/// opens a @ref LibreSCRS::SmartCard::CardSession against the first reader
/// that has a card present, and prints the reader name + ATR hex.
///
/// Exercises the SHARED-library code path:
///   * Public surface only: every include path is under @c <LibreSCRS/...>.
///   * Linked against @c LibreSCRS::All which transitively pulls every
///     @c LibreSCRS_*.so into the executable's DT_NEEDED edge.
///   * No reader required to BUILD or LINK; only required to demonstrate
///     a successful @ref CardSession::open.

#include <LibreSCRS/SmartCard/CardSession.h>
#include <LibreSCRS/SmartCard/MonitorService.h>

#include <cstdio>
#include <iostream>
#include <string>

namespace {

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

} // namespace

int main()
{
    using namespace LibreSCRS::SmartCard;

    // 1. MonitorService::listReaders is the canonical entry point for
    //    enumerating attached PC/SC readers. Noexcept in 4.0: a missing
    //    PC/SC subsystem surfaces as std::nullopt rather than throwing.
    MonitorService monitor;
    const auto maybeReaders = monitor.listReaders();
    if (!maybeReaders) {
        std::cerr << "PC/SC subsystem unavailable on this host.\n";
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
