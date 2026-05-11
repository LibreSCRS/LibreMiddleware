// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Minimal find_package(LibreMiddleware CONFIG) consumer. Exercises one
// symbol from each of the two linked Config-package imported targets
// (LibreMiddleware::SmartCard and LibreMiddleware::Plugin) to prove
// the install-tree headers, .so libraries, and Targets.cmake all
// resolve end-to-end.
//
// Not intended as comprehensive API coverage — examples/sdk-consumer/main.cpp
// covers the broader public surface against the in-tree FetchContent path.

#include <LibreSCRS/Plugin/CardPluginService.h>
#include <LibreSCRS/Plugin/PluginTypes.h>
#include <LibreSCRS/SmartCard/MonitorService.h>

#include <filesystem>
#include <iostream>

int main()
{
    LibreSCRS::SmartCard::MonitorService monitor;
    auto readers = monitor.listReaders();
    if (readers.has_value()) {
        std::cout << "Detected " << readers->size() << " reader(s)\n";
    } else {
        std::cout << "Reader enumeration unavailable (PC/SC not running?)\n";
    }

    LibreSCRS::Plugin::CardPluginService registry{std::filesystem::path{"/nonexistent/plugins"}};
    std::cout << "CardPlugin ABI v" << LibreSCRS::Plugin::kCardPluginAbiVersion << ", loaded=" << registry.size()
              << "\n";

    return 0;
}
