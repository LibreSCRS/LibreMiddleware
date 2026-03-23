// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

#include <plugin/card_plugin.h>

#include <cstdint>
#include <filesystem>
#include <memory>
#include <set>
#include <vector>

namespace plugin {

class CardPluginRegistry
{
public:
    CardPluginRegistry() = default;
    ~CardPluginRegistry();

    CardPluginRegistry(const CardPluginRegistry&) = delete;
    CardPluginRegistry& operator=(const CardPluginRegistry&) = delete;
    CardPluginRegistry(CardPluginRegistry&&) = delete;
    CardPluginRegistry& operator=(CardPluginRegistry&&) = delete;

    /// Load all plugin .so files from directory. Returns number of plugins loaded.
    size_t loadPluginsFromDirectory(const std::filesystem::path& dir);

    /// Phase 1: find by ATR match (no card I/O). Returns nullptr if no match.
    CardPlugin* findPluginForCard(const std::vector<uint8_t>& atr) const;

    /// ATR-only overload (Phase 1 only — fast, no card I/O).
    /// Returns all plugins where canHandle(atr) returns true, sorted by priority.
    std::vector<CardPlugin*> findAllCandidates(const std::vector<uint8_t>& atr) const;

    /// Two-phase: ATR match first, then AID probe on live connection.
    /// De-duplicated, sorted by priority.
    std::vector<CardPlugin*> findAllCandidates(const std::vector<uint8_t>& atr, smartcard::PCSCConnection& conn) const;

    /// All loaded plugins, sorted by probePriority (ascending).
    const std::vector<CardPlugin*>& plugins() const;

private:
    struct LoadedPlugin
    {
        void* handle = nullptr;
        std::unique_ptr<CardPlugin> plugin;
    };

    std::vector<LoadedPlugin> loadedPlugins;
    std::vector<CardPlugin*> sortedPlugins;

    void sortPlugins();
};

} // namespace plugin
