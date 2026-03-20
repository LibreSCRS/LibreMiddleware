// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <plugin/card_plugin_registry.h>

#include <algorithm>
#include <dlfcn.h>
#include <iostream>

namespace plugin {

using CreateFunc = std::unique_ptr<CardPlugin> (*)();
using AbiVersionFunc = uint32_t (*)();

CardPluginRegistry::~CardPluginRegistry()
{
    sortedPlugins_.clear();
    for (auto& lp : loadedPlugins_) {
        lp.plugin.reset();
        if (lp.handle) {
            dlclose(lp.handle);
        }
    }
}

size_t CardPluginRegistry::loadPluginsFromDirectory(const std::filesystem::path& dir)
{
    if (!std::filesystem::exists(dir) || !std::filesystem::is_directory(dir)) {
        return 0;
    }

    size_t count = 0;
    for (const auto& entry : std::filesystem::directory_iterator(dir)) {
        if (!entry.is_regular_file())
            continue;

        auto ext = entry.path().extension().string();
        if (ext != ".so" && ext != ".dylib")
            continue;

        void* handle = dlopen(entry.path().c_str(), RTLD_LAZY);
        if (!handle) {
            std::cerr << "CardPluginRegistry: failed to load " << entry.path() << ": " << dlerror() << "\n";
            continue;
        }

        auto abiFunc = reinterpret_cast<AbiVersionFunc>(dlsym(handle, "card_plugin_abi_version"));
        if (!abiFunc) {
            std::cerr << "CardPluginRegistry: " << entry.path() << " missing card_plugin_abi_version()\n";
            dlclose(handle);
            continue;
        }

        uint32_t version = abiFunc();
        if (version != LIBRESCRS_PLUGIN_ABI_VERSION) {
            std::cerr << "CardPluginRegistry: " << entry.path() << " ABI version mismatch (got " << version
                      << ", expected " << LIBRESCRS_PLUGIN_ABI_VERSION << ")\n";
            dlclose(handle);
            continue;
        }

        auto createFunc = reinterpret_cast<CreateFunc>(dlsym(handle, "create_card_plugin"));
        if (!createFunc) {
            std::cerr << "CardPluginRegistry: " << entry.path() << " missing create_card_plugin()\n";
            dlclose(handle);
            continue;
        }

        auto plugin = createFunc();
        if (!plugin) {
            std::cerr << "CardPluginRegistry: " << entry.path() << " create_card_plugin() returned nullptr\n";
            dlclose(handle);
            continue;
        }

        loadedPlugins_.push_back({handle, std::move(plugin)});
        ++count;
    }

    sortPlugins();
    return count;
}

CardPlugin* CardPluginRegistry::findPluginForCard(const std::vector<uint8_t>& atr) const
{
    for (auto* plugin : sortedPlugins_) {
        if (plugin->canHandle(atr)) {
            return plugin;
        }
    }
    return nullptr;
}

CardPlugin* CardPluginRegistry::findPluginForConnection(smartcard::PCSCConnection& conn) const
{
    for (auto* plugin : sortedPlugins_) {
        if (plugin->canHandleConnection(conn)) {
            return plugin;
        }
    }
    return nullptr;
}

std::vector<CardPlugin*> CardPluginRegistry::findAllCandidates(const std::vector<uint8_t>& atr) const
{
    std::vector<CardPlugin*> result;
    for (auto* plugin : sortedPlugins_) {
        if (plugin->canHandle(atr)) {
            result.push_back(plugin);
        }
    }
    return result;
}

std::vector<CardPlugin*> CardPluginRegistry::findAllCandidates(const std::vector<uint8_t>& atr,
                                                               smartcard::PCSCConnection& conn) const
{
    std::set<CardPlugin*> seen;
    std::vector<CardPlugin*> result;

    // Phase 1: ATR matches
    for (auto* plugin : sortedPlugins_) {
        if (plugin->canHandle(atr)) {
            result.push_back(plugin);
            seen.insert(plugin);
        }
    }

    // Phase 2: AID probe on remaining plugins
    for (auto* plugin : sortedPlugins_) {
        if (seen.count(plugin) > 0) {
            continue;
        }
        try {
            if (plugin->canHandleConnection(conn)) {
                result.push_back(plugin);
            }
        } catch (...) {
            // AID probe failed — skip this plugin
        }
    }

    std::sort(result.begin(), result.end(),
              [](const auto* a, const auto* b) { return a->probePriority() < b->probePriority(); });
    return result;
}

const std::vector<CardPlugin*>& CardPluginRegistry::plugins() const
{
    return sortedPlugins_;
}

void CardPluginRegistry::sortPlugins()
{
    sortedPlugins_.clear();
    sortedPlugins_.reserve(loadedPlugins_.size());
    for (auto& lp : loadedPlugins_) {
        sortedPlugins_.push_back(lp.plugin.get());
    }
    std::sort(sortedPlugins_.begin(), sortedPlugins_.end(),
              [](const auto* a, const auto* b) { return a->probePriority() < b->probePriority(); });
}

} // namespace plugin
