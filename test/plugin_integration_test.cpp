// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <gtest/gtest.h>
#include <plugin/card_plugin_registry.h>

#include <filesystem>
#include <iostream>
#include <set>

using namespace plugin;

namespace {
std::filesystem::path pluginDir()
{
    return std::filesystem::path(PLUGIN_DIR);
}
} // namespace

TEST(PluginIntegrationTest, LoadAllPlugins)
{
    CardPluginRegistry registry;
    auto loaded = registry.loadPluginsFromDirectory(pluginDir());
    EXPECT_EQ(loaded, 4u);
    EXPECT_EQ(registry.plugins().size(), 4u);
    for (auto* p : registry.plugins()) {
        std::cout << "  Loaded: " << p->pluginId() << " (" << p->displayName() << ") priority=" << p->probePriority()
                  << "\n";
    }
}

TEST(PluginIntegrationTest, PrioritySortOrder)
{
    CardPluginRegistry registry;
    registry.loadPluginsFromDirectory(pluginDir());
    auto& plugins = registry.plugins();
    for (size_t i = 1; i < plugins.size(); ++i) {
        EXPECT_LE(plugins[i - 1]->probePriority(), plugins[i]->probePriority());
    }
}

TEST(PluginIntegrationTest, EachPluginHasUniqueId)
{
    CardPluginRegistry registry;
    registry.loadPluginsFromDirectory(pluginDir());
    std::set<std::string> ids;
    for (auto* p : registry.plugins()) {
        EXPECT_TRUE(ids.insert(p->pluginId()).second) << "Duplicate plugin ID: " << p->pluginId();
    }
}

TEST(PluginIntegrationTest, GemaltoEidATRMatchesRsEid)
{
    CardPluginRegistry registry;
    registry.loadPluginsFromDirectory(pluginDir());
    std::vector<uint8_t> gemaltoATR = {0x3B, 0xFF, 0x94, 0x00, 0x00};
    auto* p = registry.findPluginForCard(gemaltoATR);
    ASSERT_NE(p, nullptr);
    EXPECT_EQ(p->pluginId(), "rs-eid");
}

TEST(PluginIntegrationTest, ApolloEidATRMatchesRsEid)
{
    CardPluginRegistry registry;
    registry.loadPluginsFromDirectory(pluginDir());
    std::vector<uint8_t> apolloATR = {0x3B, 0xB9, 0x18, 0x00};
    auto* p = registry.findPluginForCard(apolloATR);
    ASSERT_NE(p, nullptr);
    EXPECT_EQ(p->pluginId(), "rs-eid");
}

TEST(PluginIntegrationTest, PksATRMatchesRsPks)
{
    CardPluginRegistry registry;
    registry.loadPluginsFromDirectory(pluginDir());
    std::vector<uint8_t> pksATR = {0x3B, 0xDE, 0x97, 0x00};
    auto* p = registry.findPluginForCard(pksATR);
    ASSERT_NE(p, nullptr);
    EXPECT_EQ(p->pluginId(), "rs-pks");
}

TEST(PluginIntegrationTest, UnknownATRReturnsNull)
{
    CardPluginRegistry registry;
    registry.loadPluginsFromDirectory(pluginDir());
    std::vector<uint8_t> unknownATR = {0x00, 0x00, 0x00};
    EXPECT_EQ(registry.findPluginForCard(unknownATR), nullptr);
}
