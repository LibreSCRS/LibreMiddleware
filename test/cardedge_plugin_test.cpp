// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <gtest/gtest.h>
#include <plugin/card_plugin_registry.h>

#include <filesystem>

using namespace plugin;

namespace {
std::filesystem::path pluginDir()
{
    return std::filesystem::path(PLUGIN_DIR);
}

CardPlugin* findCardEdge(CardPluginRegistry& registry)
{
    for (auto* p : registry.plugins()) {
        if (p->pluginId() == "cardedge")
            return p;
    }
    return nullptr;
}
} // namespace

TEST(CardEdgePluginTest, LoadsViaRegistry)
{
    CardPluginRegistry registry;
    auto loaded = registry.loadPluginsFromDirectory(pluginDir());
    EXPECT_GE(loaded, 1u);
    ASSERT_NE(findCardEdge(registry), nullptr);
}

TEST(CardEdgePluginTest, Metadata)
{
    CardPluginRegistry registry;
    registry.loadPluginsFromDirectory(pluginDir());
    auto* p = findCardEdge(registry);
    ASSERT_NE(p, nullptr);

    EXPECT_EQ(p->pluginId(), "cardedge");
    EXPECT_EQ(p->displayName(), "CardEdge (Serbian PKI)");
    EXPECT_EQ(p->probePriority(), 840);
}

TEST(CardEdgePluginTest, SupportsPKI)
{
    CardPluginRegistry registry;
    registry.loadPluginsFromDirectory(pluginDir());
    auto* p = findCardEdge(registry);
    ASSERT_NE(p, nullptr);

    EXPECT_TRUE(p->supportsPKI());
}

TEST(CardEdgePluginTest, CanHandleAlwaysFalse)
{
    CardPluginRegistry registry;
    registry.loadPluginsFromDirectory(pluginDir());
    auto* p = findCardEdge(registry);
    ASSERT_NE(p, nullptr);

    EXPECT_FALSE(p->canHandle({0x3B, 0xFF, 0x94}));
    EXPECT_FALSE(p->canHandle({}));
}

TEST(CardEdgePluginTest, PriorityBeforePKCS15)
{
    CardPluginRegistry registry;
    registry.loadPluginsFromDirectory(pluginDir());
    auto* p = findCardEdge(registry);
    ASSERT_NE(p, nullptr);
    EXPECT_EQ(p->probePriority(), 840);

    for (auto* other : registry.plugins()) {
        if (other->pluginId() == "pkcs15") {
            EXPECT_LT(p->probePriority(), other->probePriority());
        }
    }
}
