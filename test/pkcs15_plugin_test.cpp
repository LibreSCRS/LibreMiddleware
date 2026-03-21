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

CardPlugin* findPkcs15(CardPluginRegistry& registry)
{
    for (auto* p : registry.plugins()) {
        if (p->pluginId() == "pkcs15")
            return p;
    }
    return nullptr;
}
} // namespace

TEST(PKCS15PluginTest, LoadsViaRegistry)
{
    CardPluginRegistry registry;
    auto loaded = registry.loadPluginsFromDirectory(pluginDir());
    EXPECT_GE(loaded, 1u);
    ASSERT_NE(findPkcs15(registry), nullptr);
}

TEST(PKCS15PluginTest, Metadata)
{
    CardPluginRegistry registry;
    registry.loadPluginsFromDirectory(pluginDir());
    auto* p = findPkcs15(registry);
    ASSERT_NE(p, nullptr);

    EXPECT_EQ(p->pluginId(), "pkcs15");
    EXPECT_EQ(p->displayName(), "PKCS#15 (generic PKI)");
    EXPECT_EQ(p->probePriority(), 850);
}

TEST(PKCS15PluginTest, SupportsPKI)
{
    CardPluginRegistry registry;
    registry.loadPluginsFromDirectory(pluginDir());
    auto* p = findPkcs15(registry);
    ASSERT_NE(p, nullptr);

    EXPECT_TRUE(p->supportsPKI());
}

TEST(PKCS15PluginTest, CanHandleAlwaysFalse)
{
    CardPluginRegistry registry;
    registry.loadPluginsFromDirectory(pluginDir());
    auto* p = findPkcs15(registry);
    ASSERT_NE(p, nullptr);

    EXPECT_FALSE(p->canHandle({0x3B, 0xFF, 0x94}));
    EXPECT_FALSE(p->canHandle({}));
}

TEST(PKCS15PluginTest, PriorityBetweenEMRTDAndOpenSC)
{
    CardPluginRegistry registry;
    registry.loadPluginsFromDirectory(pluginDir());
    auto* p = findPkcs15(registry);
    ASSERT_NE(p, nullptr);
    EXPECT_EQ(p->probePriority(), 850);

    for (auto* other : registry.plugins()) {
        if (other->pluginId() == "emrtd") {
            EXPECT_LT(other->probePriority(), 850);
        }
        if (other->pluginId() == "opensc") {
            EXPECT_GT(other->probePriority(), 850);
        }
    }
}
