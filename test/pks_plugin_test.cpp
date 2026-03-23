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

CardPlugin* findPks(CardPluginRegistry& registry)
{
    for (auto* p : registry.plugins()) {
        if (p->pluginId() == "rs-pks")
            return p;
    }
    return nullptr;
}
} // namespace

TEST(PksPluginTest, LoadsViaRegistry)
{
    CardPluginRegistry registry;
    auto loaded = registry.loadPluginsFromDirectory(pluginDir());
    EXPECT_GE(loaded, 1u);
    ASSERT_NE(findPks(registry), nullptr);
}

TEST(PksPluginTest, Metadata)
{
    CardPluginRegistry registry;
    registry.loadPluginsFromDirectory(pluginDir());
    auto* p = findPks(registry);
    ASSERT_NE(p, nullptr);

    EXPECT_EQ(p->pluginId(), "rs-pks");
    EXPECT_EQ(p->displayName(), "Serbian PKS Qualified Signature");
    EXPECT_EQ(p->probePriority(), 200);
}

TEST(PksPluginTest, CanHandleATR)
{
    CardPluginRegistry registry;
    registry.loadPluginsFromDirectory(pluginDir());
    auto* p = findPks(registry);
    ASSERT_NE(p, nullptr);

    // PKS ATR: 3B DE 97 ...
    EXPECT_TRUE(p->canHandle({0x3B, 0xDE, 0x97, 0x00, 0x00}));
    // Non-PKS ATRs
    EXPECT_FALSE(p->canHandle({0x3B, 0xFF, 0x94}));
    EXPECT_FALSE(p->canHandle({}));
    EXPECT_FALSE(p->canHandle({0x3B, 0xB9, 0x18})); // Apollo eID
}

TEST(PksPluginTest, PriorityBeforeEMRTD)
{
    CardPluginRegistry registry;
    registry.loadPluginsFromDirectory(pluginDir());
    auto* p = findPks(registry);
    ASSERT_NE(p, nullptr);

    for (auto* other : registry.plugins()) {
        if (other->pluginId() == "emrtd") {
            EXPECT_LT(p->probePriority(), other->probePriority());
        }
    }
}
