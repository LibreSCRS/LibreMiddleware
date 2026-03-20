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
} // namespace

TEST(EMRTDPluginTest, LoadsViaRegistry)
{
    CardPluginRegistry registry;
    auto loaded = registry.loadPluginsFromDirectory(pluginDir());
    EXPECT_GE(loaded, 1u);

    CardPlugin* emrtd = nullptr;
    for (auto* p : registry.plugins()) {
        if (p->pluginId() == "emrtd") {
            emrtd = p;
            break;
        }
    }
    ASSERT_NE(emrtd, nullptr);
}

TEST(EMRTDPluginTest, Metadata)
{
    CardPluginRegistry registry;
    registry.loadPluginsFromDirectory(pluginDir());

    CardPlugin* emrtd = nullptr;
    for (auto* p : registry.plugins()) {
        if (p->pluginId() == "emrtd") {
            emrtd = p;
            break;
        }
    }
    ASSERT_NE(emrtd, nullptr);

    EXPECT_EQ(emrtd->pluginId(), "emrtd");
    EXPECT_EQ(emrtd->displayName(), "Electronic Passport (eMRTD)");
    EXPECT_EQ(emrtd->probePriority(), 800);
}

TEST(EMRTDPluginTest, CanHandleAlwaysFalse)
{
    CardPluginRegistry registry;
    registry.loadPluginsFromDirectory(pluginDir());

    CardPlugin* emrtd = nullptr;
    for (auto* p : registry.plugins()) {
        if (p->pluginId() == "emrtd") {
            emrtd = p;
            break;
        }
    }
    ASSERT_NE(emrtd, nullptr);

    EXPECT_FALSE(emrtd->canHandle({0x3B, 0xFF, 0x94}));
    EXPECT_FALSE(emrtd->canHandle({}));
}

TEST(EMRTDPluginTest, PriorityBetweenDedicatedAndOpenSC)
{
    CardPluginRegistry registry;
    registry.loadPluginsFromDirectory(pluginDir());

    CardPlugin* emrtd = nullptr;
    for (auto* p : registry.plugins()) {
        if (p->pluginId() == "emrtd") {
            emrtd = p;
            break;
        }
    }
    ASSERT_NE(emrtd, nullptr);
    EXPECT_EQ(emrtd->probePriority(), 800);

    for (auto* p : registry.plugins()) {
        if (p->pluginId() == "rs-eid" || p->pluginId() == "vehicle") {
            EXPECT_LT(p->probePriority(), 800);
        }
        if (p->pluginId() == "opensc") {
            EXPECT_GT(p->probePriority(), 800);
        }
    }
}
