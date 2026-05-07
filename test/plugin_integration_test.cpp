// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <gtest/gtest.h>
#include <LibreSCRS/Plugin/CardPluginService.h>

#include <filesystem>
#include <iostream>
#include <set>

using namespace LibreSCRS::Plugin;

namespace {
std::filesystem::path pluginDir()
{
    return std::filesystem::path(PLUGIN_DIR);
}
} // namespace

TEST(PluginIntegrationTest, LoadAllPlugins)
{
    CardPluginService registry{pluginDir()};
    size_t expectedCount = 3;
#ifdef HAS_EMRTD_PLUGIN
    expectedCount++;
#endif
#ifdef HAS_PKCS15_PLUGIN
    expectedCount++;
#endif
#ifdef HAS_CARDEDGE_PLUGIN
    expectedCount++;
#endif
#ifdef HAS_OPENSC_PLUGIN
    expectedCount++;
#endif
#ifdef HAS_PIV_PLUGIN
    expectedCount++;
#endif
    EXPECT_EQ(registry.size(), expectedCount);
    EXPECT_EQ(registry.plugins().size(), expectedCount);
    for (const auto& p : registry.plugins()) {
        std::cout << "  Loaded: " << p->pluginId() << " (" << p->displayName() << ") priority=" << p->probePriority()
                  << "\n";
    }
}

TEST(PluginIntegrationTest, PrioritySortOrder)
{
    CardPluginService registry{pluginDir()};
    auto plugins = registry.plugins();
    for (size_t i = 1; i < plugins.size(); ++i) {
        EXPECT_LE(plugins[i - 1]->probePriority(), plugins[i]->probePriority());
    }
}

TEST(PluginIntegrationTest, EachPluginHasUniqueId)
{
    CardPluginService registry{pluginDir()};
    std::set<std::string> ids;
    for (const auto& p : registry.plugins()) {
        EXPECT_TRUE(ids.insert(p->pluginId()).second) << "Duplicate plugin ID: " << p->pluginId();
    }
}

TEST(PluginIntegrationTest, GemaltoEidATRMatchesRsEid)
{
    CardPluginService registry{pluginDir()};
    std::vector<uint8_t> gemaltoATR = {0x3B, 0xFF, 0x94, 0x00, 0x00};
    auto p = registry.findPluginForCard(gemaltoATR);
    ASSERT_NE(p, nullptr);
    EXPECT_EQ(p->pluginId(), "rs-eid");
}

TEST(PluginIntegrationTest, ApolloEidATRMatchesRsEid)
{
    CardPluginService registry{pluginDir()};
    std::vector<uint8_t> apolloATR = {0x3B, 0xB9, 0x18, 0x00};
    auto p = registry.findPluginForCard(apolloATR);
    ASSERT_NE(p, nullptr);
    EXPECT_EQ(p->pluginId(), "rs-eid");
}

TEST(PluginIntegrationTest, UnknownATRReturnsNull)
{
    CardPluginService registry{pluginDir()};
    std::vector<uint8_t> unknownATR = {0x00, 0x00, 0x00};
    EXPECT_EQ(registry.findPluginForCard(unknownATR), nullptr);
}

#ifdef HAS_OPENSC_PLUGIN
TEST(PluginIntegrationTest, OpenSCIsLastInProbeOrder)
{
    CardPluginService registry{pluginDir()};

    auto plugins = registry.plugins();
    ASSERT_FALSE(plugins.empty());
    EXPECT_EQ(plugins.back()->pluginId(), "opensc");
    EXPECT_EQ(plugins.back()->probePriority(), 900);
}
#endif

#ifdef HAS_EMRTD_PLUGIN
TEST(PluginIntegrationTest, EMRTDPriorityBetweenDedicatedAndOpenSC)
{
    CardPluginService registry{pluginDir()};

    std::shared_ptr<CardPlugin> emrtd;
    for (const auto& p : registry.plugins()) {
        if (p->pluginId() == "emrtd") {
            emrtd = p;
            break;
        }
    }
    ASSERT_NE(emrtd, nullptr);
    EXPECT_EQ(emrtd->probePriority(), 800);
}
#endif
