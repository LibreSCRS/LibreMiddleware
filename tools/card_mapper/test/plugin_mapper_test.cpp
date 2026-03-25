// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "plugin_mapper.h"

#include <gtest/gtest.h>

#include <algorithm>

using namespace card_mapper;

TEST(PluginMapper, KnownPluginsContainsAll)
{
    auto plugins = getKnownPlugins();
    EXPECT_EQ(plugins.size(), 5u);
    EXPECT_NE(std::find(plugins.begin(), plugins.end(), "eid"), plugins.end());
    EXPECT_NE(std::find(plugins.begin(), plugins.end(), "cardedge"), plugins.end());
    EXPECT_NE(std::find(plugins.begin(), plugins.end(), "health"), plugins.end());
    EXPECT_NE(std::find(plugins.begin(), plugins.end(), "vehicle"), plugins.end());
    EXPECT_NE(std::find(plugins.begin(), plugins.end(), "emrtd"), plugins.end());
}

TEST(PluginMapper, EidPluginInfo)
{
    auto info = getPluginInfo("eid");
    EXPECT_EQ(info.name, "Serbian eID");
    EXPECT_EQ(info.pluginName, "eid");
    EXPECT_EQ(info.aids.size(), 3u); // SERID, SERIF, SERRP
    EXPECT_EQ(info.aids[0].size(), 11u); // AID length
    EXPECT_FALSE(info.dataFiles.empty());
    // Should have 3 data files: DocumentData, PersonalData, VariableData
    EXPECT_EQ(info.dataFiles.size(), 3u);
    // DocumentData should have 7 tags
    EXPECT_EQ(info.dataFiles[0].tags.size(), 7u);
    // PersonalData should have 11 tags
    EXPECT_EQ(info.dataFiles[1].tags.size(), 11u);
    // VariableData should have 11 tags
    EXPECT_EQ(info.dataFiles[2].tags.size(), 11u);
}

TEST(PluginMapper, CardEdgePluginInfo)
{
    auto info = getPluginInfo("cardedge");
    EXPECT_EQ(info.name, "CardEdge PKI");
    EXPECT_EQ(info.pluginName, "cardedge");
    EXPECT_EQ(info.aids.size(), 1u);
    EXPECT_EQ(info.aids[0].size(), 12u);
}

TEST(PluginMapper, HealthPluginInfo)
{
    auto info = getPluginInfo("health");
    EXPECT_EQ(info.name, "Serbian Health Insurance");
    EXPECT_EQ(info.pluginName, "health");
    EXPECT_EQ(info.aids.size(), 1u);
    EXPECT_EQ(info.dataFiles.size(), 4u);
}

TEST(PluginMapper, VehiclePluginInfo)
{
    auto info = getPluginInfo("vehicle");
    EXPECT_EQ(info.name, "Serbian Vehicle Registration");
    EXPECT_EQ(info.pluginName, "vehicle");
    EXPECT_EQ(info.aids.size(), 3u);
    // Vehicle uses non-TLV parsing, so no tag data files
    EXPECT_TRUE(info.dataFiles.empty());
}

TEST(PluginMapper, EmrtdPluginInfo)
{
    auto info = getPluginInfo("emrtd");
    EXPECT_EQ(info.name, "eMRTD");
    EXPECT_EQ(info.pluginName, "emrtd");
    EXPECT_EQ(info.aids.size(), 1u);
    EXPECT_EQ(info.aids[0].size(), 7u);
}

TEST(PluginMapper, UnknownPluginThrows)
{
    EXPECT_THROW(getPluginInfo("nonexistent"), std::runtime_error);
}

TEST(PluginMapper, EidRootNodeHasChildren)
{
    auto info = getPluginInfo("eid");
    EXPECT_EQ(info.rootNode.name, "MF");
    EXPECT_TRUE(info.rootNode.isDir);
    EXPECT_FALSE(info.rootNode.children.empty());
    // MF has one child DF
    EXPECT_EQ(info.rootNode.children.size(), 1u);
    // DF has 11 children (data files)
    EXPECT_EQ(info.rootNode.children[0].children.size(), 11u);
}
