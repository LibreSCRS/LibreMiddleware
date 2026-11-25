// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "plugin_mapper.h"

#include <gtest/gtest.h>

using namespace card_mapper;

TEST(PluginMapper, EidPluginInfo)
{
    auto info = getPluginInfo("eid");
    EXPECT_EQ(info.name, "Serbian eID");
    EXPECT_EQ(info.pluginName, "eid");
    EXPECT_EQ(info.aids.size(), 4u);     // SERID, SERIF, SERRP, SEREL
    EXPECT_EQ(info.aids[0].size(), 11u); // AID length
    EXPECT_EQ(info.aidNames.size(), 4u);
    EXPECT_FALSE(info.dataFiles.empty());
    // Six data files, three per layout (ID/IF/RP share one): DocumentData,
    // PersonalData, VariableData; then the official ID's document, personal and
    // service data.
    ASSERT_EQ(info.dataFiles.size(), 6u);
    // DocumentData should have 8 tags
    EXPECT_EQ(info.dataFiles[0].tags.size(), 8u);
    // PersonalData should have 14 tags
    EXPECT_EQ(info.dataFiles[1].tags.size(), 14u);
    // VariableData should have 10 tags
    EXPECT_EQ(info.dataFiles[2].tags.size(), 10u);
    // The official ID's files: 3, 9 and 3 tags
    EXPECT_EQ(info.dataFiles[3].tags.size(), 3u);
    EXPECT_EQ(info.dataFiles[4].tags.size(), 9u);
    EXPECT_EQ(info.dataFiles[5].tags.size(), 3u);
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

TEST(PluginMapper, EuVrcPluginInfo)
{
    auto info = getPluginInfo("eu-vrc");
    EXPECT_EQ(info.name, "EU Vehicle Registration Certificate");
    EXPECT_EQ(info.pluginName, "eu-vrc");
    EXPECT_EQ(info.aids.size(), 4u); // EU AID + 3 Serbian sequences
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
    // MF has two child DFs: the layout ID, IF and RP share, and the official ID's
    ASSERT_EQ(info.rootNode.children.size(), 2u);
    // The first has 11 children (every file of the profile), the second 11 too
    EXPECT_EQ(info.rootNode.children[0].children.size(), 11u);
    EXPECT_EQ(info.rootNode.children[1].children.size(), 11u);
}
