// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <gtest/gtest.h>
#include <LibreSCRS/Plugin/CardPluginService.h>

#include <filesystem>
#include <memory>

using namespace LibreSCRS::Plugin;

namespace {
std::filesystem::path pluginDir()
{
    return std::filesystem::path(PLUGIN_DIR);
}

std::shared_ptr<CardPlugin> findCardEdge(CardPluginService& registry)
{
    for (const auto& p : registry.plugins()) {
        if (p->pluginId() == "cardedge")
            return p;
    }
    return nullptr;
}
} // namespace

TEST(CardEdgePluginTest, LoadsViaRegistry)
{
    CardPluginService registry{pluginDir()};
    EXPECT_GE(registry.size(), 1u);
    ASSERT_NE(findCardEdge(registry), nullptr);
}

TEST(CardEdgePluginTest, Metadata)
{
    CardPluginService registry{pluginDir()};
    auto p = findCardEdge(registry);
    ASSERT_NE(p, nullptr);

    EXPECT_EQ(p->pluginId(), "cardedge");
    EXPECT_EQ(p->displayName(), "CardEdge (Serbian PKI)");
    EXPECT_EQ(p->probePriority(), 840);
}

TEST(CardEdgePluginTest, CapabilitiesIncludePKIAndPinManagement)
{
    CardPluginService registry{pluginDir()};
    auto p = findCardEdge(registry);
    ASSERT_NE(p, nullptr);

    auto caps = p->capabilities();
    EXPECT_TRUE(hasCapability(caps, CardCapabilities::PKI));
    EXPECT_TRUE(hasCapability(caps, CardCapabilities::PinManagement));
}

TEST(CardEdgePluginTest, CanHandleAlwaysFalse)
{
    CardPluginService registry{pluginDir()};
    auto p = findCardEdge(registry);
    ASSERT_NE(p, nullptr);

    EXPECT_FALSE(p->canHandle(std::vector<uint8_t>{0x3B, 0xFF, 0x94}));
    EXPECT_FALSE(p->canHandle(std::vector<uint8_t>{}));
}

TEST(CardEdgePluginTest, PriorityBeforePKCS15)
{
    CardPluginService registry{pluginDir()};
    auto p = findCardEdge(registry);
    ASSERT_NE(p, nullptr);
    EXPECT_EQ(p->probePriority(), 840);

    for (const auto& other : registry.plugins()) {
        if (other->pluginId() == "pkcs15") {
            EXPECT_LT(p->probePriority(), other->probePriority());
        }
    }
}
