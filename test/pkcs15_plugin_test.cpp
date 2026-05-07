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

std::shared_ptr<CardPlugin> findPkcs15(CardPluginService& registry)
{
    for (const auto& p : registry.plugins()) {
        if (p->pluginId() == "pkcs15")
            return p;
    }
    return nullptr;
}
} // namespace

TEST(PKCS15PluginTest, LoadsViaRegistry)
{
    CardPluginService registry{pluginDir()};
    EXPECT_GE(registry.size(), 1u);
    ASSERT_NE(findPkcs15(registry), nullptr);
}

TEST(PKCS15PluginTest, Metadata)
{
    CardPluginService registry{pluginDir()};
    auto p = findPkcs15(registry);
    ASSERT_NE(p, nullptr);

    EXPECT_EQ(p->pluginId(), "pkcs15");
    EXPECT_EQ(p->displayName(), "PKCS#15 (generic PKI)");
    EXPECT_EQ(p->probePriority(), 850);
}

TEST(PKCS15PluginTest, CapabilitiesIncludePKIAndPinManagement)
{
    CardPluginService registry{pluginDir()};
    auto p = findPkcs15(registry);
    ASSERT_NE(p, nullptr);

    auto caps = p->capabilities();
    EXPECT_TRUE(hasCapability(caps, CardCapabilities::PKI));
    EXPECT_TRUE(hasCapability(caps, CardCapabilities::PinManagement));
}

TEST(PKCS15PluginTest, CanHandleAlwaysFalse)
{
    CardPluginService registry{pluginDir()};
    auto p = findPkcs15(registry);
    ASSERT_NE(p, nullptr);

    EXPECT_FALSE(p->canHandle(std::vector<uint8_t>{0x3B, 0xFF, 0x94}));
    EXPECT_FALSE(p->canHandle(std::vector<uint8_t>{}));
}

TEST(PKCS15PluginTest, PriorityBetweenEMRTDAndOpenSC)
{
    CardPluginService registry{pluginDir()};
    auto p = findPkcs15(registry);
    ASSERT_NE(p, nullptr);
    EXPECT_EQ(p->probePriority(), 850);

    for (const auto& other : registry.plugins()) {
        if (other->pluginId() == "emrtd") {
            EXPECT_LT(other->probePriority(), 850);
        }
        if (other->pluginId() == "opensc") {
            EXPECT_GT(other->probePriority(), 850);
        }
    }
}
