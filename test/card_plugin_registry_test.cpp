// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <gtest/gtest.h>
#include <plugin/card_plugin_registry.h>

#include <cstdint>
#include <filesystem>

using namespace plugin;

namespace {
std::filesystem::path mockPluginDir()
{
    return std::filesystem::path(MOCK_PLUGIN_DIR);
}
} // namespace

TEST(CardPluginRegistryTest, LoadsPluginFromDirectory)
{
    CardPluginRegistry registry;
    auto loaded = registry.loadPluginsFromDirectory(mockPluginDir());
    EXPECT_EQ(loaded, 1u);
    EXPECT_EQ(registry.plugins().size(), 1u);
}

TEST(CardPluginRegistryTest, PluginMetadata)
{
    CardPluginRegistry registry;
    registry.loadPluginsFromDirectory(mockPluginDir());
    ASSERT_EQ(registry.plugins().size(), 1u);
    auto* p = registry.plugins()[0];
    EXPECT_EQ(p->pluginId(), "mock");
    EXPECT_EQ(p->displayName(), "Mock Card");
    EXPECT_EQ(p->probePriority(), 500);
}

TEST(CardPluginRegistryTest, FindPluginByATR)
{
    CardPluginRegistry registry;
    registry.loadPluginsFromDirectory(mockPluginDir());
    std::vector<uint8_t> matchingATR = {0xDE, 0xAD, 0xBE, 0xEF};
    auto* found = registry.findPluginForCard(matchingATR);
    ASSERT_NE(found, nullptr);
    EXPECT_EQ(found->pluginId(), "mock");
}

TEST(CardPluginRegistryTest, NoMatchReturnsNull)
{
    CardPluginRegistry registry;
    registry.loadPluginsFromDirectory(mockPluginDir());
    std::vector<uint8_t> unknownATR = {0x3B, 0x00};
    EXPECT_EQ(registry.findPluginForCard(unknownATR), nullptr);
}

TEST(CardPluginRegistryTest, EmptyDirectoryLoadsNothing)
{
    CardPluginRegistry registry;
    auto tmpdir = std::filesystem::temp_directory_path() / "librescrs-test-empty-plugins";
    std::filesystem::create_directories(tmpdir);
    auto loaded = registry.loadPluginsFromDirectory(tmpdir);
    EXPECT_EQ(loaded, 0u);
    std::filesystem::remove(tmpdir);
}

TEST(CardPluginRegistryTest, NonexistentDirectoryLoadsNothing)
{
    CardPluginRegistry registry;
    auto loaded = registry.loadPluginsFromDirectory("/nonexistent/path");
    EXPECT_EQ(loaded, 0u);
}

TEST(CardPluginRegistryTest, FindAllCandidatesByATR)
{
    CardPluginRegistry registry;
    registry.loadPluginsFromDirectory(mockPluginDir());
    std::vector<uint8_t> matchingATR = {0xDE, 0xAD, 0xBE, 0xEF};
    auto candidates = registry.findAllCandidates(matchingATR);
    ASSERT_EQ(candidates.size(), 1u);
    EXPECT_EQ(candidates[0]->pluginId(), "mock");
}

TEST(CardPluginRegistryTest, FindAllCandidatesEmptyForUnknownATR)
{
    CardPluginRegistry registry;
    registry.loadPluginsFromDirectory(mockPluginDir());
    std::vector<uint8_t> unknownATR = {0x3B, 0x00};
    auto candidates = registry.findAllCandidates(unknownATR);
    EXPECT_TRUE(candidates.empty());
}

TEST(CardPluginRegistryTest, FindAllCandidatesTwoPhaseMatchesByATR)
{
    CardPluginRegistry registry;
    registry.loadPluginsFromDirectory(mockPluginDir());

    std::vector<uint8_t> matchingATR = {0xDE, 0xAD, 0xBE, 0xEF};

    // Create a dummy PCSCConnection reference. The mock plugin never dereferences
    // the connection, so this is safe for testing the two-phase code path.
    alignas(std::max_align_t) uint8_t connStorage[256] = {};
    auto& dummyConn = reinterpret_cast<smartcard::PCSCConnection&>(connStorage);

    auto atrOnly = registry.findAllCandidates(matchingATR);
    auto twoPhase = registry.findAllCandidates(matchingATR, dummyConn);

    // Two-phase result should match ATR-only result (de-duplication works,
    // Phase 2 adds nothing since the mock's canHandleConnection returns false).
    ASSERT_EQ(twoPhase.size(), atrOnly.size());
    for (size_t i = 0; i < atrOnly.size(); ++i) {
        EXPECT_EQ(twoPhase[i]->pluginId(), atrOnly[i]->pluginId());
    }
}
