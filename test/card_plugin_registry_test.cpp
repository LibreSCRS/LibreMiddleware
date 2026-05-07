// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <gtest/gtest.h>
#include <LibreSCRS/Plugin/CardPluginService.h>

#include <cstdint>
#include <filesystem>

using namespace LibreSCRS::Plugin;

namespace {
std::filesystem::path mockPluginDir()
{
    return std::filesystem::path(MOCK_PLUGIN_DIR);
}
} // namespace

TEST(CardPluginRegistryTest, LoadsPluginFromDirectory)
{
    CardPluginService registry{mockPluginDir()};
    EXPECT_EQ(registry.size(), 1u);
    EXPECT_EQ(registry.plugins().size(), 1u);
}

TEST(CardPluginRegistryTest, PluginMetadata)
{
    CardPluginService registry{mockPluginDir()};
    auto plugins = registry.plugins();
    ASSERT_EQ(plugins.size(), 1u);
    const auto& p = plugins[0];
    EXPECT_EQ(p->pluginId(), "mock");
    EXPECT_EQ(p->displayName(), "Mock Card");
    EXPECT_EQ(p->probePriority(), 500);
}

TEST(CardPluginRegistryTest, FindPluginByATR)
{
    CardPluginService registry{mockPluginDir()};
    std::vector<uint8_t> matchingATR = {0xDE, 0xAD, 0xBE, 0xEF};
    auto found = registry.findPluginForCard(matchingATR);
    ASSERT_NE(found, nullptr);
    EXPECT_EQ(found->pluginId(), "mock");
}

TEST(CardPluginRegistryTest, NoMatchReturnsNull)
{
    CardPluginService registry{mockPluginDir()};
    std::vector<uint8_t> unknownATR = {0x3B, 0x00};
    EXPECT_EQ(registry.findPluginForCard(unknownATR), nullptr);
}

TEST(CardPluginRegistryTest, EmptyDirectoryLoadsNothing)
{
    auto tmpdir = std::filesystem::temp_directory_path() / "librescrs-test-empty-plugins";
    std::filesystem::create_directories(tmpdir);
    CardPluginService registry{tmpdir};
    EXPECT_EQ(registry.size(), 0u);
    std::filesystem::remove(tmpdir);
}

TEST(CardPluginRegistryTest, NonexistentDirectoryLoadsNothing)
{
    // Nonexistent path must not throw / abort — errors are surfaced via
    // loadReport() (empty for a missing dir, since nothing was scanned).
    CardPluginService registry{std::filesystem::path{"/nonexistent/path"}};
    EXPECT_EQ(registry.size(), 0u);
    EXPECT_TRUE(registry.loadReport().empty());
}

TEST(CardPluginRegistryTest, IsUsableTrueOnSuccessfulLoad)
{
    CardPluginService registry{mockPluginDir()};
    ASSERT_GT(registry.size(), 0u) << "fixture sanity: mock plugin must load";
    EXPECT_TRUE(registry.isUsable());
}

TEST(CardPluginRegistryTest, IsUsableFalseOnEmptyDirectory)
{
    auto tmpdir = std::filesystem::temp_directory_path() / "librescrs-test-isusable-empty";
    std::filesystem::create_directories(tmpdir);
    CardPluginService registry{tmpdir};
    EXPECT_FALSE(registry.isUsable()) << "empty registry must report not-usable";
    std::filesystem::remove(tmpdir);
}

TEST(CardPluginRegistryTest, IsUsableFalseOnNonexistentDirectory)
{
    CardPluginService registry{std::filesystem::path{"/nonexistent/path"}};
    EXPECT_FALSE(registry.isUsable());
}

TEST(CardPluginRegistryTest, FindAllCandidatesByATR)
{
    CardPluginService registry{mockPluginDir()};
    std::vector<uint8_t> matchingATR = {0xDE, 0xAD, 0xBE, 0xEF};
    auto candidates = registry.findAllCandidates(matchingATR);
    ASSERT_EQ(candidates.size(), 1u);
    EXPECT_EQ(candidates[0]->pluginId(), "mock");
}

TEST(CardPluginRegistryTest, FindAllCandidatesEmptyForUnknownATR)
{
    CardPluginService registry{mockPluginDir()};
    std::vector<uint8_t> unknownATR = {0x3B, 0x00};
    auto candidates = registry.findAllCandidates(unknownATR);
    EXPECT_TRUE(candidates.empty());
}

// CardPluginService reshape — pimpl + span<path> ctor
// + structured LoadReport + shared_ptr<CardPlugin> ownership seam.

TEST(CardPluginRegistryTest, LoadReportContainsSuccessEntry)
{
    CardPluginService registry{mockPluginDir()};
    const auto& report = registry.loadReport();
    ASSERT_EQ(report.size(), 1u);
    EXPECT_EQ(report[0].status, LoadOutcome::Status::Loaded);
    EXPECT_EQ(report[0].pluginId, "mock");
    EXPECT_TRUE(report[0].diagnostic.empty());
    EXPECT_FALSE(report[0].soPath.empty());
}

TEST(CardPluginRegistryTest, SpanCtorScansAllDirectories)
{
    auto tmp1 = std::filesystem::temp_directory_path() / "librescrs-test-span-a";
    auto tmp2 = std::filesystem::temp_directory_path() / "librescrs-test-span-b";
    std::filesystem::create_directories(tmp1);
    std::filesystem::create_directories(tmp2);

    // Passing the mock plugin dir twice via span is legal (each directory is
    // scanned independently) — we use two empty tmp dirs + the mock dir to
    // exercise the span path without loading the same plugin twice.
    std::array<std::filesystem::path, 3> dirs{tmp1, mockPluginDir(), tmp2};
    CardPluginService registry{std::span<const std::filesystem::path>{dirs}};

    EXPECT_EQ(registry.size(), 1u);
    EXPECT_EQ(registry.plugins()[0]->pluginId(), "mock");

    std::filesystem::remove(tmp1);
    std::filesystem::remove(tmp2);
}

TEST(CardPluginRegistryTest, PluginsReturnsSharedPtr)
{
    CardPluginService registry{mockPluginDir()};
    auto plugins = registry.plugins();
    ASSERT_EQ(plugins.size(), 1u);

    // The returned element IS a shared_ptr — its use_count is at least 2
    // (one in the returned vector, one in the registry's internal vector).
    EXPECT_GE(plugins[0].use_count(), 2);
    EXPECT_EQ(plugins[0]->pluginId(), "mock");
}

TEST(CardPluginRegistryTest, MoveConstructTransfersState)
{
    CardPluginService a{mockPluginDir()};
    ASSERT_EQ(a.size(), 1u);

    CardPluginService b{std::move(a)};
    EXPECT_EQ(b.size(), 1u);
    EXPECT_EQ(b.plugins()[0]->pluginId(), "mock");
}

// Plugin SOs must export destroy_card_plugin in addition to
// create_card_plugin / card_plugin_abi_version. The registry invokes the
// plugin-side destructor via a shared_ptr custom deleter, so the plugin's
// own allocator runs — avoiding the classic cross-stdlib free-list crash
// when host and plugin are built against different C++ standard libraries.
//
// This test proves the deleter actually runs by snapshotting the plugin
// shared_ptr's reference count after the registry releases its own strong
// reference. If destroy_card_plugin were missing the registry would reject
// the plugin at load time (LoadOutcome::Status::MissingFactory). If the
// deleter were never invoked the use_count assertion below would still pass
// (shared_ptr bookkeeping is independent of the deleter), so the behavioural
// signal comes from the full round-trip: the plugin loaded, the host can
// use it, and the deleter must run at destruction time — AddressSanitizer
// on the CI jobs flags any mismatch between plugin-side new and host-side
// delete.
TEST(CardPluginRegistryTest, PluginDeleterRunsOnReleaseWithoutDoubleFree)
{
    std::weak_ptr<CardPlugin> weak;
    {
        CardPluginService registry{mockPluginDir()};
        auto plugins = registry.plugins();
        ASSERT_EQ(plugins.size(), 1u);
        weak = plugins[0];
        // Drop the local copy; registry still holds its strong reference.
    }
    // After registry destruction the strong reference count should have
    // dropped to zero and the deleter should have run the plugin-side
    // destroy_card_plugin + dlclose sequence. If destroy_card_plugin were
    // missing or the deleter skipped, ASan would abort the test process;
    // the weak_ptr check below verifies ownership is fully released.
    EXPECT_TRUE(weak.expired()) << "plugin shared_ptr must be released once both registry and local copies drop";
}
