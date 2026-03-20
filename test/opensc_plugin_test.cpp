// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <gtest/gtest.h>
#include <plugin/card_plugin_registry.h>

#include <libopensc/opensc.h>

#include <filesystem>

using namespace plugin;

namespace {

std::filesystem::path pluginDir()
{
    return std::filesystem::path(PLUGIN_DIR);
}

} // namespace

// --- Unit tests (no hardware) ---

TEST(OpenSCPluginTest, LoadsViaRegistry)
{
    CardPluginRegistry registry;
    auto loaded = registry.loadPluginsFromDirectory(pluginDir());
    EXPECT_GE(loaded, 1u);

    CardPlugin* opensc = nullptr;
    for (auto* p : registry.plugins()) {
        if (p->pluginId() == "opensc") {
            opensc = p;
            break;
        }
    }
    ASSERT_NE(opensc, nullptr);
}

TEST(OpenSCPluginTest, Metadata)
{
    CardPluginRegistry registry;
    registry.loadPluginsFromDirectory(pluginDir());

    CardPlugin* opensc = nullptr;
    for (auto* p : registry.plugins()) {
        if (p->pluginId() == "opensc") {
            opensc = p;
            break;
        }
    }
    ASSERT_NE(opensc, nullptr);

    EXPECT_EQ(opensc->pluginId(), "opensc");
    EXPECT_EQ(opensc->displayName(), "OpenSC (generic)");
    EXPECT_EQ(opensc->probePriority(), 900);
}

TEST(OpenSCPluginTest, CanHandleAlwaysFalse)
{
    CardPluginRegistry registry;
    registry.loadPluginsFromDirectory(pluginDir());

    CardPlugin* opensc = nullptr;
    for (auto* p : registry.plugins()) {
        if (p->pluginId() == "opensc") {
            opensc = p;
            break;
        }
    }
    ASSERT_NE(opensc, nullptr);

    EXPECT_FALSE(opensc->canHandle({0x3B, 0xFF, 0x94}));
    EXPECT_FALSE(opensc->canHandle({0x3B, 0xB9, 0x18}));
    EXPECT_FALSE(opensc->canHandle({0x00}));
    EXPECT_FALSE(opensc->canHandle({}));
}

TEST(OpenSCPluginTest, LowestPriority)
{
    CardPluginRegistry registry;
    registry.loadPluginsFromDirectory(pluginDir());

    auto& plugins = registry.plugins();
    ASSERT_FALSE(plugins.empty());

    for (auto* p : plugins) {
        if (p->pluginId() != "opensc") {
            EXPECT_LT(p->probePriority(), 900) << p->pluginId() << " has priority >= 900";
        }
    }
}

// --- Integration tests (require libopensc, no hardware) ---

TEST(OpenSCPluginTest, ContextEstablishRelease)
{
    sc_context_t* ctx = nullptr;
    int rc = sc_establish_context(&ctx, "librescrs-test");
    ASSERT_EQ(rc, 0) << "sc_establish_context failed: " << sc_strerror(rc);
    ASSERT_NE(ctx, nullptr);

    sc_release_context(ctx);
}

TEST(OpenSCPluginTest, NoReaderGracefulFail)
{
    sc_context_t* ctx = nullptr;
    int rc = sc_establish_context(&ctx, "librescrs-test");
    ASSERT_EQ(rc, 0);

    sc_reader_t* reader = sc_ctx_get_reader_by_name(ctx, "nonexistent_reader_12345");
    EXPECT_EQ(reader, nullptr);

    sc_release_context(ctx);
}
