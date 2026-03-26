// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <gtest/gtest.h>
#include <plugin/card_plugin_registry.h>
#include <plugin/security_check.h>
#include <smartcard/pcsc_connection.h>

#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

using namespace plugin;

namespace {
std::filesystem::path pluginDir()
{
    return std::filesystem::path(PLUGIN_DIR);
}

// ---------------------------------------------------------------------------
// Hardware integration test infrastructure
// ---------------------------------------------------------------------------

bool g_authFailed = false;

#define SKIP_IF_AUTH_FAILED()                                                                                          \
    if (g_authFailed)                                                                                                  \
    GTEST_SKIP() << "Previous auth failed, skipping to prevent lockout"

struct MRZEnv
{
    std::string docNumber;
    std::string dob;
    std::string expiry;
};

std::optional<MRZEnv> getMRZFromEnv()
{
    auto doc = std::getenv("LIBRESCRS_TEST_MRZ_DOC");
    auto dob = std::getenv("LIBRESCRS_TEST_MRZ_DOB");
    auto exp = std::getenv("LIBRESCRS_TEST_MRZ_EXPIRY");
    if (!doc || !dob || !exp)
        return std::nullopt;
    return MRZEnv{doc, dob, exp};
}

// Helper: find the emrtd plugin from the registry
CardPlugin* findEMRTD(CardPluginRegistry& registry)
{
    for (auto* p : registry.plugins()) {
        if (p->pluginId() == "emrtd")
            return p;
    }
    return nullptr;
}

// Helper: read card via streaming and capture groups in order
struct StreamingResult
{
    CardData data;
    std::vector<std::string> groupOrder;
};

StreamingResult readCardWithStreaming(CardPlugin* plugin, smartcard::PCSCConnection& conn)
{
    StreamingResult result;
    result.data = plugin->readCardStreaming(conn, [&](const std::string& /*cardType*/, const CardFieldGroup& group) {
        result.groupOrder.push_back(group.groupKey);
    });
    return result;
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

// ---------------------------------------------------------------------------
// Hardware integration tests — require physical card reader + eMRTD passport
// Skipped automatically when env vars are not set.
// ---------------------------------------------------------------------------

TEST(EMRTDHardwareTest, PaceMRZEndToEnd)
{
    SKIP_IF_AUTH_FAILED();
    auto mrz = getMRZFromEnv();
    if (!mrz)
        GTEST_SKIP() << "Set LIBRESCRS_TEST_MRZ_DOC, LIBRESCRS_TEST_MRZ_DOB, LIBRESCRS_TEST_MRZ_EXPIRY to run";

    auto readers = smartcard::PCSCConnection::listReaders();
    if (readers.empty())
        GTEST_SKIP() << "No smart card readers found";

    CardPluginRegistry registry;
    registry.loadPluginsFromDirectory(pluginDir());
    auto* emrtd = findEMRTD(registry);
    ASSERT_NE(emrtd, nullptr) << "eMRTD plugin not loaded";

    smartcard::PCSCConnection conn(readers[0]);

    // Set MRZ credentials (per-connection)
    emrtd->setCredentials(conn, "mrz_doc_number", mrz->docNumber);
    emrtd->setCredentials(conn, "mrz_dob", mrz->dob);
    emrtd->setCredentials(conn, "mrz_expiry", mrz->expiry);

    auto result = readCardWithStreaming(emrtd, conn);

    if (result.data.groups.empty()) {
        g_authFailed = true;
        FAIL() << "readCardStreaming returned no groups — authentication likely failed";
    }

    // Verify key groups are present
    EXPECT_NE(result.data.findGroup("personal"), nullptr) << "personal group missing";
    EXPECT_NE(result.data.findGroup("document"), nullptr) << "document group missing";
    EXPECT_NE(result.data.findGroup("photo"), nullptr) << "photo group missing";
    EXPECT_NE(result.data.findGroup("security_status"), nullptr) << "security_status group missing";
}

TEST(EMRTDHardwareTest, PassiveAuthEndToEnd)
{
    SKIP_IF_AUTH_FAILED();
    auto mrz = getMRZFromEnv();
    if (!mrz)
        GTEST_SKIP() << "Set LIBRESCRS_TEST_MRZ_DOC, LIBRESCRS_TEST_MRZ_DOB, LIBRESCRS_TEST_MRZ_EXPIRY to run";

    auto readers = smartcard::PCSCConnection::listReaders();
    if (readers.empty())
        GTEST_SKIP() << "No smart card readers found";

    CardPluginRegistry registry;
    registry.loadPluginsFromDirectory(pluginDir());
    auto* emrtd = findEMRTD(registry);
    ASSERT_NE(emrtd, nullptr);

    smartcard::PCSCConnection conn(readers[0]);

    emrtd->setCredentials(conn, "mrz_doc_number", mrz->docNumber);
    emrtd->setCredentials(conn, "mrz_dob", mrz->dob);
    emrtd->setCredentials(conn, "mrz_expiry", mrz->expiry);

    auto result = readCardWithStreaming(emrtd, conn);

    if (result.data.groups.empty()) {
        g_authFailed = true;
        FAIL() << "readCardStreaming returned no groups";
    }

    // Find security_status group and look for PA SOD signature check
    auto* secGroup = result.data.findGroup("security_status");
    ASSERT_NE(secGroup, nullptr) << "security_status group missing";

    // Look for pa.sod_signature field with PASSED status
    bool foundSodSignature = false;
    for (const auto& field : secGroup->fields) {
        if (field.key == "pa.sod_signature") {
            foundSodSignature = true;
            auto statusStr = field.asString();
            auto status = statusFromString(statusStr);
            EXPECT_EQ(status, SecurityCheck::PASSED) << "PA SOD signature status: " << statusStr;
            break;
        }
    }
    EXPECT_TRUE(foundSodSignature) << "pa.sod_signature field not found in security_status";
}

TEST(EMRTDHardwareTest, ChipAuthEndToEnd)
{
    SKIP_IF_AUTH_FAILED();
    auto mrz = getMRZFromEnv();
    if (!mrz)
        GTEST_SKIP() << "Set LIBRESCRS_TEST_MRZ_DOC, LIBRESCRS_TEST_MRZ_DOB, LIBRESCRS_TEST_MRZ_EXPIRY to run";

    auto readers = smartcard::PCSCConnection::listReaders();
    if (readers.empty())
        GTEST_SKIP() << "No smart card readers found";

    CardPluginRegistry registry;
    registry.loadPluginsFromDirectory(pluginDir());
    auto* emrtd = findEMRTD(registry);
    ASSERT_NE(emrtd, nullptr);

    smartcard::PCSCConnection conn(readers[0]);

    emrtd->setCredentials(conn, "mrz_doc_number", mrz->docNumber);
    emrtd->setCredentials(conn, "mrz_dob", mrz->dob);
    emrtd->setCredentials(conn, "mrz_expiry", mrz->expiry);

    auto result = readCardWithStreaming(emrtd, conn);

    if (result.data.groups.empty()) {
        g_authFailed = true;
        FAIL() << "readCardStreaming returned no groups";
    }

    auto* secGroup = result.data.findGroup("security_status");
    ASSERT_NE(secGroup, nullptr) << "security_status group missing";

    // Check for ca.chip_auth or aa.active_auth — at least one should be
    // PASSED or NOT_SUPPORTED (never FAILED on a genuine document)
    bool foundCA = false;
    bool foundAA = false;
    for (const auto& field : secGroup->fields) {
        if (field.key == "ca.chip_auth") {
            foundCA = true;
            auto status = statusFromString(field.asString());
            EXPECT_NE(status, SecurityCheck::FAILED) << "Chip Authentication reported FAILED on a genuine document";
        } else if (field.key == "aa.active_auth") {
            foundAA = true;
            auto status = statusFromString(field.asString());
            EXPECT_NE(status, SecurityCheck::FAILED) << "Active Authentication reported FAILED on a genuine document";
        }
    }
    EXPECT_TRUE(foundCA || foundAA) << "Neither ca.chip_auth nor aa.active_auth found in security_status";
}

TEST(EMRTDHardwareTest, StreamingGroupOrder)
{
    SKIP_IF_AUTH_FAILED();
    auto mrz = getMRZFromEnv();
    if (!mrz)
        GTEST_SKIP() << "Set LIBRESCRS_TEST_MRZ_DOC, LIBRESCRS_TEST_MRZ_DOB, LIBRESCRS_TEST_MRZ_EXPIRY to run";

    auto readers = smartcard::PCSCConnection::listReaders();
    if (readers.empty())
        GTEST_SKIP() << "No smart card readers found";

    CardPluginRegistry registry;
    registry.loadPluginsFromDirectory(pluginDir());
    auto* emrtd = findEMRTD(registry);
    ASSERT_NE(emrtd, nullptr);

    smartcard::PCSCConnection conn(readers[0]);

    emrtd->setCredentials(conn, "mrz_doc_number", mrz->docNumber);
    emrtd->setCredentials(conn, "mrz_dob", mrz->dob);
    emrtd->setCredentials(conn, "mrz_expiry", mrz->expiry);

    auto result = readCardWithStreaming(emrtd, conn);

    if (result.data.groups.empty()) {
        g_authFailed = true;
        FAIL() << "readCardStreaming returned no groups";
    }

    ASSERT_FALSE(result.groupOrder.empty()) << "No groups delivered via streaming callback";

    // "presence" should arrive before "personal" if both exist
    auto presenceIt = std::find(result.groupOrder.begin(), result.groupOrder.end(), "presence");
    auto personalIt = std::find(result.groupOrder.begin(), result.groupOrder.end(), "personal");
    if (presenceIt != result.groupOrder.end() && personalIt != result.groupOrder.end()) {
        EXPECT_LT(std::distance(result.groupOrder.begin(), presenceIt),
                  std::distance(result.groupOrder.begin(), personalIt))
            << "presence should arrive before personal";
    }

    // "security_status" should be the last group delivered
    auto secIt = std::find(result.groupOrder.begin(), result.groupOrder.end(), "security_status");
    if (secIt != result.groupOrder.end()) {
        EXPECT_EQ(secIt, result.groupOrder.end() - 1) << "security_status should be the last group delivered";
    }
}
