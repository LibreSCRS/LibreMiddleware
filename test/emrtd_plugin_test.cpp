// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <gtest/gtest.h>
#include <LibreSCRS/Plugin/CardPluginService.h>
#include <LibreSCRS/Plugin/SecurityCheck.h>
#include <LibreSCRS/Secure/String.h>
#include <LibreSCRS/SmartCard/CardSession.h>
#include <LibreSCRS/SmartCard/detail/CardSessionInjection.h>
#include <LibreSCRS/SmartCard/detail/Unwrap.h>
#include <pcsc_connection.h>

#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

using namespace LibreSCRS::Plugin;

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
std::shared_ptr<CardPlugin> findEMRTD(CardPluginService& registry)
{
    for (const auto& p : registry.plugins()) {
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

StreamingResult readCardWithStreaming(const std::shared_ptr<CardPlugin>& plugin,
                                      LibreSCRS::SmartCard::CardSession& session)
{
    StreamingResult result;
    auto rr = plugin->readCard(session, [&](const std::string& /*cardType*/, const CardFieldGroup& group) {
        result.groupOrder.push_back(group.groupKey);
    });
    if (rr.data.has_value())
        result.data = std::move(*rr.data);
    return result;
}

} // namespace

TEST(EMRTDPluginTest, LoadsViaRegistry)
{
    CardPluginService registry{pluginDir()};
    EXPECT_GE(registry.size(), 1u);

    std::shared_ptr<CardPlugin> emrtd;
    for (const auto& p : registry.plugins()) {
        if (p->pluginId() == "emrtd") {
            emrtd = p;
            break;
        }
    }
    ASSERT_NE(emrtd, nullptr);
}

TEST(EMRTDPluginTest, Metadata)
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

    EXPECT_EQ(emrtd->pluginId(), "emrtd");
    EXPECT_EQ(emrtd->displayName(), "Electronic Passport (eMRTD)");
    EXPECT_EQ(emrtd->probePriority(), 800);
}

TEST(EMRTDPluginTest, CanHandleAlwaysFalse)
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

    EXPECT_FALSE(emrtd->canHandle(std::vector<uint8_t>{0x3B, 0xFF, 0x94}));
    EXPECT_FALSE(emrtd->canHandle(std::vector<uint8_t>{}));
}

TEST(EMRTDPluginTest, PriorityBetweenDedicatedAndOpenSC)
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

    for (const auto& p : registry.plugins()) {
        if (p->pluginId() == "rs-eid" || p->pluginId() == "vehicle") {
            EXPECT_LT(p->probePriority(), 800);
        }
        // opensc-plugin shares the 800 priority bucket with emrtd;
        // pkcs15-plugin (900) is the generic last-resort fallback.
        if (p->pluginId() == "pkcs15") {
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

    auto readers = LibreSCRS::SmartCard::Internal::PCSCConnection::listReaders();
    if (readers.empty())
        GTEST_SKIP() << "No smart card readers found";

    CardPluginService registry{pluginDir()};
    auto emrtd = findEMRTD(registry);
    ASSERT_NE(emrtd, nullptr) << "eMRTD plugin not loaded";

    auto opened = LibreSCRS::SmartCard::CardSession::open(readers[0]);
    if (!opened.has_value())
        GTEST_SKIP() << "Cannot open CardSession on reader " << readers[0];
    auto session = std::make_shared<LibreSCRS::SmartCard::CardSession>(std::move(*opened));

    // Set MRZ credentials (per-session)
    emrtd->setCredentials(*session, "mrz_doc_number", LibreSCRS::Secure::String{mrz->docNumber});
    emrtd->setCredentials(*session, "mrz_dob", LibreSCRS::Secure::String{mrz->dob});
    emrtd->setCredentials(*session, "mrz_expiry", LibreSCRS::Secure::String{mrz->expiry});

    auto result = readCardWithStreaming(emrtd, *session);

    if (result.data.groups.empty()) {
        g_authFailed = true;
        FAIL() << "readCard returned no groups — authentication likely failed";
    }

    // Verify key groups are present
    EXPECT_TRUE(result.data.findGroup("personal").has_value()) << "personal group missing";
    EXPECT_TRUE(result.data.findGroup("document").has_value()) << "document group missing";
    EXPECT_TRUE(result.data.findGroup("photo").has_value()) << "photo group missing";
    EXPECT_TRUE(result.data.findGroup("security_status").has_value()) << "security_status group missing";
}

TEST(EMRTDHardwareTest, PassiveAuthEndToEnd)
{
    SKIP_IF_AUTH_FAILED();
    auto mrz = getMRZFromEnv();
    if (!mrz)
        GTEST_SKIP() << "Set LIBRESCRS_TEST_MRZ_DOC, LIBRESCRS_TEST_MRZ_DOB, LIBRESCRS_TEST_MRZ_EXPIRY to run";

    auto readers = LibreSCRS::SmartCard::Internal::PCSCConnection::listReaders();
    if (readers.empty())
        GTEST_SKIP() << "No smart card readers found";

    CardPluginService registry{pluginDir()};
    auto emrtd = findEMRTD(registry);
    ASSERT_NE(emrtd, nullptr);

    auto opened = LibreSCRS::SmartCard::CardSession::open(readers[0]);
    if (!opened.has_value())
        GTEST_SKIP() << "Cannot open CardSession on reader " << readers[0];
    auto session = std::make_shared<LibreSCRS::SmartCard::CardSession>(std::move(*opened));

    emrtd->setCredentials(*session, "mrz_doc_number", LibreSCRS::Secure::String{mrz->docNumber});
    emrtd->setCredentials(*session, "mrz_dob", LibreSCRS::Secure::String{mrz->dob});
    emrtd->setCredentials(*session, "mrz_expiry", LibreSCRS::Secure::String{mrz->expiry});

    auto result = readCardWithStreaming(emrtd, *session);

    if (result.data.groups.empty()) {
        g_authFailed = true;
        FAIL() << "readCard returned no groups";
    }

    // Find security_status group and look for PA SOD signature check
    auto secGroupOpt = result.data.findGroup("security_status");
    ASSERT_TRUE(secGroupOpt.has_value()) << "security_status group missing";
    const auto& secGroup = result.data.groupAt(*secGroupOpt);

    // Look for pa.sod_signature field with PASSED status
    bool foundSodSignature = false;
    for (const auto& field : secGroup.fields) {
        if (field.key == "pa.sod_signature") {
            foundSodSignature = true;
            auto statusStrOpt = field.textValue();
            ASSERT_TRUE(statusStrOpt.has_value()) << "pa.sod_signature field is not textual";
            const auto& statusStr = *statusStrOpt;
            auto status = statusFromString(statusStr);
            ASSERT_TRUE(status.has_value()) << "Unrecognized status string: " << statusStr;
            EXPECT_EQ(*status, SecurityCheck::Status::Passed) << "PA SOD signature status: " << statusStr;
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

    auto readers = LibreSCRS::SmartCard::Internal::PCSCConnection::listReaders();
    if (readers.empty())
        GTEST_SKIP() << "No smart card readers found";

    CardPluginService registry{pluginDir()};
    auto emrtd = findEMRTD(registry);
    ASSERT_NE(emrtd, nullptr);

    auto opened = LibreSCRS::SmartCard::CardSession::open(readers[0]);
    if (!opened.has_value())
        GTEST_SKIP() << "Cannot open CardSession on reader " << readers[0];
    auto session = std::make_shared<LibreSCRS::SmartCard::CardSession>(std::move(*opened));

    emrtd->setCredentials(*session, "mrz_doc_number", LibreSCRS::Secure::String{mrz->docNumber});
    emrtd->setCredentials(*session, "mrz_dob", LibreSCRS::Secure::String{mrz->dob});
    emrtd->setCredentials(*session, "mrz_expiry", LibreSCRS::Secure::String{mrz->expiry});

    auto result = readCardWithStreaming(emrtd, *session);

    if (result.data.groups.empty()) {
        g_authFailed = true;
        FAIL() << "readCard returned no groups";
    }

    auto secGroupOpt = result.data.findGroup("security_status");
    ASSERT_TRUE(secGroupOpt.has_value()) << "security_status group missing";
    const auto& secGroup = result.data.groupAt(*secGroupOpt);

    // Check for ca.chip_auth or aa.active_auth — at least one should be
    // PASSED or NOT_SUPPORTED (never FAILED on a genuine document)
    bool foundCA = false;
    bool foundAA = false;
    for (const auto& field : secGroup.fields) {
        auto textOpt = field.textValue();
        if (!textOpt.has_value())
            continue;
        const auto& text = *textOpt;
        if (field.key == "ca.chip_auth") {
            foundCA = true;
            auto status = statusFromString(text);
            ASSERT_TRUE(status.has_value()) << "Unrecognized ca.chip_auth status: " << text;
            EXPECT_NE(*status, SecurityCheck::Status::Failed)
                << "Chip Authentication reported FAILED on a genuine document";
        } else if (field.key == "aa.active_auth") {
            foundAA = true;
            auto status = statusFromString(text);
            ASSERT_TRUE(status.has_value()) << "Unrecognized aa.active_auth status: " << text;
            EXPECT_NE(*status, SecurityCheck::Status::Failed)
                << "Active Authentication reported FAILED on a genuine document";
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

    auto readers = LibreSCRS::SmartCard::Internal::PCSCConnection::listReaders();
    if (readers.empty())
        GTEST_SKIP() << "No smart card readers found";

    CardPluginService registry{pluginDir()};
    auto emrtd = findEMRTD(registry);
    ASSERT_NE(emrtd, nullptr);

    auto opened = LibreSCRS::SmartCard::CardSession::open(readers[0]);
    if (!opened.has_value())
        GTEST_SKIP() << "Cannot open CardSession on reader " << readers[0];
    auto session = std::make_shared<LibreSCRS::SmartCard::CardSession>(std::move(*opened));

    emrtd->setCredentials(*session, "mrz_doc_number", LibreSCRS::Secure::String{mrz->docNumber});
    emrtd->setCredentials(*session, "mrz_dob", LibreSCRS::Secure::String{mrz->dob});
    emrtd->setCredentials(*session, "mrz_expiry", LibreSCRS::Secure::String{mrz->expiry});

    auto result = readCardWithStreaming(emrtd, *session);

    if (result.data.groups.empty()) {
        g_authFailed = true;
        FAIL() << "readCard returned no groups";
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

// ---------------------------------------------------------------------------
// Session-keying regression tests (raw-pointer session key staleness).
//
// These tests don't require hardware — they use the detail-injected detached
// CardSession factory to exercise the plugin's per-session state map without
// any real PC/SC I/O.
// ---------------------------------------------------------------------------

TEST(EmrtdPluginSessionKeying, GenerationBasedKeyPreventsLeak)
{
    CardPluginService registry{pluginDir()};
    auto plugin = findEMRTD(registry);
    ASSERT_NE(plugin, nullptr);

    const std::string reader = "Reader A";
    std::uint64_t genA = 0;

    {
        auto sessionA = LibreSCRS::SmartCard::detail::makeDetachedCardSession(reader);
        ASSERT_NE(sessionA, nullptr);
        genA = LibreSCRS::SmartCard::detail::sessionGeneration(*sessionA);
        EXPECT_GT(genA, 0u) << "live session must have non-zero generation";

        // Populate credentials on sessionA — previously would have leaked
        // through a raw PCSCConnection* key to any successor session the
        // allocator happened to park at the same address.
        plugin->setCredentials(*sessionA, "can", LibreSCRS::Secure::String{"123456"});
    } // sessionA destructs here — shared_ptr drops, PCSCConnection goes away.

    auto sessionB = LibreSCRS::SmartCard::detail::makeDetachedCardSession(reader);
    ASSERT_NE(sessionB, nullptr);
    const auto genB = LibreSCRS::SmartCard::detail::sessionGeneration(*sessionB);

    // Generation counter is strictly monotonic: sessionB must have been
    // assigned a higher generation than sessionA even though both share the
    // same reader name.
    EXPECT_GT(genB, genA) << "successor session must have strictly greater generation";

    // Observable check — a credentials-less session asks for authentication
    // via the `auth_required` group; a session that inherited sessionA's
    // CAN would instead fall through to the `authenticate()` path (which
    // yields an `error` group on a detached PCSCConnection, never an
    // `auth_required`). Presence of `auth_required` therefore proves
    // sessionB did NOT inherit sessionA's credentials.
    auto rr = plugin->readCard(*sessionB);
    ASSERT_TRUE(rr.data.has_value());
    const auto& data = *rr.data;
    EXPECT_TRUE(data.findGroup("auth_required").has_value())
        << "sessionB must see an empty credential slot — reader-name + generation key prevents leak";
    EXPECT_FALSE(data.findGroup("error").has_value())
        << "sessionB must not reach the authenticate() path that implies leaked credentials";
}

TEST(EmrtdPluginSessionKeying, GenerationSurvivesMove)
{
    auto sessionA = LibreSCRS::SmartCard::detail::makeDetachedCardSession("Reader Move");
    ASSERT_NE(sessionA, nullptr);
    const auto originalGen = LibreSCRS::SmartCard::detail::sessionGeneration(*sessionA);
    EXPECT_GT(originalGen, 0u);

    // Move-construct into a fresh CardSession. The moved-to session must
    // preserve the original generation (it owns the same Impl). A moved-from
    // session is out-of-contract for any accessor (UB), matching sibling
    // pimpl-backed classes — no read on *sessionA after the move.
    LibreSCRS::SmartCard::CardSession movedTo{std::move(*sessionA)};

    EXPECT_EQ(LibreSCRS::SmartCard::detail::sessionGeneration(movedTo), originalGen)
        << "moved-to session must retain the original generation";
}
