// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <gtest/gtest.h>
#include <LibreSCRS/Auth/AuthRequirement.h>
#include <LibreSCRS/Auth/CredentialProvider.h>
#include <LibreSCRS/Auth/CredentialResult.h>
#include <LibreSCRS/Auth/PaceSecretKind.h>
#include <LibreSCRS/Plugin/ActivationProfile.h>
#include <LibreSCRS/Plugin/CardPlugin.h>
#include <LibreSCRS/Plugin/CardPluginService.h>
#include <LibreSCRS/Plugin/ReadResult.h>
#include <LibreSCRS/Plugin/SecurityCheck.h>
#include <LibreSCRS/Secure/String.h>
#include <LibreSCRS/SmartCard/CardSession.h>
#include <LibreSCRS/SmartCard/SmProtocolRequest.h>
#include <LibreSCRS/SmartCard/detail/CardSessionInjection.h>
#include <LibreSCRS/SmartCard/detail/Unwrap.h>
#include <LibreSCRS/SecureChannel/BacParams.h>
#include <LibreSCRS/SecureChannel/ChannelErrors.h>
#include <LibreSCRS_internal/Plugin/CardPluginActivationAccessor.h>
#include <LibreSCRS_internal/SmartCard/CardAccessReader.h>
#include <LibreSCRS_internal/SmartCard/PaceDowngradeVerdict.h>
#include <bac.h>
#include <crypto_utils.h>
#include <pace.h>
#include <pcsc_connection.h>
#include <types.h>

#include "chip_auth_fake_chip.h"
#include "emrtd-crypto/synthetic_masterlist.h"

#include <unistd.h> // getpid, for a per-process anchor directory name

#include <algorithm>
#include <array>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
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

// Text of one field of one group, or nullopt when the group, the field, or a
// textual value is missing.
std::optional<std::string> fieldText(const CardData& data, const std::string& groupKey, const std::string& fieldKey)
{
    auto idx = data.findGroup(groupKey);
    if (!idx)
        return std::nullopt;
    for (const auto& field : data.groupAt(*idx).fields) {
        if (field.key == fieldKey)
            return field.textValue();
    }
    return std::nullopt;
}

// --- security_status field shape -------------------------------------------
//
// A verdict group publishes each security check as a FAMILY of separate fields
// keyed `check_<N>_<suffix>` — suffixes `id`, `category`, `status`, `label`,
// `detail`, `error` — rather than as one pre-joined string keyed by the check
// id. `N` is a positional ordinal and nothing more: the order in which the
// plugin appends checks is not a contract, so every assertion below looks a
// check up by its id through checkIndexOf() and none may hardcode `N`. A test
// that pinned the ordinal would break the first time a check is added.

// Split `check_<N>_<suffix>` into ordinal and suffix. Returns nullopt for any
// other key shape — notably the three `overall_*` aggregates, which are not
// part of the per-check family and keep their own keys.
std::optional<std::pair<std::size_t, std::string>> parseCheckKey(const std::string& key)
{
    constexpr std::string_view kPrefix = "check_";
    if (key.compare(0, kPrefix.size(), kPrefix) != 0)
        return std::nullopt;
    const auto sep = key.find('_', kPrefix.size());
    if (sep == std::string::npos || sep == kPrefix.size() || sep + 1 == key.size())
        return std::nullopt;
    std::size_t n = 0;
    const char* first = key.data() + kPrefix.size();
    const char* last = key.data() + sep;
    const auto [ptr, ec] = std::from_chars(first, last, n);
    if (ec != std::errc{} || ptr != last)
        return std::nullopt;
    return std::pair<std::size_t, std::string>{n, key.substr(sep + 1)};
}

// The ordinal of the check whose `check_<N>_id` field carries @p checkId.
std::optional<std::size_t> checkIndexOf(const CardData& data, const std::string& groupKey, const std::string& checkId)
{
    auto idx = data.findGroup(groupKey);
    if (!idx)
        return std::nullopt;
    for (const auto& field : data.groupAt(*idx).fields) {
        const auto parsed = parseCheckKey(field.key);
        if (!parsed || parsed->second != "id")
            continue;
        if (field.textValue().value_or("") == checkId)
            return parsed->first;
    }
    return std::nullopt;
}

// One attribute of the check at ordinal @p n. `detail` and `error` are absent
// when the producer had nothing to say, so a missing field is a verdict too.
std::optional<std::string> checkField(const CardData& data, const std::string& groupKey, std::size_t n,
                                      const std::string& suffix)
{
    return fieldText(data, groupKey, "check_" + std::to_string(n) + "_" + suffix);
}

// Sets an environment variable for a scope and puts back exactly what was
// there. Every case in this file runs in one process, so a variable left set
// would decide the outcome of whatever ran next.
class ScopedEnv
{
public:
    ScopedEnv(const char* name, const std::string& value) : name_(name)
    {
        if (const char* had = ::getenv(name))
            previous_ = std::string(had);
        ::setenv(name, value.c_str(), 1);
    }
    ~ScopedEnv()
    {
        if (previous_)
            ::setenv(name_, previous_->c_str(), 1);
        else
            ::unsetenv(name_);
    }
    ScopedEnv(const ScopedEnv&) = delete;
    ScopedEnv& operator=(const ScopedEnv&) = delete;

private:
    const char* name_;
    std::optional<std::string> previous_;
};

// A directory in the shape the agent's anchor cache really has on disk: one
// DER-encoded certificate per file, named `000000.cer` upward, nothing else in
// it. Removed when the object dies.
//
// Deliberately NOT the fixture's writePemDir(). PEM is what the crypto-layer
// tests feed the loader, and a channel proven only against PEM would leave
// untried the exact bytes the field failure was measured against -- five DER
// `.cer` files a person had really imported, which the badge said were not
// there.
class DerAnchorDir
{
public:
    DerAnchorDir(const std::string& stem, const std::vector<std::vector<std::uint8_t>>& certsDer)
        : dir_(std::filesystem::temp_directory_path() /
               ("librescrs-anchors-" + stem + "-" + std::to_string(::getpid())))
    {
        std::error_code ec;
        std::filesystem::remove_all(dir_, ec);
        std::filesystem::create_directories(dir_);
        for (std::size_t i = 0; i < certsDer.size(); ++i) {
            std::string name(6, '0');
            const std::string n = std::to_string(i);
            name.replace(name.size() - n.size(), n.size(), n);
            std::ofstream out(dir_ / (name + ".cer"), std::ios::binary | std::ios::trunc);
            out.write(reinterpret_cast<const char*>(certsDer[i].data()),
                      static_cast<std::streamsize>(certsDer[i].size()));
        }
    }
    ~DerAnchorDir()
    {
        std::error_code ec;
        std::filesystem::remove_all(dir_, ec);
    }
    DerAnchorDir(const DerAnchorDir&) = delete;
    DerAnchorDir& operator=(const DerAnchorDir&) = delete;

    [[nodiscard]] const std::filesystem::path& path() const
    {
        return dir_;
    }

private:
    std::filesystem::path dir_;
};

// Every check id present in @p groupKey, in emission order.
std::vector<std::string> checkIds(const CardData& data, const std::string& groupKey)
{
    std::vector<std::string> ids;
    auto idx = data.findGroup(groupKey);
    if (!idx)
        return ids;
    for (const auto& field : data.groupAt(*idx).fields) {
        const auto parsed = parseCheckKey(field.key);
        if (parsed && parsed->second == "id") {
            if (auto text = field.textValue())
                ids.push_back(*text);
        }
    }
    return ids;
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

    // Find security_status group and look for the PA SOD signature check.
    ASSERT_TRUE(result.data.findGroup("security_status").has_value()) << "security_status group missing";

    // Located by check id, never by ordinal — the emission order is not a
    // contract. Its status is its own field, so the value is the bare token.
    const auto sodIdx = checkIndexOf(result.data, "security_status", "pa_sod_signature");
    ASSERT_TRUE(sodIdx.has_value()) << "pa_sod_signature check not found in security_status";
    const auto statusStrOpt = checkField(result.data, "security_status", *sodIdx, "status");
    ASSERT_TRUE(statusStrOpt.has_value()) << "pa_sod_signature check has no textual status field";
    const auto status = statusFromString(*statusStrOpt);
    ASSERT_TRUE(status.has_value()) << "Unrecognized status string: " << *statusStrOpt;
    EXPECT_EQ(*status, SecurityCheck::Status::Passed) << "PA SOD signature status: " << *statusStrOpt;
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

    ASSERT_TRUE(result.data.findGroup("security_status").has_value()) << "security_status group missing";

    // Check for chip_auth or active_auth — at least one should be present, and
    // whichever is present must be PASSED or NOT_SUPPORTED (never FAILED on a
    // genuine document). Both are looked up by id; neither ordinal is pinned.
    const auto caIdx = checkIndexOf(result.data, "security_status", "chip_auth");
    const auto aaIdx = checkIndexOf(result.data, "security_status", "active_auth");
    auto notFailed = [&result](std::size_t n, const char* what) {
        const auto text = checkField(result.data, "security_status", n, "status");
        ASSERT_TRUE(text.has_value()) << what << " check has no textual status field";
        const auto status = statusFromString(*text);
        ASSERT_TRUE(status.has_value()) << "Unrecognized " << what << " status: " << *text;
        EXPECT_NE(*status, SecurityCheck::Status::Failed) << what << " reported FAILED on a genuine document";
    };
    if (caIdx.has_value())
        notFailed(*caIdx, "Chip Authentication");
    if (aaIdx.has_value())
        notFailed(*aaIdx, "Active Authentication");
    EXPECT_TRUE(caIdx.has_value() || aaIdx.has_value()) << "Neither chip_auth nor active_auth found in security_status";
}

// PACE-CAN end-to-end: reads a contactless eMRTD via PACE keyed on the CAN,
// exercising the Chip Authentication SM-path proof exchange on real hardware.
// Set LIBRESCRS_TEST_CAN (and optionally LIBRESCRS_TEST_READER_INDEX) to run.
TEST(EMRTDHardwareTest, PaceCanEndToEnd)
{
    SKIP_IF_AUTH_FAILED();
    const char* can = std::getenv("LIBRESCRS_TEST_CAN");
    if (can == nullptr || *can == '\0')
        GTEST_SKIP() << "Set LIBRESCRS_TEST_CAN to run";

    auto readers = LibreSCRS::SmartCard::Internal::PCSCConnection::listReaders();
    if (readers.empty())
        GTEST_SKIP() << "No smart card readers found";

    std::size_t idx = 0;
    if (const char* r = std::getenv("LIBRESCRS_TEST_READER_INDEX"))
        idx = static_cast<std::size_t>(std::atoi(r));
    if (idx >= readers.size())
        GTEST_SKIP() << "reader index out of range";

    CardPluginService registry{pluginDir()};
    auto emrtd = findEMRTD(registry);
    ASSERT_NE(emrtd, nullptr);

    auto opened = LibreSCRS::SmartCard::CardSession::open(readers[idx]);
    if (!opened.has_value())
        GTEST_SKIP() << "Cannot open CardSession on reader " << readers[idx];
    auto session = std::make_shared<LibreSCRS::SmartCard::CardSession>(std::move(*opened));

    // Deposit the CAN AFTER canHandleConnection: the discovery probe erases any
    // predecessor plugin-session state for this reader, which would drop a CAN
    // deposited before it.
    ASSERT_TRUE(emrtd->canHandleConnection({}, *session));
    emrtd->setCredentials(*session, "can", LibreSCRS::Secure::String{std::string{can}});

    auto result = readCardWithStreaming(emrtd, *session);
    if (result.data.groups.empty()) {
        g_authFailed = true;
        FAIL() << "readCard returned no groups (PACE-CAN failed?)";
    }

    // Print only the verdict-bearing fields (never the personal data groups):
    // the SM-path Chip Authentication verdict is what this run is proving.
    // The `overall_*` aggregates keep their own keys; a check's attributes are
    // separate fields, reached through its id and never through its ordinal.
    const auto authMethod = fieldText(result.data, "presence", "auth_method");
    const auto dataGroups = fieldText(result.data, "presence", "data_groups");
    const auto overallAuthenticity = fieldText(result.data, "security_status", "overall_authenticity");
    const auto caIdx = checkIndexOf(result.data, "security_status", "chip_auth");
    const auto cscaIdx = checkIndexOf(result.data, "security_status", "pa_csca_chain");
    std::optional<std::string> chipAuth;
    std::optional<std::string> cscaChain;
    std::optional<std::string> cscaChainReason;
    if (caIdx.has_value())
        chipAuth = checkField(result.data, "security_status", *caIdx, "status");
    if (cscaIdx.has_value()) {
        cscaChain = checkField(result.data, "security_status", *cscaIdx, "status");
        // `reason`, not `detail`: the CSCA check's English sentence was
        // replaced by a translation key, and on a real card the key is the
        // thing worth reading -- it names which of the six situations the run
        // landed in.
        cscaChainReason = checkField(result.data, "security_status", *cscaIdx, "reason");
    }
    std::cout << "data_groups           = " << dataGroups.value_or("<none>") << "\n";
    std::cout << "auth_method           = " << authMethod.value_or("<none>") << "\n";
    std::cout << "chip_auth             = " << chipAuth.value_or("<none>") << "\n";
    std::cout << "overall_authenticity  = " << overallAuthenticity.value_or("<none>") << "\n";
    std::cout << "pa_csca_chain         = " << cscaChain.value_or("<none>") << "\n";
    std::cout << "pa_csca_chain reason  = " << cscaChainReason.value_or("<none>") << "\n";

    // Honest authenticity: with no CSCA anchors configured the chain check is
    // NOT_PERFORMED, so the authenticity aggregate must NOT read PASSED — the
    // signer is unanchored. That is the only state this build can be in: there
    // is no way to configure anchors yet, and deliberately no way to name them
    // from the environment. The status field carries the bare token, so this
    // compares exactly where the joined shape could only test a prefix.
    if (cscaChain && *cscaChain == "NOT_PERFORMED")
        EXPECT_NE(overallAuthenticity.value_or(""), "PASSED")
            << "authenticity claimed PASSED without a verified CSCA chain";

    // A genuine document must never report CA/AA FAILED. On a DG14-bearing card
    // read via PACE, Chip Authentication runs over the SM tunnel and its
    // verdict is only PASSED because the post-key-change proof exchange
    // succeeded — the whole point of the 4.4 change.
    if (chipAuth)
        EXPECT_NE(*chipAuth, "FAILED") << "chip_auth FAILED on a genuine card";
}

// Every advertised data group the plugin can parse must come out of a PACE-CAN
// read as its own group. The failure this pins: an EAC-protected DG (DG3) has
// no Terminal Authentication available, and on the SRB-eID-V2.00 family its
// SM SELECT is answered with 6988 AND the card then kills the SM session — so
// every LATER file (DG11, DG12, the national annex) died collaterally with
// 6F02, silently: the holder saw a read that "worked" minus their address and
// issuing data. The EAC-protected pair must instead surface as "EAC required"
// without an on-card attempt while the rest of the advertised set survives.
// Set LIBRESCRS_TEST_CAN (and optionally LIBRESCRS_TEST_READER_INDEX) to run.
TEST(EMRTDHardwareTest, PaceCanAdvertisedReadableGroupsAllArrive)
{
    SKIP_IF_AUTH_FAILED();
    const char* can = std::getenv("LIBRESCRS_TEST_CAN");
    if (can == nullptr || *can == '\0')
        GTEST_SKIP() << "Set LIBRESCRS_TEST_CAN to run";

    auto readers = LibreSCRS::SmartCard::Internal::PCSCConnection::listReaders();
    if (readers.empty())
        GTEST_SKIP() << "No smart card readers found";

    std::size_t idx = 0;
    if (const char* r = std::getenv("LIBRESCRS_TEST_READER_INDEX"))
        idx = static_cast<std::size_t>(std::atoi(r));
    if (idx >= readers.size())
        GTEST_SKIP() << "reader index out of range";

    CardPluginService registry{pluginDir()};
    auto emrtd = findEMRTD(registry);
    ASSERT_NE(emrtd, nullptr);

    auto opened = LibreSCRS::SmartCard::CardSession::open(readers[idx]);
    if (!opened.has_value())
        GTEST_SKIP() << "Cannot open CardSession on reader " << readers[idx];
    auto session = std::make_shared<LibreSCRS::SmartCard::CardSession>(std::move(*opened));

    ASSERT_TRUE(emrtd->canHandleConnection({}, *session));
    emrtd->setCredentials(*session, "can", LibreSCRS::Secure::String{std::string{can}});

    auto result = readCardWithStreaming(emrtd, *session);
    if (result.data.groups.empty()) {
        g_authFailed = true;
        FAIL() << "readCard returned no groups (PACE-CAN failed?)";
    }

    std::optional<std::string> dataGroups;
    std::vector<std::string> groupKeys;
    for (const auto& g : result.data.groups) {
        groupKeys.push_back(g.groupKey);
        for (const auto& f : g.fields) {
            if (g.groupKey == "presence" && f.key == "data_groups")
                dataGroups = f.textValue();
        }
    }
    ASSERT_TRUE(dataGroups.has_value()) << "presence group carries no data_groups list";

    const auto advertised = [&](int dg) { return dataGroups->find("DG" + std::to_string(dg)) != std::string::npos; };
    const auto haveGroup = [&](const char* key) {
        return std::find(groupKeys.begin(), groupKeys.end(), std::string{key}) != groupKeys.end();
    };

    // Parsed, PACE-readable DGs: advertised -> the group must have arrived.
    if (advertised(1)) {
        EXPECT_TRUE(haveGroup("personal")) << "DG1 advertised but the personal group is missing";
        EXPECT_TRUE(haveGroup("document")) << "DG1 advertised but the document group is missing";
    }
    if (advertised(2))
        EXPECT_TRUE(haveGroup("photo")) << "DG2 advertised but the photo group is missing";
    if (advertised(5))
        EXPECT_TRUE(haveGroup("portrait")) << "DG5 advertised but the portrait group is missing";
    if (advertised(7))
        EXPECT_TRUE(haveGroup("signature")) << "DG7 advertised but the signature group is missing";
    if (advertised(11))
        EXPECT_TRUE(haveGroup("additional")) << "DG11 advertised but the additional group is missing";
    if (advertised(12))
        EXPECT_TRUE(haveGroup("document_extra")) << "DG12 advertised but the issuing group is missing";
    if (advertised(13))
        EXPECT_TRUE(haveGroup("national")) << "DG13 advertised but the national group is missing";

    // EAC-protected pair: advertised -> surfaced honestly as gated, never
    // silently dropped (and, per the root cause above, never SELECTed under
    // SM in the first place — the collateral assertion is the set above).
    if (advertised(3))
        EXPECT_TRUE(haveGroup("biometric_fingerprint")) << "DG3 advertised but not surfaced as EAC-gated";
    if (advertised(4))
        EXPECT_TRUE(haveGroup("biometric_iris")) << "DG4 advertised but not surfaced as EAC-gated";
}

// Contact plain read: a dual-interface document whose LDS is readable in plain
// on the contact interface exercises the plain->Chip-Authentication->SM upgrade
// on real hardware — the path unit tests cover with a synthetic ECDH chip. No
// credential is deposited: the discovery probe decides plain-readability.
// Set LIBRESCRS_TEST_CONTACT_READER_INDEX to the CONTACT reader to run.
TEST(EMRTDHardwareTest, ContactPlainReadChipAuthEndToEnd)
{
    SKIP_IF_AUTH_FAILED();
    const char* ridx = std::getenv("LIBRESCRS_TEST_CONTACT_READER_INDEX");
    if (ridx == nullptr || *ridx == '\0')
        GTEST_SKIP() << "Set LIBRESCRS_TEST_CONTACT_READER_INDEX to run";

    auto readers = LibreSCRS::SmartCard::Internal::PCSCConnection::listReaders();
    const std::size_t idx = static_cast<std::size_t>(std::atoi(ridx));
    if (idx >= readers.size())
        GTEST_SKIP() << "reader index out of range";

    CardPluginService registry{pluginDir()};
    auto emrtd = findEMRTD(registry);
    ASSERT_NE(emrtd, nullptr);

    auto opened = LibreSCRS::SmartCard::CardSession::open(readers[idx]);
    if (!opened.has_value())
        GTEST_SKIP() << "Cannot open CardSession on reader " << readers[idx];
    auto session = std::make_shared<LibreSCRS::SmartCard::CardSession>(std::move(*opened));

    // No CAN/MRZ: the discovery probe caches plain-readability, and the read
    // takes the plain path (and, if plain-readable, the CA upgrade).
    if (!emrtd->canHandleConnection({}, *session))
        GTEST_SKIP() << "eMRTD applet not present on this reader";

    auto result = readCardWithStreaming(emrtd, *session);
    if (result.data.groups.empty())
        GTEST_SKIP() << "no groups (card not plain-readable on contact — needs PACE)";

    const auto authMethod = fieldText(result.data, "presence", "auth_method");
    const auto dataGroups = fieldText(result.data, "presence", "data_groups");
    const bool hasAuthRequired = result.data.findGroup("auth_required").has_value();
    // Located by check id; the status is its own field, so no prose to parse.
    const auto caIdx = checkIndexOf(result.data, "security_status", "chip_auth");
    std::optional<std::string> chipAuth;
    if (caIdx.has_value())
        chipAuth = checkField(result.data, "security_status", *caIdx, "status");
    if (hasAuthRequired)
        GTEST_SKIP() << "card is not plain-readable on this interface (auth_required) — needs PACE";

    std::cout << "data_groups = " << dataGroups.value_or("<none>") << "\n";
    std::cout << "auth_method = " << authMethod.value_or("<none>") << "\n";
    std::cout << "chip_auth   = " << chipAuth.value_or("<none>") << "\n";

    // The read went plain. Either the card raised the channel to Chip
    // Authentication (auth_method "Chip Authentication", chip_auth not FAILED),
    // or it refused the protocol on the plain channel (auth_method "None (plain
    // read)", chip_auth NOT_PERFORMED) — never FAILED on a genuine card.
    if (chipAuth)
        EXPECT_NE(*chipAuth, "FAILED") << "chip_auth FAILED on a genuine card";
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

// ---------------------------------------------------------------------------
// Interface-aware activation tests (scripted LDS rig, no hardware).
//
// A TransmitFilter on a detached session simulates the LDS access rules of a
// dual-interface eMRTD document:
//  - plainLds=true mirrors the CONTACT interface: SELECT/READ of EF.COM and
//    the identity data groups succeed in plain (access condition "Always");
//    EF.SOD stays SM-gated (6982), as observed on shipping documents.
//  - plainLds=false mirrors the CONTACTLESS interface: every LDS SELECT under
//    the applet returns 6982 — PACE is required before any read.
// Non-LDS instructions (MSE SET AT 0x22, GENERAL AUTHENTICATE 0x86, ...)
// return 6D00, so an attempted SM activation fails visibly and every APDU is
// recorded in the rig log for no-PACE assertions.
// ---------------------------------------------------------------------------

namespace {

using LibreSCRS::SmartCard::Internal::APDUCommand;
using LibreSCRS::SmartCard::Internal::APDUResponse;

const std::vector<uint8_t> kEmrtdAidBytes = {0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01};
// A second applet on the rig (any non-eMRTD AID): lets tests install a
// foreign-bound plain channel on the session, as a sibling plugin would.
const std::vector<uint8_t> kSiblingAidBytes = {0xA0, 0x00, 0x00, 0x00, 0x63, 0x50, 0x4B};

// EF.COM: LDS version 0108, unicode 040000, tag list = DG1 (0x61) + DG14 (0x6E).
std::vector<uint8_t> comFixture()
{
    return {0x60, 0x14, 0x5F, 0x01, 0x04, '0', '1', '0',  '8',  0x5F, 0x36,
            0x06, '0',  '4',  '0',  '0',  '0', '0', 0x5C, 0x02, 0x61, 0x6E};
}

// DG1 carrying the ICAO 9303 TD3 specimen MRZ (UTO / ERIKSSON / L898902C3).
std::vector<uint8_t> dg1Fixture()
{
    const std::string mrz = "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<"
                            "L898902C36UTO7408122F1204159ZE184226B<<<<<10";
    std::vector<uint8_t> dg1 = {0x61, static_cast<uint8_t>(3 + mrz.size()), 0x5F, 0x1F,
                                static_cast<uint8_t>(mrz.size())};
    dg1.insert(dg1.end(), mrz.begin(), mrz.end());
    return dg1;
}

// EF.SOD as a card carries it: the CMS SignedData wrapped in the application
// tag 0x77, with a BER length. Real documents wrap it; the reader's own TLV
// walk reads the outer length to know when the file has been read out, so a
// bare CMS would exercise a shape no card produces.
std::vector<uint8_t> sodFixture(const std::vector<uint8_t>& cms)
{
    std::vector<uint8_t> ef{0x77};
    if (cms.size() < 0x80) {
        ef.push_back(static_cast<uint8_t>(cms.size()));
    } else if (cms.size() <= 0xFF) {
        ef.push_back(0x81);
        ef.push_back(static_cast<uint8_t>(cms.size()));
    } else {
        ef.push_back(0x82);
        ef.push_back(static_cast<uint8_t>((cms.size() >> 8) & 0xFF));
        ef.push_back(static_cast<uint8_t>(cms.size() & 0xFF));
    }
    ef.insert(ef.end(), cms.begin(), cms.end());
    return ef;
}

// Scripted EF.CardAccess behaviour for the MF-scoped capability probe.
// The default SoftFail keeps every pre-existing rig test byte-for-byte
// identical: those tests never emit an MF-scoped (P1=0x00) SELECT, so the
// knob is inert for them. A test that wants a definitive verdict MUST set
// the knob explicitly — an unset knob asserts Unknown, not Absent.
enum class CardAccessMode {
    AbsentNotFound, // MF ok; SELECT 011C -> 6A82 (definitive absence)
    Deactivated,    // MF ok; SELECT 011C -> 6283 (file deactivated: definitive
                    // absence; the reader must NOT attempt READ BINARY —
                    // the rig fails the poison counter if it does)
    Terminated6285, // MF ok; SELECT 011C -> 6285 (termination warning: NOT
                    // definitive; the reader proceeds to READ, which fails)
    PresentPace,    // MF ok; 011C holds a valid PACEInfo (PACE-CAN OID)
    PresentNoPace,  // MF ok; 011C holds a well-formed CardAccess, zero PACEInfo
    MalformedData,  // MF ok; 011C read ok but first byte != 0x31 (junk)
    Truncated,      // MF ok; 011C outer BER length > returned bytes
    SoftFail        // MF selection chain fails 6982 (rig default)
};

// A minimal EF.CardAccess: a SecurityInfos SET (0x31) carrying one PACEInfo
// SEQUENCE whose first element is the standard PACE-ECDH-GM-AES-CBC-CMAC-128
// OID (0.4.0.127.0.7.2.2.4.2.2). emrtd::crypto::parseCardAccess is the OID
// oracle; PaceOracleAccepts* assertions feed it this fixture before any
// Present verdict relies on it.
std::vector<uint8_t> presentPaceCardAccess()
{
    return {0x31, 0x11,                                                 // SET, 17 content bytes
            0x30, 0x0F,                                                 // SEQUENCE (PACEInfo), 15 content bytes
            0x06, 0x0A, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, // OID PACE-ECDH-GM-AES-CBC-CMAC-128
            0x02, 0x02,                                                 // ...OID tail
            0x02, 0x01, 0x02};                                          // INTEGER version = 2
}

// A well-formed EF.CardAccess SET whose single SecurityInfo carries a
// NON-PACE OID (Chip Authentication 0.4.0.127.0.7.2.2.3.2.1): a definitive
// "PACE not offered" document, NOT an anomaly. parseCardAccess yields zero
// PACE OIDs -> Absent.
std::vector<uint8_t> presentNoPaceCardAccess()
{
    return {0x31, 0x11,                                                 // SET, 17 content bytes
            0x30, 0x0F,                                                 // SEQUENCE, 15 content bytes
            0x06, 0x0A, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x03, // OID id-CA-ECDH (non-PACE)
            0x02, 0x01,                                                 // ...OID tail
            0x02, 0x01, 0x01};                                          // INTEGER version = 1
}

struct LdsRigState
{
    bool plainLds = true;
    // EF.SOD is SM-gated on this rig whatever @ref plainLds says, because that
    // is what shipping documents do -- so no test reaches passive
    // authentication unless it asks. A test that wants the passive-auth path
    // sets this and puts a real security object in files[0x011D]; leaving it
    // false keeps every other rig test byte-for-byte as it was.
    bool plainSod = false;
    std::vector<APDUCommand> log;
    std::map<uint16_t, std::vector<uint8_t>> files;
    const std::vector<uint8_t>* current = nullptr;
    // MF-scoped EF.CardAccess model. @ref cardAccessData holds the
    // EF.CardAccess bytes served for Present*/Malformed/Truncated modes.
    CardAccessMode cardAccess = CardAccessMode::SoftFail;
    std::vector<uint8_t> cardAccessData;
    // Poison counter for the Deactivated mode: a READ BINARY issued while the
    // deactivated EF.CardAccess is the immediately-preceding selection is a
    // contract violation (content of a deactivated file must never be read) —
    // tests assert this stays 0. Any subsequent SELECT clears the arming.
    int deactivatedReadAttempts = 0;
    bool deactivatedSelectArmed = false;
};

APDUResponse ldsRigTransmit(LdsRigState& st, const APDUCommand& cmd)
{
    st.log.push_back(cmd);
    auto ok = [](std::vector<uint8_t> d = {}) { return APDUResponse{std::move(d), 0x90, 0x00}; };
    auto sw = [](uint8_t a, uint8_t b) { return APDUResponse{{}, a, b}; };

    // Any SELECT disarms the deactivated-read poison; only the 6283 return
    // below re-arms it, so the counter names exactly the forbidden
    // read-right-after-deactivated-select shape.
    if (cmd.ins == 0xA4)
        st.deactivatedSelectArmed = false;

    if (cmd.ins == 0xA4 && cmd.p1 == 0x04) { // SELECT by AID
        st.current = nullptr;
        // The eMRTD applet and one generic sibling applet exist on the rig
        // (dual-applet documents); anything else is absent.
        if (cmd.data == kEmrtdAidBytes || cmd.data == kSiblingAidBytes)
            return ok();
        return sw(0x6A, 0x82);
    }
    if (cmd.ins == 0xA4 && cmd.p1 == 0x00) { // SELECT by FID (MF-scoped: EF.CardAccess probe)
        // The MF-scoped EF.CardAccess reader (readCardAccessDetailed) emits
        // SELECT 3F00 -> SELECT 011C -> plain READ BINARY, all P1=0x00.
        // EF.CardAccess is unprotected by construction, so 011C stays
        // pre-auth readable here even on contactless (carved out of the
        // whole-LDS SM gate the P1=0x02 branch applies below).
        if (cmd.data.size() != 2)
            return sw(0x6A, 0x86);
        if (st.cardAccess == CardAccessMode::SoftFail)
            return sw(0x69, 0x82); // MF selection chain fails (rig default)
        const uint16_t fid = static_cast<uint16_t>((cmd.data[0] << 8) | cmd.data[1]);
        if (fid == 0x3F00) { // master file
            st.current = nullptr;
            return ok();
        }
        if (fid == 0x011C) { // EF.CardAccess at MF
            if (st.cardAccess == CardAccessMode::AbsentNotFound) {
                st.current = nullptr;
                return sw(0x6A, 0x82); // definitive absence
            }
            if (st.cardAccess == CardAccessMode::Deactivated) {
                st.current = nullptr;
                st.deactivatedSelectArmed = true;
                return sw(0x62, 0x83); // file deactivated (both select variants)
            }
            if (st.cardAccess == CardAccessMode::Terminated6285) {
                st.current = nullptr;
                return sw(0x62, 0x85); // termination warning: NOT definitive
            }
            st.current = &st.cardAccessData;
            return ok();
        }
        return sw(0x6A, 0x82); // any other MF-scoped FID: absent
    }
    if (cmd.ins == 0xA4 && cmd.p1 == 0x02) { // SELECT EF by FID
        // Model the ISO 7816-4 behavior real card OSes exhibit: a FAILED
        // SELECT leaves the previously selected file current — only a
        // successful SELECT moves the current-EF pointer.
        if (cmd.data.size() != 2)
            return sw(0x6A, 0x86);
        const uint16_t fid = static_cast<uint16_t>((cmd.data[0] << 8) | cmd.data[1]);
        auto it = st.files.find(fid);
        if (it == st.files.end())
            return sw(0x6A, 0x82);
        // Whole LDS SM-gated on contactless; EF.SOD SM-gated on top of that
        // unless a test has asked for it in plain.
        if (!st.plainLds || (fid == 0x011D && !st.plainSod))
            return sw(0x69, 0x82);
        st.current = &it->second;
        return ok();
    }
    if (cmd.ins == 0xB0) { // READ BINARY
        if (st.deactivatedSelectArmed) {
            // Forbidden shape: reading a file the chip just declared
            // deactivated. Count it (tests assert 0) and fail the read.
            ++st.deactivatedReadAttempts;
            return sw(0x69, 0x85);
        }
        if (cmd.p1 & 0x80) // short-FID read (EF.CardAccess probe): not present on the rig
            return sw(0x69, 0x82);
        if (st.current == nullptr)
            return sw(0x69, 0x86);
        const size_t off = (static_cast<size_t>(cmd.p1 & 0x7F) << 8) | cmd.p2;
        if (off >= st.current->size())
            return sw(0x6B, 0x00);
        const size_t n = std::min<size_t>(256, st.current->size() - off);
        return ok(
            {st.current->begin() + static_cast<ptrdiff_t>(off), st.current->begin() + static_cast<ptrdiff_t>(off + n)});
    }
    return sw(0x6D, 0x00); // any SM/PACE instruction: unsupported on the rig
}

std::shared_ptr<LdsRigState> installLdsRig(LibreSCRS::SmartCard::CardSession& session, bool plainLds,
                                           bool plainSod = false)
{
    auto st = std::make_shared<LdsRigState>();
    st->plainLds = plainLds;
    st->plainSod = plainSod;
    st->files[0x011E] = comFixture();
    st->files[0x0101] = dg1Fixture();
    st->files[0x010E] = {0x6E, 0x03, 0x31, 0x01, 0x00}; // DG14 stub (raw bytes only)
    st->files[0x011D] = {0x77, 0x01, 0x00};             // EF.SOD present but SM-gated
    LibreSCRS::SmartCard::detail::unwrap(session).setTransmitFilter(
        [st](const APDUCommand& cmd) { return ldsRigTransmit(*st, cmd); });
    return st;
}

// Arm the MF-scoped EF.CardAccess model for a given verdict. Loads the
// EF.CardAccess bytes the READ BINARY at MF returns (empty for the
// absent/soft-fail modes, which never reach a read).
void setCardAccessMode(LdsRigState& st, CardAccessMode mode)
{
    st.cardAccess = mode;
    switch (mode) {
    case CardAccessMode::PresentPace:
        st.cardAccessData = presentPaceCardAccess();
        break;
    case CardAccessMode::PresentNoPace:
        st.cardAccessData = presentNoPaceCardAccess();
        break;
    case CardAccessMode::MalformedData:
        st.cardAccessData = {0x30, 0x03, 0x02, 0x01, 0x00}; // a SEQUENCE, not a SET (first byte != 0x31)
        break;
    case CardAccessMode::Truncated:
        st.cardAccessData = {0x31, 0x82, 0x01, 0x00, 0x30, 0x03}; // declares 256 content bytes, 6 present
        break;
    case CardAccessMode::AbsentNotFound:
    case CardAccessMode::Deactivated:
    case CardAccessMode::Terminated6285:
    case CardAccessMode::SoftFail:
        st.cardAccessData.clear();
        break;
    }
}

bool logContainsIns(const LdsRigState& st, uint8_t ins)
{
    return std::any_of(st.log.begin(), st.log.end(), [ins](const APDUCommand& c) { return c.ins == ins; });
}

bool logContainsSelectFid(const LdsRigState& st, uint16_t fid)
{
    return std::any_of(st.log.begin(), st.log.end(), [fid](const APDUCommand& c) {
        return c.ins == 0xA4 && c.p1 == 0x02 && c.data.size() == 2 &&
               static_cast<uint16_t>((c.data[0] << 8) | c.data[1]) == fid;
    });
}

// MF-scoped (P1=0x00) SELECT of @p fid — the shape the EF.CardAccess reader
// emits for SELECT 3F00 / SELECT 011C.
bool logContainsMfScopedSelect(const LdsRigState& st, uint16_t fid)
{
    return std::any_of(st.log.begin(), st.log.end(), [fid](const APDUCommand& c) {
        return c.ins == 0xA4 && c.p1 == 0x00 && c.data.size() == 2 &&
               static_cast<uint16_t>((c.data[0] << 8) | c.data[1]) == fid;
    });
}

template <typename Pred>
std::optional<size_t> logIndexOfFirst(const LdsRigState& st, Pred pred)
{
    for (size_t i = 0; i < st.log.size(); ++i)
        if (pred(st.log[i]))
            return i;
    return std::nullopt;
}

template <typename Pred>
std::optional<size_t> logIndexOfLast(const LdsRigState& st, Pred pred)
{
    for (size_t i = st.log.size(); i-- > 0;)
        if (pred(st.log[i]))
            return i;
    return std::nullopt;
}

} // namespace

TEST(EmrtdInterfaceActivation, ContactWithProviderReadsIdentityWithoutPace)
{
    CardPluginService registry{pluginDir()};
    auto plugin = findEMRTD(registry);
    ASSERT_NE(plugin, nullptr);

    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("Scripted Contact Reader");
    ASSERT_NE(session, nullptr);
    auto rig = installLdsRig(*session, /*plainLds=*/true);

    bool providerInvoked = false;
    session->setCredentialProvider([&providerInvoked](const LibreSCRS::Auth::AuthRequirement&) {
        providerInvoked = true;
        return LibreSCRS::Auth::CredentialResult::cancelled();
    });

    // Discovery probe (the production sequence) caches plain-readability.
    ASSERT_TRUE(plugin->canHandleConnection({}, *session));

    auto rr = plugin->readCard(*session);
    EXPECT_EQ(rr.status, ReadResult::Status::Ok);
    ASSERT_TRUE(rr.data.has_value());
    EXPECT_TRUE(rr.data->findGroup("personal").has_value()) << "identity must be read plain on contact";
    EXPECT_FALSE(rr.data->findGroup("auth_required").has_value());
    EXPECT_EQ(fieldText(*rr.data, "personal", "surname").value_or(""), "ERIKSSON");

    EXPECT_FALSE(providerInvoked) << "no CAN prompt may reach the provider on the contact interface";
    EXPECT_FALSE(logContainsIns(*rig, 0x22)) << "MSE SET AT transmitted — PACE was wrongly attempted";
    EXPECT_FALSE(logContainsIns(*rig, 0x86)) << "GENERAL AUTHENTICATE transmitted — PACE was wrongly attempted";
}

// A genuineness check is emitted only when the document carries the data group
// its capability lives in: chip_auth iff DG14, active_auth iff DG15. This rig's
// COM lists DG1 + DG14 and no DG15, so the security view must show a chip_auth
// row and NO active_auth row — an absent capability is not a not-performed
// check.
TEST(EmrtdInterfaceActivation, SecurityChecksTrackDataGroupPresence)
{
    CardPluginService registry{pluginDir()};
    auto plugin = findEMRTD(registry);
    ASSERT_NE(plugin, nullptr);

    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("Scripted Contact Reader");
    ASSERT_NE(session, nullptr);
    auto rig = installLdsRig(*session, /*plainLds=*/true);
    session->setCredentialProvider(
        [](const LibreSCRS::Auth::AuthRequirement&) { return LibreSCRS::Auth::CredentialResult::cancelled(); });

    ASSERT_TRUE(plugin->canHandleConnection({}, *session));
    auto rr = plugin->readCard(*session);
    ASSERT_EQ(rr.status, ReadResult::Status::Ok);
    ASSERT_TRUE(rr.data.has_value());

    // DG14 present -> a chip_auth check exists; DG15 absent -> no active_auth
    // check. Presence is decided by whether the id is findable at all, not by
    // where in the emission order it landed.
    EXPECT_TRUE(checkIndexOf(*rr.data, "security_status", "chip_auth").has_value())
        << "chip_auth check must be present when DG14 exists";
    EXPECT_FALSE(checkIndexOf(*rr.data, "security_status", "active_auth").has_value())
        << "active_auth check must be omitted when the document has no DG15";
}

// A card-side status-word refusal of INTERNAL AUTHENTICATE on a PLAIN channel
// is a policy statement (the contact interface may legitimately SM-gate the
// protocol), not a clone signal: the active_auth row must read NOT_PERFORMED,
// never FAILED. Inside an SM tunnel the same refusal keeps FAILED — that
// distinction is pinned at the crypto layer (chipRefusedProtocol contract).
TEST(EmrtdInterfaceActivation, PlainReadActiveAuthRefusalIsNotPerformed)
{
    CardPluginService registry{pluginDir()};
    auto plugin = findEMRTD(registry);
    ASSERT_NE(plugin, nullptr);

    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("Scripted Contact Reader");
    ASSERT_NE(session, nullptr);
    auto rig = installLdsRig(*session, /*plainLds=*/true);
    // COM additionally lists DG15 (0x6F), and DG15 carries a parseable EC key
    // so the AA attempt reaches the wire — where the rig answers INS 0x88 with
    // its unsupported-instruction SW, the refusal shape under test.
    rig->files[0x011E] = {0x60, 0x15, 0x5F, 0x01, 0x04, '0', '1',  '0',  '8',  0x5F, 0x36, 0x06,
                          '0',  '4',  '0',  '0',  '0',  '0', 0x5C, 0x03, 0x61, 0x6E, 0x6F};
    auto aaKey = LibreSCRS::Test::EcCardKey::generate();
    rig->files[0x010F] = LibreSCRS::Test::buildDg15(aaKey.spkiDer);
    session->setCredentialProvider(
        [](const LibreSCRS::Auth::AuthRequirement&) { return LibreSCRS::Auth::CredentialResult::cancelled(); });

    ASSERT_TRUE(plugin->canHandleConnection({}, *session));
    auto rr = plugin->readCard(*session);
    ASSERT_EQ(rr.status, ReadResult::Status::Ok);
    ASSERT_TRUE(rr.data.has_value());

    EXPECT_TRUE(logContainsIns(*rig, 0x88)) << "the AA attempt must reach the wire";
    // The verdict has its own field now, so this compares the whole token
    // rather than a prefix of a sentence that also carried the refusal reason.
    const auto aaIdx = checkIndexOf(*rr.data, "security_status", "active_auth");
    ASSERT_TRUE(aaIdx.has_value()) << "the active_auth check must be present when DG15 exists";
    const std::string aa = checkField(*rr.data, "security_status", *aaIdx, "status").value_or("");
    EXPECT_EQ(aa, "NOT_PERFORMED") << "a refusal on a plain channel is not a genuineness failure; got: " << aa;
}

// Each security check must reach the host as SEPARATE fields — its id,
// category, status, label and (when the producer has one) its detail and error
// — not as one pre-joined English string keyed by the check id. The joined
// shape cannot carry a machine-readable reason alongside displayed text: a
// consumer that wants to translate a verdict has to parse prose back apart to
// find it, and any reason it recovers is already in one language. Pins the
// per-check emission loop in emrtd_card_plugin.cpp's "8. Emit security_status
// group". This rig gives active_auth both a status AND an error detail, so it
// is the check that proves the two travel apart.
TEST(EmrtdInterfaceActivation, SecurityChecksTravelAsSeparateFieldsNotOneJoinedString)
{
    CardPluginService registry{pluginDir()};
    auto plugin = findEMRTD(registry);
    ASSERT_NE(plugin, nullptr);

    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("Scripted Contact Reader");
    ASSERT_NE(session, nullptr);
    auto rig = installLdsRig(*session, /*plainLds=*/true);
    // Same DG15-bearing rig as PlainReadActiveAuthRefusalIsNotPerformed: the AA
    // attempt reaches the wire and is refused, so the check carries an error.
    rig->files[0x011E] = {0x60, 0x15, 0x5F, 0x01, 0x04, '0', '1',  '0',  '8',  0x5F, 0x36, 0x06,
                          '0',  '4',  '0',  '0',  '0',  '0', 0x5C, 0x03, 0x61, 0x6E, 0x6F};
    auto aaKey = LibreSCRS::Test::EcCardKey::generate();
    rig->files[0x010F] = LibreSCRS::Test::buildDg15(aaKey.spkiDer);
    session->setCredentialProvider(
        [](const LibreSCRS::Auth::AuthRequirement&) { return LibreSCRS::Auth::CredentialResult::cancelled(); });

    ASSERT_TRUE(plugin->canHandleConnection({}, *session));
    auto rr = plugin->readCard(*session);
    ASSERT_EQ(rr.status, ReadResult::Status::Ok);
    ASSERT_TRUE(rr.data.has_value());

    // Shape first, so a pre-fix run names BOTH halves of the defect: the old
    // field keyed by the check id still there, and no field in the new shape.
    EXPECT_FALSE(fieldText(*rr.data, "security_status", "active_auth").has_value())
        << "the concatenated field must be gone, not merely duplicated";

    // Nothing may be left in a third shape: every field is either one of the
    // three aggregates or a member of some check's family.
    auto secIdx = rr.data->findGroup("security_status");
    ASSERT_TRUE(secIdx.has_value());
    for (const auto& field : rr.data->groupAt(*secIdx).fields) {
        const bool aggregate = field.key.compare(0, 8, "overall_") == 0;
        EXPECT_TRUE(aggregate || parseCheckKey(field.key).has_value())
            << "field in neither the aggregate nor the per-check shape: " << field.key;
    }

    // The three aggregates are the one thing both desktop hosts already render:
    // they keep their own keys and stay outside the per-check family.
    EXPECT_TRUE(fieldText(*rr.data, "security_status", "overall_genuineness").has_value());
    EXPECT_FALSE(parseCheckKey("overall_genuineness").has_value());

    const auto i = checkIndexOf(*rr.data, "security_status", "active_auth");
    ASSERT_TRUE(i.has_value()) << "the check must be findable by its id";

    EXPECT_EQ(checkField(*rr.data, "security_status", *i, "status").value_or(""), "NOT_PERFORMED");
    EXPECT_EQ(checkField(*rr.data, "security_status", *i, "id").value_or(""), "active_auth");
    EXPECT_EQ(checkField(*rr.data, "security_status", *i, "category").value_or(""), "chip_genuineness");
    EXPECT_EQ(checkField(*rr.data, "security_status", *i, "label").value_or(""), "Active Authentication");
    EXPECT_FALSE(checkField(*rr.data, "security_status", *i, "error").value_or("").empty())
        << "the refusal reason must arrive in its own field, not glued onto the status";
}

// Pins two lines in emrtd_card_plugin.cpp: the CSCA check built in "7. Passive
// Authentication", which used to carry an English sentence in `detail`, and the
// `reason` suffix in the per-check emission loop in "8. Emit security_status
// group".
//
// This is the first plugin test to reach passive authentication at all. It
// needs a rig that serves a real EF.SOD (see LdsRigState::plainSod), because
// the verdict under test does not exist on a document that was never read.
TEST(EmrtdInterfaceActivation, CscaVerdictTravelsAsATranslatableReasonNotAnEnglishSentence)
{
    CardPluginService registry{pluginDir()};
    auto plugin = findEMRTD(registry);
    ASSERT_NE(plugin, nullptr);

    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("Scripted Contact Reader");
    ASSERT_NE(session, nullptr);
    auto rig = installLdsRig(*session, /*plainLds=*/true, /*plainSod=*/true);

    // A document that is internally consistent the way a real one is: a
    // security object signed by a document signer a country signing
    // certificate issued, and the exact data group bytes that object hashes.
    // Nothing here configures a trust anchor, so the chain is the one thing
    // that cannot be established -- which is the situation every reader of
    // this build is in, and what the reason has to be able to say.
    const auto ml = LibreSCRS::Test::makeMasterList(1);
    rig->files[0x011D] = sodFixture(LibreSCRS::Test::makeSod(ml, 0));
    const auto dgs = LibreSCRS::Test::sodDataGroups();
    ASSERT_EQ(dgs.size(), 1u) << "the fixture grew a data group this rig does not serve";
    ASSERT_EQ(dgs.count(1), 1u) << "and it is DG1 the rig serves";
    rig->files[0x0101] = dgs.at(1);

    session->setCredentialProvider(
        [](const LibreSCRS::Auth::AuthRequirement&) { return LibreSCRS::Auth::CredentialResult::cancelled(); });

    ASSERT_TRUE(plugin->canHandleConnection({}, *session));
    auto rr = plugin->readCard(*session);
    ASSERT_EQ(rr.status, ReadResult::Status::Ok);
    ASSERT_TRUE(rr.data.has_value());

    // The document really was read and really does hold up on its own terms.
    // Without this the CSCA assertions below could pass on a rig that served
    // nothing at all.
    const auto sodIdx = checkIndexOf(*rr.data, "security_status", "pa_sod_signature");
    ASSERT_TRUE(sodIdx.has_value()) << "the rig must really have served a security object";
    EXPECT_EQ(checkField(*rr.data, "security_status", *sodIdx, "status").value_or(""), "PASSED");
    const auto dgIdx = checkIndexOf(*rr.data, "security_status", "pa_dg1_hash");
    ASSERT_TRUE(dgIdx.has_value());
    EXPECT_EQ(checkField(*rr.data, "security_status", *dgIdx, "status").value_or(""), "PASSED");

    const auto i = checkIndexOf(*rr.data, "security_status", "pa_csca_chain");
    ASSERT_TRUE(i.has_value()) << "the CSCA check must be findable by its id";
    EXPECT_EQ(checkField(*rr.data, "security_status", *i, "status").value_or(""), "NOT_PERFORMED");
    EXPECT_EQ(checkField(*rr.data, "security_status", *i, "reason").value_or(""), "csca.not-configured")
        << "the reason must travel as a key a host can translate, in its own field";
    EXPECT_FALSE(checkField(*rr.data, "security_status", *i, "detail").has_value())
        << "the English sentence the key replaces must be GONE, not sitting beside it";

    // And it must not have moved somewhere else in the group either.
    auto secIdx = rr.data->findGroup("security_status");
    ASSERT_TRUE(secIdx.has_value());
    for (const auto& field : rr.data->groupAt(*secIdx).fields) {
        EXPECT_EQ(field.textValue().value_or("").find("No CSCA trust store"), std::string::npos)
            << "an English literal survives at " << field.key;
    }

    // The badge still tells the truth: a signature checked against a
    // certificate the document carried itself does not establish authenticity.
    EXPECT_NE(fieldText(*rr.data, "security_status", "overall_authenticity").value_or(""), "PASSED")
        << "authenticity claimed PASSED with no anchor configured";
}

// Pins the ABSENCE of an environment read in emrtd_card_plugin.cpp's "7.
// Passive Authentication".
//
// A trust anchor is the whole of what a passive-authentication badge means. An
// environment variable is set by anything running as the person using the
// machine -- so while one was read, any process in the session could drop a CA
// it had minted itself into a directory, point the variable at it, and have a
// document it forged reported as chaining to a country signing certificate.
// That is a green badge issued on the say-so of the attacker.
//
// The document below is exactly that attack, minus the forging: the anchors in
// the directory really did issue this document's signer, so a build that reads
// the variable answers PASSED. Nothing about the answer changes if the whole
// document is synthesised by whoever set the variable.
//
// Until a configuration a person can vouch for arrives, the honest answer is
// that no anchors are configured. "Not configured" is a smaller answer than
// "passed"; it is also the only one of the two that is true.
TEST(EmrtdInterfaceActivation, AnEnvironmentVariableCannotSupplyTrustAnchors)
{
    CardPluginService registry{pluginDir()};
    auto plugin = findEMRTD(registry);
    ASSERT_NE(plugin, nullptr);

    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("Scripted Contact Reader");
    ASSERT_NE(session, nullptr);
    auto rig = installLdsRig(*session, /*plainLds=*/true, /*plainSod=*/true);

    const auto ml = LibreSCRS::Test::makeMasterList(1);
    rig->files[0x011D] = sodFixture(LibreSCRS::Test::makeSod(ml, 0));
    const auto dgs = LibreSCRS::Test::sodDataGroups();
    ASSERT_EQ(dgs.count(1), 1u);
    rig->files[0x0101] = dgs.at(1);

    // An unhashed directory holding the very anchor that issued this
    // document's signer -- the anchor set that WOULD make it pass, planted
    // where nothing privileged put it.
    const std::string planted = LibreSCRS::Test::writePemDir(ml.cscaDer);
    struct Remove
    {
        std::string dir;
        ~Remove()
        {
            std::error_code ec;
            std::filesystem::remove_all(dir, ec);
        }
    } cleanup{planted};

    session->setCredentialProvider(
        [](const LibreSCRS::Auth::AuthRequirement&) { return LibreSCRS::Auth::CredentialResult::cancelled(); });

    std::optional<CardData> data;
    {
        const ScopedEnv store("LIBRESCRS_CSCA_STORE", planted);
        ASSERT_TRUE(plugin->canHandleConnection({}, *session));
        auto rr = plugin->readCard(*session);
        ASSERT_EQ(rr.status, ReadResult::Status::Ok);
        ASSERT_TRUE(rr.data.has_value());
        data = std::move(*rr.data);
    }

    // The document itself is beyond reproach -- so a failure below is about
    // where the anchors came from and nothing else.
    const auto sodIdx = checkIndexOf(*data, "security_status", "pa_sod_signature");
    ASSERT_TRUE(sodIdx.has_value());
    ASSERT_EQ(checkField(*data, "security_status", *sodIdx, "status").value_or(""), "PASSED");

    const auto i = checkIndexOf(*data, "security_status", "pa_csca_chain");
    ASSERT_TRUE(i.has_value());
    EXPECT_EQ(checkField(*data, "security_status", *i, "status").value_or(""), "NOT_PERFORMED")
        << "anchors from an unprivileged source must not decide this";
    EXPECT_EQ(checkField(*data, "security_status", *i, "reason").value_or(""), "csca.not-configured")
        << "and the reader must be told no anchors are configured, not shown a green badge";
    EXPECT_NE(fieldText(*data, "security_status", "overall_authenticity").value_or(""), "PASSED")
        << "the badge would have claimed authenticity on the say-so of an environment variable";
}

// --- the anchors a HOST published ------------------------------------------
//
// The three cases below are the other side of the test above. Anchors may not
// come from the environment; they have to come from somewhere, and this is it:
// CardPluginService::setCscaAnchorDirectory, called by the host that loaded the
// plugin.
//
// They exist because of a failure measured on a machine with a real passport on
// the reader. A person had imported a master list; the agent had verified it,
// applied its trust rules and written five anchors into its cache, and its own
// state property said so. The badge on the document still read "no country
// signing certificates have been imported". Both halves were green in their own
// test suites -- the import was tested against the cache it writes, the chain
// check was tested against a directory a test handed it -- and nothing anywhere
// drove the PLUGIN with a directory of anchors present. That is what these do.
//
// Each drives the real plugin `.so` through the registry, over a scripted card
// serving a genuine security object, and reads the badge fields a host paints
// from. Nothing here calls the chain check directly: the point at issue was
// never whether that code works.

// The verdict a real passport gets against anchors that do not include its
// issuer: `no-anchor-for-issuer`, and specifically NOT `not-configured`. Those
// two are the same STATUS, which is why the reason key exists at all, and
// telling them apart is the whole difference between "you have not imported
// anything" and "what you imported does not cover this country".
TEST(EmrtdInterfaceActivation, AnchorsPublishedByTheHostReachTheChainCheck)
{
    CardPluginService registry{pluginDir()};
    auto plugin = findEMRTD(registry);
    ASSERT_NE(plugin, nullptr);

    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("Scripted Contact Reader");
    ASSERT_NE(session, nullptr);
    auto rig = installLdsRig(*session, /*plainLds=*/true, /*plainSod=*/true);

    // Two authorities that have nothing to do with each other. The document is
    // this country's; the anchors on disk are that one's.
    const auto issuing = LibreSCRS::Test::makeMasterList(1);
    const auto other = LibreSCRS::Test::makeMasterList(1);
    rig->files[0x011D] = sodFixture(LibreSCRS::Test::makeSod(issuing, 0));
    const auto dgs = LibreSCRS::Test::sodDataGroups();
    ASSERT_EQ(dgs.count(1), 1u);
    rig->files[0x0101] = dgs.at(1);

    const DerAnchorDir anchors("other-authority", other.cscaDer);
    registry.setCscaAnchorDirectory(anchors.path());

    session->setCredentialProvider(
        [](const LibreSCRS::Auth::AuthRequirement&) { return LibreSCRS::Auth::CredentialResult::cancelled(); });

    ASSERT_TRUE(plugin->canHandleConnection({}, *session));
    auto rr = plugin->readCard(*session);
    ASSERT_EQ(rr.status, ReadResult::Status::Ok);
    ASSERT_TRUE(rr.data.has_value());

    // The document held up on its own terms, so a failure below is about the
    // anchors and nothing else.
    const auto sodIdx = checkIndexOf(*rr.data, "security_status", "pa_sod_signature");
    ASSERT_TRUE(sodIdx.has_value()) << "the rig must really have served a security object";
    ASSERT_EQ(checkField(*rr.data, "security_status", *sodIdx, "status").value_or(""), "PASSED");

    const auto i = checkIndexOf(*rr.data, "security_status", "pa_csca_chain");
    ASSERT_TRUE(i.has_value());
    EXPECT_EQ(checkField(*rr.data, "security_status", *i, "reason").value_or(""), "csca.no-anchor-for-issuer")
        << "anchors the host published were not looked at: this is the field defect";
    EXPECT_EQ(checkField(*rr.data, "security_status", *i, "status").value_or(""), "NOT_PERFORMED")
        << "holding another authority's anchors is not an accusation against this document";
    EXPECT_NE(fieldText(*rr.data, "security_status", "overall_authenticity").value_or(""), "PASSED")
        << "no anchor issued this signer, so authenticity is not established";
}

// The same document against the anchors that DID issue its signer. Without
// this, a plugin that answered `no-anchor-for-issuer` unconditionally -- never
// reading the directory at all -- would pass the case above.
TEST(EmrtdInterfaceActivation, AnchorsThatIssuedTheSignerEstablishAuthenticity)
{
    CardPluginService registry{pluginDir()};
    auto plugin = findEMRTD(registry);
    ASSERT_NE(plugin, nullptr);

    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("Scripted Contact Reader");
    ASSERT_NE(session, nullptr);
    auto rig = installLdsRig(*session, /*plainLds=*/true, /*plainSod=*/true);

    const auto issuing = LibreSCRS::Test::makeMasterList(1);
    rig->files[0x011D] = sodFixture(LibreSCRS::Test::makeSod(issuing, 0));
    const auto dgs = LibreSCRS::Test::sodDataGroups();
    ASSERT_EQ(dgs.count(1), 1u);
    rig->files[0x0101] = dgs.at(1);

    const DerAnchorDir anchors("issuing-authority", issuing.cscaDer);
    registry.setCscaAnchorDirectory(anchors.path());

    session->setCredentialProvider(
        [](const LibreSCRS::Auth::AuthRequirement&) { return LibreSCRS::Auth::CredentialResult::cancelled(); });

    ASSERT_TRUE(plugin->canHandleConnection({}, *session));
    auto rr = plugin->readCard(*session);
    ASSERT_EQ(rr.status, ReadResult::Status::Ok);
    ASSERT_TRUE(rr.data.has_value());

    const auto i = checkIndexOf(*rr.data, "security_status", "pa_csca_chain");
    ASSERT_TRUE(i.has_value());
    EXPECT_EQ(checkField(*rr.data, "security_status", *i, "status").value_or(""), "PASSED");
    EXPECT_EQ(checkField(*rr.data, "security_status", *i, "reason").value_or(""), "")
        << "the one outcome with nothing to explain must explain nothing";
    EXPECT_EQ(fieldText(*rr.data, "security_status", "overall_authenticity").value_or(""), "PASSED")
        << "signature verified and signer anchored: this is what a badge is allowed to claim";
}

// Publication is single-shot, and this is the direction that matters: a second
// caller cannot UPGRADE a verdict. Anything sharing the host process would
// otherwise be able to hand the plugin a certification authority of its own
// after the fact -- the in-process version of the environment variable the test
// above forbids, and worth its own case because the argument for that removal
// is not an argument about environment variables.
TEST(EmrtdInterfaceActivation, ALaterPublicationCannotRepointAPluginsAnchors)
{
    CardPluginService registry{pluginDir()};
    auto plugin = findEMRTD(registry);
    ASSERT_NE(plugin, nullptr);

    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("Scripted Contact Reader");
    ASSERT_NE(session, nullptr);
    auto rig = installLdsRig(*session, /*plainLds=*/true, /*plainSod=*/true);

    const auto issuing = LibreSCRS::Test::makeMasterList(1);
    const auto other = LibreSCRS::Test::makeMasterList(1);
    rig->files[0x011D] = sodFixture(LibreSCRS::Test::makeSod(issuing, 0));
    const auto dgs = LibreSCRS::Test::sodDataGroups();
    ASSERT_EQ(dgs.count(1), 1u);
    rig->files[0x0101] = dgs.at(1);

    const DerAnchorDir first("repoint-first", other.cscaDer);
    const DerAnchorDir second("repoint-second", issuing.cscaDer);
    registry.setCscaAnchorDirectory(first.path());
    registry.setCscaAnchorDirectory(second.path());

    // The second directory really would change the answer -- the previous test
    // reads exactly these anchors and gets PASSED -- so a green verdict here
    // could only mean the second call was honoured.
    EXPECT_EQ(plugin->cscaAnchorDirectory(), first.path()) << "the first publication must be the one that stands";

    session->setCredentialProvider(
        [](const LibreSCRS::Auth::AuthRequirement&) { return LibreSCRS::Auth::CredentialResult::cancelled(); });

    ASSERT_TRUE(plugin->canHandleConnection({}, *session));
    auto rr = plugin->readCard(*session);
    ASSERT_EQ(rr.status, ReadResult::Status::Ok);
    ASSERT_TRUE(rr.data.has_value());

    const auto i = checkIndexOf(*rr.data, "security_status", "pa_csca_chain");
    ASSERT_TRUE(i.has_value());
    EXPECT_EQ(checkField(*rr.data, "security_status", *i, "reason").value_or(""), "csca.no-anchor-for-issuer")
        << "a later caller re-pointed the plugin at anchors of its own choosing";
}

// A host that publishes nothing keeps exactly the behaviour it had: the honest
// "not configured", not a crash and not a silently empty store. The registry
// here is never told anything -- which is every host that has not been taught
// to publish, and every host that has no anchor cache at all.
TEST(EmrtdInterfaceActivation, AHostThatPublishesNothingStillGetsNotConfigured)
{
    CardPluginService registry{pluginDir()};
    auto plugin = findEMRTD(registry);
    ASSERT_NE(plugin, nullptr);
    EXPECT_TRUE(plugin->cscaAnchorDirectory().empty()) << "an unpublished plugin must name no directory at all";

    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("Scripted Contact Reader");
    ASSERT_NE(session, nullptr);
    auto rig = installLdsRig(*session, /*plainLds=*/true, /*plainSod=*/true);

    const auto issuing = LibreSCRS::Test::makeMasterList(1);
    rig->files[0x011D] = sodFixture(LibreSCRS::Test::makeSod(issuing, 0));
    const auto dgs = LibreSCRS::Test::sodDataGroups();
    ASSERT_EQ(dgs.count(1), 1u);
    rig->files[0x0101] = dgs.at(1);

    session->setCredentialProvider(
        [](const LibreSCRS::Auth::AuthRequirement&) { return LibreSCRS::Auth::CredentialResult::cancelled(); });

    ASSERT_TRUE(plugin->canHandleConnection({}, *session));
    auto rr = plugin->readCard(*session);
    ASSERT_EQ(rr.status, ReadResult::Status::Ok);
    ASSERT_TRUE(rr.data.has_value());

    const auto i = checkIndexOf(*rr.data, "security_status", "pa_csca_chain");
    ASSERT_TRUE(i.has_value());
    EXPECT_EQ(checkField(*rr.data, "security_status", *i, "reason").value_or(""), "csca.not-configured");
    EXPECT_EQ(checkField(*rr.data, "security_status", *i, "status").value_or(""), "NOT_PERFORMED");
}

TEST(EmrtdInterfaceActivation, ContactPlainReadAttemptsChipAuthAndStaysPlainWhenUnavailable)
{
    CardPluginService registry{pluginDir()};
    auto plugin = findEMRTD(registry);
    ASSERT_NE(plugin, nullptr);

    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("Scripted Contact Reader");
    ASSERT_NE(session, nullptr);
    auto rig = installLdsRig(*session, /*plainLds=*/true);
    session->setCredentialProvider(
        [](const LibreSCRS::Auth::AuthRequirement&) { return LibreSCRS::Auth::CredentialResult::cancelled(); });

    ASSERT_TRUE(plugin->canHandleConnection({}, *session));
    auto rr = plugin->readCard(*session);
    ASSERT_EQ(rr.status, ReadResult::Status::Ok);
    ASSERT_TRUE(rr.data.has_value());

    // The plain path now ATTEMPTS to run Chip Authentication and raise the
    // channel to SM (skipping it would leave the verdict unmade AND the rest
    // of the read in cleartext). This rig's DG14 is an unparseable stub, so the
    // attempt yields NOT_SUPPORTED — a property of the DG14 content, honestly
    // reported — and the channel stays plain (no upgrade), so auth_method
    // stays "None (plain read)". Because parseDG14 fails before the protocol
    // APDUs, no MSE:Set AT / GENERAL AUTHENTICATE reaches the wire.
    EXPECT_EQ(fieldText(*rr.data, "presence", "auth_method").value_or(""), "None (plain read)");
    const auto caIdx = checkIndexOf(*rr.data, "security_status", "chip_auth");
    ASSERT_TRUE(caIdx.has_value()) << "chip_auth check must be present when DG14 exists";
    EXPECT_EQ(checkField(*rr.data, "security_status", *caIdx, "status").value_or(""), "NOT_SUPPORTED");
    EXPECT_TRUE(logContainsSelectFid(*rig, 0x010E)) << "DG14 raw bytes must still be read on the plain path";
    EXPECT_FALSE(logContainsIns(*rig, 0x22));
    EXPECT_FALSE(logContainsIns(*rig, 0x86));

    // EF.SOD is SM-gated on this rig (as on the shipping document): the
    // plain path must not fabricate ANY passive-auth verdict from it — no
    // pa_* checks may appear, and nothing may be reported as FAILED.
    // Read through the check ids and statuses, not the field keys: with each
    // check spread over a `check_<N>_*` family, a key-prefix test for "pa_"
    // would match nothing and pass while proving nothing.
    ASSERT_TRUE(rr.data->findGroup("security_status").has_value());
    for (const auto& id : checkIds(*rr.data, "security_status")) {
        EXPECT_FALSE(id.compare(0, 3, "pa_") == 0) << "unexpected passive-auth check: " << id;
        const auto n = checkIndexOf(*rr.data, "security_status", id);
        ASSERT_TRUE(n.has_value());
        EXPECT_NE(checkField(*rr.data, "security_status", *n, "status").value_or(""), "FAILED")
            << id << " reported FAILED on the plain path";
    }
    // The aggregates must stay clear of FAILED too — they were covered by the
    // sweep over every field the joined shape allowed.
    for (const char* key : {"overall_integrity", "overall_authenticity", "overall_genuineness"}) {
        EXPECT_NE(fieldText(*rr.data, "security_status", key).value_or(""), "FAILED")
            << key << " reported FAILED on the plain path";
    }
}

TEST(EmrtdInterfaceActivation, ContactlessWithProviderStillActivatesSm)
{
    CardPluginService registry{pluginDir()};
    auto plugin = findEMRTD(registry);
    ASSERT_NE(plugin, nullptr);

    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("Scripted Contactless Reader");
    ASSERT_NE(session, nullptr);
    auto rig = installLdsRig(*session, /*plainLds=*/false);

    bool providerInvoked = false;
    session->setCredentialProvider([&providerInvoked](const LibreSCRS::Auth::AuthRequirement&) {
        providerInvoked = true;
        return LibreSCRS::Auth::CredentialResult::cancelled();
    });

    ASSERT_TRUE(plugin->canHandleConnection({}, *session));
    auto rr = plugin->readCard(*session);

    // The provider→PACE shortcut must stay untouched on contactless: the
    // activation walk consults the provider (which cancels here), and no
    // identity data is ever readable in plain.
    EXPECT_TRUE(providerInvoked) << "contactless read with a provider must still drive SM activation";
    EXPECT_EQ(rr.status, ReadResult::Status::Cancelled);
    EXPECT_FALSE(rr.data.has_value() && rr.data->findGroup("personal").has_value());
    (void)rig;
}

TEST(EmrtdInterfaceActivation, ContactlessDiscoveryWithoutProviderStillAuthRequired)
{
    CardPluginService registry{pluginDir()};
    auto plugin = findEMRTD(registry);
    ASSERT_NE(plugin, nullptr);

    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("Scripted Contactless Reader");
    ASSERT_NE(session, nullptr);
    auto rig = installLdsRig(*session, /*plainLds=*/false);

    ASSERT_TRUE(plugin->canHandleConnection({}, *session));
    rig->log.clear();
    auto rr = plugin->readCard(*session);

    // Host discovery on contactless keeps today's contract: an auth_required
    // probe group, never identity data — and the read itself must not even
    // attempt the plain LDS path (no EF.COM SELECT) once the probe cached a
    // not-readable verdict.
    ASSERT_EQ(rr.status, ReadResult::Status::Ok);
    ASSERT_TRUE(rr.data.has_value());
    EXPECT_TRUE(rr.data->findGroup("auth_required").has_value());
    EXPECT_FALSE(rr.data->findGroup("personal").has_value());
    EXPECT_FALSE(logContainsSelectFid(*rig, 0x011E)) << "plain-first attempt must be skipped on contactless";
}

// A deposited CAN takes precedence over the plain-readability verdict: the
// host explicitly asked for PACE (CAN), so the profile must stay PACE even on
// a plain-readable interface. On this rig the activation then fails (no SM
// instructions), which is the observable proof the PACE path was taken.
TEST(EmrtdInterfaceActivation, DepositedCanStillDrivesPace)
{
    CardPluginService registry{pluginDir()};
    auto plugin = findEMRTD(registry);
    ASSERT_NE(plugin, nullptr);

    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("Scripted Contact Reader");
    ASSERT_NE(session, nullptr);
    auto rig = installLdsRig(*session, /*plainLds=*/true);

    ASSERT_TRUE(plugin->canHandleConnection({}, *session));
    plugin->setCredentials(*session, "can", LibreSCRS::Secure::String{"123456"});
    auto rr = plugin->readCard(*session);

    EXPECT_NE(rr.status, ReadResult::Status::Ok);
    EXPECT_FALSE(rr.data.has_value() && rr.data->findGroup("personal").has_value());
    (void)rig;
}

// A plain channel another plugin installed (bound to ITS applet) must not be
// read over blindly: the plain path re-acquires its own correctly bound
// channel, so the identity still reads after a sibling-plugin operation.
TEST(EmrtdInterfaceActivation, ForeignPlainChannelIsHealedOnContact)
{
    CardPluginService registry{pluginDir()};
    auto plugin = findEMRTD(registry);
    ASSERT_NE(plugin, nullptr);

    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("Scripted Contact Reader");
    ASSERT_NE(session, nullptr);
    auto rig = installLdsRig(*session, /*plainLds=*/true);

    ASSERT_TRUE(plugin->canHandleConnection({}, *session));

    // Simulate a sibling plugin's plain operation: activate (and leave
    // installed) a channel bound to the sibling applet.
    {
        auto sibling = session->activateChannelFor(
            LibreSCRS::SmartCard::AppletAid{kSiblingAidBytes[0], kSiblingAidBytes[1], kSiblingAidBytes[2],
                                            kSiblingAidBytes[3], kSiblingAidBytes[4], kSiblingAidBytes[5],
                                            kSiblingAidBytes[6]},
            LibreSCRS::CancelToken{});
        ASSERT_TRUE(sibling.has_value()) << "sibling plain activation must succeed on the rig";
    } // holder released; the sibling-bound channel stays installed

    auto rr = plugin->readCard(*session);
    ASSERT_EQ(rr.status, ReadResult::Status::Ok);
    ASSERT_TRUE(rr.data.has_value());
    EXPECT_TRUE(rr.data->findGroup("personal").has_value())
        << "the plain path must re-bind its own applet, not read over the sibling channel";
    EXPECT_FALSE(rr.data->findGroup("auth_required").has_value());
}

// Without a discovery probe (canHandleConnection never ran) the verdict is
// unknown and a provider session keeps today's conservative PACE (CAN) path.
TEST(EmrtdInterfaceActivation, UnprobedProviderSessionStaysOnPace)
{
    CardPluginService registry{pluginDir()};
    auto plugin = findEMRTD(registry);
    ASSERT_NE(plugin, nullptr);

    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("Scripted Contact Reader");
    ASSERT_NE(session, nullptr);
    auto rig = installLdsRig(*session, /*plainLds=*/true);

    bool providerInvoked = false;
    session->setCredentialProvider([&providerInvoked](const LibreSCRS::Auth::AuthRequirement&) {
        providerInvoked = true;
        return LibreSCRS::Auth::CredentialResult::cancelled();
    });

    auto rr = plugin->readCard(*session);

    EXPECT_TRUE(providerInvoked) << "unknown interface verdict must keep the provider-driven PACE path";
    EXPECT_EQ(rr.status, ReadResult::Status::Cancelled);
    (void)rig;
}

TEST(EmrtdInterfaceActivation, ContactDiscoveryWithoutProviderReadsIdentity)
{
    CardPluginService registry{pluginDir()};
    auto plugin = findEMRTD(registry);
    ASSERT_NE(plugin, nullptr);

    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("Scripted Contact Reader");
    ASSERT_NE(session, nullptr);
    auto rig = installLdsRig(*session, /*plainLds=*/true);

    ASSERT_TRUE(plugin->canHandleConnection({}, *session));
    auto rr = plugin->readCard(*session);

    // Host discovery (no provider) on the contact interface reads the
    // identity directly — no auth_required round-trip, no CAN prompt.
    ASSERT_EQ(rr.status, ReadResult::Status::Ok);
    ASSERT_TRUE(rr.data.has_value());
    EXPECT_TRUE(rr.data->findGroup("personal").has_value());
    EXPECT_FALSE(rr.data->findGroup("auth_required").has_value());
    EXPECT_FALSE(logContainsIns(*rig, 0x22));
    EXPECT_FALSE(logContainsIns(*rig, 0x86));
}

// ---------------------------------------------------------------------------
// MF-scoped EF.CardAccess capability probe (tri-state) driving the
// BAC-by-capability provider branch and the capability-gated deposit branch.
// ---------------------------------------------------------------------------

// A definitively PACE-absent document (clean 6A82 on EF.CardAccess at MF) on
// the provider branch activates BAC — one Mrz prompt, no wasted PACE-CAN —
// and never opens a blanket BAC fallback.
TEST(EmrtdInterfaceActivation, BacOnlyDocumentYieldsBacProfileOnProviderBranch)
{
    CardPluginService registry{pluginDir()};
    auto plugin = findEMRTD(registry);
    ASSERT_NE(plugin, nullptr);

    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("Scripted Contactless Reader");
    ASSERT_NE(session, nullptr);
    auto rig = installLdsRig(*session, /*plainLds=*/false);
    setCardAccessMode(*rig, CardAccessMode::AbsentNotFound);

    session->setCredentialProvider(
        [](const LibreSCRS::Auth::AuthRequirement&) { return LibreSCRS::Auth::CredentialResult::cancelled(); });

    ASSERT_TRUE(plugin->canHandleConnection({}, *session));
    const auto p = LibreSCRS::Plugin::detail::CardPluginActivationAccessor::profile(*plugin, *session);

    EXPECT_NE(std::get_if<LibreSCRS::SmartCard::BacRequest>(&p.primary), nullptr)
        << "a definitively PACE-absent document must activate BAC on the provider branch";
    EXPECT_FALSE(p.allowBacFallback);
}

// EF.CardAccess present but carrying NO PACEInfo is also a definitive no-PACE
// verdict — same BAC activation.
TEST(EmrtdInterfaceActivation, CardAccessWithoutPaceInfoAlsoYieldsBacProfile)
{
    ASSERT_TRUE(emrtd::crypto::parseCardAccess(presentNoPaceCardAccess()).empty())
        << "the no-PACE fixture must parse to zero PACE OIDs (definitive, not anomaly)";

    CardPluginService registry{pluginDir()};
    auto plugin = findEMRTD(registry);
    ASSERT_NE(plugin, nullptr);

    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("Scripted Contactless Reader");
    ASSERT_NE(session, nullptr);
    auto rig = installLdsRig(*session, /*plainLds=*/false);
    setCardAccessMode(*rig, CardAccessMode::PresentNoPace);

    session->setCredentialProvider(
        [](const LibreSCRS::Auth::AuthRequirement&) { return LibreSCRS::Auth::CredentialResult::cancelled(); });

    ASSERT_TRUE(plugin->canHandleConnection({}, *session));
    const auto p = LibreSCRS::Plugin::detail::CardPluginActivationAccessor::profile(*plugin, *session);

    EXPECT_NE(std::get_if<LibreSCRS::SmartCard::BacRequest>(&p.primary), nullptr);
    EXPECT_FALSE(p.allowBacFallback);
}

// SW 6283 ("selected file invalidated/deactivated") on the EF.CardAccess
// selection after a real MF chain is the chip's OWN declaration that the file
// is unusable: PACE parameters are unobtainable, so the verdict is as
// definitive as a clean 6A82. Observed on real BAC-only personalizations of a
// PACE-capable OS. The reader must NOT attempt READ BINARY: content of a
// deactivated file is not a valid source of PACEInfo, and skipping the read
// keeps the definitive signal free of attacker-influenceable bits under SM.
TEST(EmrtdInterfaceActivation, HelperReportsDeactivatedCardAccessDefinitive)
{
    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("Scripted Contactless Reader");
    ASSERT_NE(session, nullptr);
    auto rig = installLdsRig(*session, /*plainLds=*/false);
    setCardAccessMode(*rig, CardAccessMode::Deactivated);

    auto& conn = LibreSCRS::SmartCard::detail::unwrap(*session);
    const auto read = LibreSCRS::SmartCard::Internal::readCardAccessDetailed(nullptr, conn, LibreSCRS::CancelToken{});

    EXPECT_TRUE(read.mfSelected);
    EXPECT_TRUE(read.efDefinitivelyAbsent) << "6283 after a real MF selection must be definitive absence";
    EXPECT_FALSE(read.readSucceeded);
    EXPECT_TRUE(read.data.empty());
    EXPECT_EQ(rig->deactivatedReadAttempts, 0) << "the reader must not READ a file the chip declared deactivated";
}

// Scope guard at the reader: the widening is EXACTLY 6283. The neighbouring
// termination warning 6285 stays non-definitive — the reader proceeds to READ
// (which this personalization fails) and the verdict falls to Unknown
// downstream (fail closed to PACE-CAN).
TEST(EmrtdInterfaceActivation, HelperKeepsTerminationWarningNonDefinitive)
{
    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("Scripted Contactless Reader");
    ASSERT_NE(session, nullptr);
    auto rig = installLdsRig(*session, /*plainLds=*/false);
    setCardAccessMode(*rig, CardAccessMode::Terminated6285);

    auto& conn = LibreSCRS::SmartCard::detail::unwrap(*session);
    const auto read = LibreSCRS::SmartCard::Internal::readCardAccessDetailed(nullptr, conn, LibreSCRS::CancelToken{});

    EXPECT_TRUE(read.mfSelected);
    EXPECT_FALSE(read.efDefinitivelyAbsent) << "6285 is not part of the definitive-absence acceptance set";
    EXPECT_FALSE(read.readSucceeded);
}

// A deactivated EF.CardAccess on the provider branch activates BAC — same
// routing as the clean-6A82 document: one Mrz prompt, no wasted PACE-CAN, no
// blanket fallback.
TEST(EmrtdInterfaceActivation, DeactivatedCardAccessYieldsBacProfileOnProviderBranch)
{
    CardPluginService registry{pluginDir()};
    auto plugin = findEMRTD(registry);
    ASSERT_NE(plugin, nullptr);

    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("Scripted Contactless Reader");
    ASSERT_NE(session, nullptr);
    auto rig = installLdsRig(*session, /*plainLds=*/false);
    setCardAccessMode(*rig, CardAccessMode::Deactivated);

    session->setCredentialProvider(
        [](const LibreSCRS::Auth::AuthRequirement&) { return LibreSCRS::Auth::CredentialResult::cancelled(); });

    ASSERT_TRUE(plugin->canHandleConnection({}, *session));
    const auto p = LibreSCRS::Plugin::detail::CardPluginActivationAccessor::profile(*plugin, *session);

    EXPECT_NE(std::get_if<LibreSCRS::SmartCard::BacRequest>(&p.primary), nullptr)
        << "a deactivated EF.CardAccess must activate BAC on the provider branch";
    EXPECT_FALSE(p.allowBacFallback);
    EXPECT_EQ(rig->deactivatedReadAttempts, 0);
}

// A PACE-capable document keeps today's PACE-CAN provider path — the
// regression pin proving the probe does not over-trigger BAC.
TEST(EmrtdInterfaceActivation, PacePresentKeepsPaceCanOnProviderBranch)
{
    ASSERT_FALSE(emrtd::crypto::parseCardAccess(presentPaceCardAccess()).empty())
        << "parseCardAccess must accept the Present fixture (the oracle contract)";

    CardPluginService registry{pluginDir()};
    auto plugin = findEMRTD(registry);
    ASSERT_NE(plugin, nullptr);

    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("Scripted Contactless Reader");
    ASSERT_NE(session, nullptr);
    auto rig = installLdsRig(*session, /*plainLds=*/false);
    setCardAccessMode(*rig, CardAccessMode::PresentPace);

    session->setCredentialProvider(
        [](const LibreSCRS::Auth::AuthRequirement&) { return LibreSCRS::Auth::CredentialResult::cancelled(); });

    ASSERT_TRUE(plugin->canHandleConnection({}, *session));
    const auto p = LibreSCRS::Plugin::detail::CardPluginActivationAccessor::profile(*plugin, *session);

    const auto* pace = std::get_if<LibreSCRS::SmartCard::PaceRequest>(&p.primary);
    ASSERT_NE(pace, nullptr);
    EXPECT_EQ(pace->secretKind, LibreSCRS::Auth::PaceSecretKind::Can);
    EXPECT_FALSE(p.allowBacFallback);
}

// An unknown verdict (probe could not complete) fails CLOSED to PACE-CAN,
// never BAC.
TEST(EmrtdInterfaceActivation, UnknownCapabilityFailsClosedToPaceCan)
{
    CardPluginService registry{pluginDir()};
    auto plugin = findEMRTD(registry);
    ASSERT_NE(plugin, nullptr);

    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("Scripted Contactless Reader");
    ASSERT_NE(session, nullptr);
    auto rig = installLdsRig(*session, /*plainLds=*/false);
    setCardAccessMode(*rig, CardAccessMode::SoftFail);

    session->setCredentialProvider(
        [](const LibreSCRS::Auth::AuthRequirement&) { return LibreSCRS::Auth::CredentialResult::cancelled(); });

    ASSERT_TRUE(plugin->canHandleConnection({}, *session));
    const auto p = LibreSCRS::Plugin::detail::CardPluginActivationAccessor::profile(*plugin, *session);

    const auto* pace = std::get_if<LibreSCRS::SmartCard::PaceRequest>(&p.primary);
    ASSERT_NE(pace, nullptr) << "unknown capability must fail closed to PACE, never BAC";
    EXPECT_EQ(pace->secretKind, LibreSCRS::Auth::PaceSecretKind::Can);
    EXPECT_FALSE(p.allowBacFallback);
}

// A read that succeeds but is not a SecurityInfos SET (first byte != 0x31) is
// an ANOMALY, not a definitive absence — Unknown, fail closed to PACE-CAN.
TEST(EmrtdInterfaceActivation, MalformedCardAccessFailsClosedToPaceCan)
{
    CardPluginService registry{pluginDir()};
    auto plugin = findEMRTD(registry);
    ASSERT_NE(plugin, nullptr);

    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("Scripted Contactless Reader");
    ASSERT_NE(session, nullptr);
    auto rig = installLdsRig(*session, /*plainLds=*/false);
    setCardAccessMode(*rig, CardAccessMode::MalformedData);

    session->setCredentialProvider(
        [](const LibreSCRS::Auth::AuthRequirement&) { return LibreSCRS::Auth::CredentialResult::cancelled(); });

    ASSERT_TRUE(plugin->canHandleConnection({}, *session));
    const auto p = LibreSCRS::Plugin::detail::CardPluginActivationAccessor::profile(*plugin, *session);

    const auto* pace = std::get_if<LibreSCRS::SmartCard::PaceRequest>(&p.primary);
    ASSERT_NE(pace, nullptr) << "malformed EF.CardAccess is Unknown, never Absent";
    EXPECT_EQ(pace->secretKind, LibreSCRS::Auth::PaceSecretKind::Can);
    EXPECT_FALSE(p.allowBacFallback);
}

// A read whose outer BER length exceeds the returned bytes (single-READ
// truncation or a >256-byte file) is Unknown — fail closed to PACE-CAN.
TEST(EmrtdInterfaceActivation, TruncatedCardAccessFailsClosedToPaceCan)
{
    CardPluginService registry{pluginDir()};
    auto plugin = findEMRTD(registry);
    ASSERT_NE(plugin, nullptr);

    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("Scripted Contactless Reader");
    ASSERT_NE(session, nullptr);
    auto rig = installLdsRig(*session, /*plainLds=*/false);
    setCardAccessMode(*rig, CardAccessMode::Truncated);

    session->setCredentialProvider(
        [](const LibreSCRS::Auth::AuthRequirement&) { return LibreSCRS::Auth::CredentialResult::cancelled(); });

    ASSERT_TRUE(plugin->canHandleConnection({}, *session));
    const auto p = LibreSCRS::Plugin::detail::CardPluginActivationAccessor::profile(*plugin, *session);

    const auto* pace = std::get_if<LibreSCRS::SmartCard::PaceRequest>(&p.primary);
    ASSERT_NE(pace, nullptr) << "truncated EF.CardAccess is Unknown, never Absent";
    EXPECT_EQ(pace->secretKind, LibreSCRS::Auth::PaceSecretKind::Can);
    EXPECT_FALSE(p.allowBacFallback);
}

// preReadAuth becomes truthful for free: a BAC-only document reports Mrz, a
// PACE-capable document reports Can.
TEST(EmrtdInterfaceActivation, PreReadAuthReportsMrzForBacOnlyDocument)
{
    CardPluginService registry{pluginDir()};
    auto plugin = findEMRTD(registry);
    ASSERT_NE(plugin, nullptr);

    {
        auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("Scripted Contactless Reader");
        ASSERT_NE(session, nullptr);
        auto rig = installLdsRig(*session, /*plainLds=*/false);
        setCardAccessMode(*rig, CardAccessMode::AbsentNotFound);
        session->setCredentialProvider(
            [](const LibreSCRS::Auth::AuthRequirement&) { return LibreSCRS::Auth::CredentialResult::cancelled(); });
        ASSERT_TRUE(plugin->canHandleConnection({}, *session));
        EXPECT_EQ(plugin->preReadAuth(*session), LibreSCRS::Auth::PreReadAuthMethod::Mrz);
    }
    {
        auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("Scripted Contactless Reader");
        ASSERT_NE(session, nullptr);
        auto rig = installLdsRig(*session, /*plainLds=*/false);
        setCardAccessMode(*rig, CardAccessMode::PresentPace);
        session->setCredentialProvider(
            [](const LibreSCRS::Auth::AuthRequirement&) { return LibreSCRS::Auth::CredentialResult::cancelled(); });
        ASSERT_TRUE(plugin->canHandleConnection({}, *session));
        EXPECT_EQ(plugin->preReadAuth(*session), LibreSCRS::Auth::PreReadAuthMethod::Can);
    }
}

// The probe reads at the MASTER FILE, inside the discovery transaction, and
// re-SELECTs the applet AID afterwards — the SELECT-3F00 assertion. A
// probe reading inside the applet DF could never emit the MF chain.
TEST(EmrtdInterfaceActivation, CapabilityProbeRunsInsideTheProbeTransaction)
{
    CardPluginService registry{pluginDir()};
    auto plugin = findEMRTD(registry);
    ASSERT_NE(plugin, nullptr);

    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("Scripted Contactless Reader");
    ASSERT_NE(session, nullptr);
    auto rig = installLdsRig(*session, /*plainLds=*/false);
    setCardAccessMode(*rig, CardAccessMode::PresentPace);

    ASSERT_TRUE(plugin->canHandleConnection({}, *session));

    EXPECT_TRUE(logContainsMfScopedSelect(*rig, 0x3F00)) << "the probe must SELECT the master file (3F00)";
    EXPECT_TRUE(logContainsMfScopedSelect(*rig, 0x011C)) << "the probe must SELECT EF.CardAccess (011C) at MF";
    EXPECT_TRUE(std::any_of(rig->log.begin(), rig->log.end(), [](const APDUCommand& c) {
        return c.ins == 0xB0 && (c.p1 & 0x80) == 0;
    })) << "the probe must issue a plain READ BINARY at the MF-selected EF";

    const auto mfIdx = logIndexOfFirst(*rig, [](const APDUCommand& c) {
        return c.ins == 0xA4 && c.p1 == 0x00 && c.data.size() == 2 && c.data[0] == 0x3F && c.data[1] == 0x00;
    });
    const auto lastAidIdx = logIndexOfLast(
        *rig, [](const APDUCommand& c) { return c.ins == 0xA4 && c.p1 == 0x04 && c.data == kEmrtdAidBytes; });
    ASSERT_TRUE(mfIdx.has_value());
    ASSERT_TRUE(lastAidIdx.has_value());
    EXPECT_GT(*lastAidIdx, *mfIdx) << "the applet AID must be re-SELECTed after the MF-scoped probe";
}

// A plain-readable contact interface stays plain even when EF.CardAccess is
// absent — the plainNow guard outranks the capability verdict.
TEST(EmrtdInterfaceActivation, PlainReadableContactStaysPlainEvenWhenAbsent)
{
    CardPluginService registry{pluginDir()};
    auto plugin = findEMRTD(registry);
    ASSERT_NE(plugin, nullptr);

    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("Scripted Contact Reader");
    ASSERT_NE(session, nullptr);
    auto rig = installLdsRig(*session, /*plainLds=*/true);
    setCardAccessMode(*rig, CardAccessMode::AbsentNotFound);

    session->setCredentialProvider(
        [](const LibreSCRS::Auth::AuthRequirement&) { return LibreSCRS::Auth::CredentialResult::cancelled(); });

    ASSERT_TRUE(plugin->canHandleConnection({}, *session));
    const auto p = LibreSCRS::Plugin::detail::CardPluginActivationAccessor::profile(*plugin, *session);

    EXPECT_FALSE(p.requiresActivation()) << "a plain-readable interface must stay plain regardless of capability";
    EXPECT_FALSE(p.aid.has_value());
}

// Deposit branch: a deposited MRZ on a PACE-capable document keeps the BAC
// fallback OFF — a MITM forcing PaceUnsupported cannot land it on BAC.
TEST(EmrtdInterfaceActivation, DepositedMrzOnPaceDocumentKeepsFallbackOff)
{
    CardPluginService registry{pluginDir()};
    auto plugin = findEMRTD(registry);
    ASSERT_NE(plugin, nullptr);

    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("Scripted Contactless Reader");
    ASSERT_NE(session, nullptr);
    auto rig = installLdsRig(*session, /*plainLds=*/false);
    setCardAccessMode(*rig, CardAccessMode::PresentPace);

    ASSERT_TRUE(plugin->canHandleConnection({}, *session));
    plugin->setCredentials(*session, "mrz_doc_number", LibreSCRS::Secure::String{"L898902C3"});
    plugin->setCredentials(*session, "mrz_dob", LibreSCRS::Secure::String{"740812"});
    plugin->setCredentials(*session, "mrz_expiry", LibreSCRS::Secure::String{"120415"});
    const auto p = LibreSCRS::Plugin::detail::CardPluginActivationAccessor::profile(*plugin, *session);

    const auto* pace = std::get_if<LibreSCRS::SmartCard::PaceRequest>(&p.primary);
    ASSERT_NE(pace, nullptr);
    EXPECT_EQ(pace->secretKind, LibreSCRS::Auth::PaceSecretKind::Mrz);
    EXPECT_FALSE(p.allowBacFallback) << "a PACE-capable document must not open a BAC fallback for a deposited MRZ";
}

// Deposit branch fail-closed: an unknown-capability document keeps the BAC
// fallback OFF for a deposited MRZ too.
TEST(EmrtdInterfaceActivation, DepositedMrzOnUnknownDocumentKeepsFallbackOff)
{
    CardPluginService registry{pluginDir()};
    auto plugin = findEMRTD(registry);
    ASSERT_NE(plugin, nullptr);

    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("Scripted Contactless Reader");
    ASSERT_NE(session, nullptr);
    auto rig = installLdsRig(*session, /*plainLds=*/false);
    setCardAccessMode(*rig, CardAccessMode::SoftFail);

    ASSERT_TRUE(plugin->canHandleConnection({}, *session));
    plugin->setCredentials(*session, "mrz_doc_number", LibreSCRS::Secure::String{"L898902C3"});
    plugin->setCredentials(*session, "mrz_dob", LibreSCRS::Secure::String{"740812"});
    plugin->setCredentials(*session, "mrz_expiry", LibreSCRS::Secure::String{"120415"});
    const auto p = LibreSCRS::Plugin::detail::CardPluginActivationAccessor::profile(*plugin, *session);

    const auto* pace = std::get_if<LibreSCRS::SmartCard::PaceRequest>(&p.primary);
    ASSERT_NE(pace, nullptr);
    EXPECT_EQ(pace->secretKind, LibreSCRS::Auth::PaceSecretKind::Mrz);
    EXPECT_FALSE(p.allowBacFallback) << "an unknown-capability document must fail closed (no BAC fallback)";
}

// Deposit branch on a genuine BAC-only document: the legacy deposit path
// stays functional — a PACE-MRZ attempt with the BAC fallback ENABLED.
TEST(EmrtdInterfaceActivation, DepositedMrzOnBacOnlyDocumentEnablesFallback)
{
    CardPluginService registry{pluginDir()};
    auto plugin = findEMRTD(registry);
    ASSERT_NE(plugin, nullptr);

    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("Scripted Contactless Reader");
    ASSERT_NE(session, nullptr);
    auto rig = installLdsRig(*session, /*plainLds=*/false);
    setCardAccessMode(*rig, CardAccessMode::AbsentNotFound);

    ASSERT_TRUE(plugin->canHandleConnection({}, *session));
    plugin->setCredentials(*session, "mrz_doc_number", LibreSCRS::Secure::String{"L898902C3"});
    plugin->setCredentials(*session, "mrz_dob", LibreSCRS::Secure::String{"740812"});
    plugin->setCredentials(*session, "mrz_expiry", LibreSCRS::Secure::String{"120415"});
    const auto p = LibreSCRS::Plugin::detail::CardPluginActivationAccessor::profile(*plugin, *session);

    const auto* pace = std::get_if<LibreSCRS::SmartCard::PaceRequest>(&p.primary);
    ASSERT_NE(pace, nullptr);
    EXPECT_EQ(pace->secretKind, LibreSCRS::Auth::PaceSecretKind::Mrz);
    EXPECT_TRUE(p.allowBacFallback) << "a genuine BAC-only document must keep the legacy deposit fallback";
}

// Deposit branch on a deactivated-EF.CardAccess document: same definitive
// no-PACE routing as the clean-6A82 case — the legacy deposit path keeps the
// BAC fallback armed, which is what carries a deposited MRZ onto BAC once the
// PACE attempt surfaces its structural failure.
TEST(EmrtdInterfaceActivation, DepositedMrzOnDeactivatedDocumentEnablesFallback)
{
    CardPluginService registry{pluginDir()};
    auto plugin = findEMRTD(registry);
    ASSERT_NE(plugin, nullptr);

    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("Scripted Contactless Reader");
    ASSERT_NE(session, nullptr);
    auto rig = installLdsRig(*session, /*plainLds=*/false);
    setCardAccessMode(*rig, CardAccessMode::Deactivated);

    ASSERT_TRUE(plugin->canHandleConnection({}, *session));
    plugin->setCredentials(*session, "mrz_doc_number", LibreSCRS::Secure::String{"L898902C3"});
    plugin->setCredentials(*session, "mrz_dob", LibreSCRS::Secure::String{"740812"});
    plugin->setCredentials(*session, "mrz_expiry", LibreSCRS::Secure::String{"120415"});
    const auto p = LibreSCRS::Plugin::detail::CardPluginActivationAccessor::profile(*plugin, *session);

    const auto* pace = std::get_if<LibreSCRS::SmartCard::PaceRequest>(&p.primary);
    ASSERT_NE(pace, nullptr);
    EXPECT_EQ(pace->secretKind, LibreSCRS::Auth::PaceSecretKind::Mrz);
    EXPECT_TRUE(p.allowBacFallback) << "a deactivated EF.CardAccess document must keep the deposit fallback";
}

// Host-discovery leg: the auth_required probe reports PACE supported from the
// MF-scoped read, not the old applet-DF SFID read (which reported false for
// every MF-only EF.CardAccess document).
TEST(EmrtdInterfaceActivation, HostDiscoveryLegReportsPaceSupportedFromMf)
{
    CardPluginService registry{pluginDir()};
    auto plugin = findEMRTD(registry);
    ASSERT_NE(plugin, nullptr);

    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("Scripted Contactless Reader");
    ASSERT_NE(session, nullptr);
    auto rig = installLdsRig(*session, /*plainLds=*/false);
    setCardAccessMode(*rig, CardAccessMode::PresentPace);

    // No provider: the read falls through to the host-discovery auth_required
    // probe.
    ASSERT_TRUE(plugin->canHandleConnection({}, *session));
    auto rr = plugin->readCard(*session);
    ASSERT_EQ(rr.status, ReadResult::Status::Ok);
    ASSERT_TRUE(rr.data.has_value());
    ASSERT_TRUE(rr.data->findGroup("auth_required").has_value());
    EXPECT_EQ(fieldText(*rr.data, "auth_required", "pace_supported").value_or(""), "true");
    EXPECT_FALSE(fieldText(*rr.data, "auth_required", "pace_oids").value_or("").empty())
        << "pace_oids must be reported from the MF-scoped EF.CardAccess read";
}

// ---------------------------------------------------------------------------
// preReadAuth truthfulness: the property answers "what WILL the user be
// asked", so it derives from the SAME profile computation as activation with
// exactly one predicate forced — "a credential provider is installed". A
// provider-less presence session must not report "None" for a document whose
// read will prompt (the agent's presence pass has no provider by design).
// ---------------------------------------------------------------------------

TEST(EmrtdPreReadAuth, ReportsMrzForDeactivatedDocument)
{
    CardPluginService registry{pluginDir()};
    auto plugin = findEMRTD(registry);
    ASSERT_NE(plugin, nullptr);

    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("Scripted Contactless Reader");
    ASSERT_NE(session, nullptr);
    auto rig = installLdsRig(*session, /*plainLds=*/false);
    setCardAccessMode(*rig, CardAccessMode::Deactivated);

    // Presence pass: no provider, no deposited credentials.
    ASSERT_TRUE(plugin->canHandleConnection({}, *session));
    EXPECT_EQ(plugin->preReadAuth(*session), LibreSCRS::Auth::PreReadAuthMethod::Mrz)
        << "a definitively PACE-less document will BAC-prompt for the MRZ";
}

TEST(EmrtdPreReadAuth, ReportsCanForPaceDocument)
{
    CardPluginService registry{pluginDir()};
    auto plugin = findEMRTD(registry);
    ASSERT_NE(plugin, nullptr);

    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("Scripted Contactless Reader");
    ASSERT_NE(session, nullptr);
    auto rig = installLdsRig(*session, /*plainLds=*/false);
    setCardAccessMode(*rig, CardAccessMode::PresentPace);

    ASSERT_TRUE(plugin->canHandleConnection({}, *session));
    EXPECT_EQ(plugin->preReadAuth(*session), LibreSCRS::Auth::PreReadAuthMethod::Can)
        << "a PACE-capable document will PACE-CAN-prompt";
}

TEST(EmrtdPreReadAuth, ReportsNoneForPlainReadableContact)
{
    CardPluginService registry{pluginDir()};
    auto plugin = findEMRTD(registry);
    ASSERT_NE(plugin, nullptr);

    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("Scripted Contact Reader");
    ASSERT_NE(session, nullptr);
    auto rig = installLdsRig(*session, /*plainLds=*/true);

    ASSERT_TRUE(plugin->canHandleConnection({}, *session));
    EXPECT_EQ(plugin->preReadAuth(*session), LibreSCRS::Auth::PreReadAuthMethod::None)
        << "a plain-readable contact interface genuinely asks nothing";
}

TEST(EmrtdPreReadAuth, ReportsMrzForDepositedMrz)
{
    CardPluginService registry{pluginDir()};
    auto plugin = findEMRTD(registry);
    ASSERT_NE(plugin, nullptr);

    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("Scripted Contactless Reader");
    ASSERT_NE(session, nullptr);
    auto rig = installLdsRig(*session, /*plainLds=*/false);
    setCardAccessMode(*rig, CardAccessMode::PresentPace);

    ASSERT_TRUE(plugin->canHandleConnection({}, *session));
    plugin->setCredentials(*session, "mrz_doc_number", LibreSCRS::Secure::String{"L898902C3"});
    plugin->setCredentials(*session, "mrz_dob", LibreSCRS::Secure::String{"740812"});
    plugin->setCredentials(*session, "mrz_expiry", LibreSCRS::Secure::String{"120415"});
    EXPECT_EQ(plugin->preReadAuth(*session), LibreSCRS::Auth::PreReadAuthMethod::Mrz)
        << "deposited-credential sessions keep the base-equivalent truthful answer";
}

// Host-discovery leg on a deactivated EF.CardAccess: truthful
// pace_supported=false (the file is chip-declared unusable), with no READ
// attempted against the deactivated file.
TEST(EmrtdInterfaceActivation, HostDiscoveryLegReportsPaceUnsupportedWhenDeactivated)
{
    CardPluginService registry{pluginDir()};
    auto plugin = findEMRTD(registry);
    ASSERT_NE(plugin, nullptr);

    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("Scripted Contactless Reader");
    ASSERT_NE(session, nullptr);
    auto rig = installLdsRig(*session, /*plainLds=*/false);
    setCardAccessMode(*rig, CardAccessMode::Deactivated);

    ASSERT_TRUE(plugin->canHandleConnection({}, *session));
    auto rr = plugin->readCard(*session);
    ASSERT_EQ(rr.status, ReadResult::Status::Ok);
    ASSERT_TRUE(rr.data.has_value());
    ASSERT_TRUE(rr.data->findGroup("auth_required").has_value());
    EXPECT_EQ(fieldText(*rr.data, "auth_required", "pace_supported").value_or(""), "false");
    EXPECT_EQ(rig->deactivatedReadAttempts, 0);
}

// ---------------------------------------------------------------------------
// Post-BAC SM-tunnel downgrade cross-check.
//
// Two layers:
//  (A) The pure fail-closed verdict `classifyPostBacCardAccess` is proven
//      DIRECTLY over hand-built CardAccessReadResult values — no channel.
//  (B) The `BacDowngradeGuard` suite drives the REAL activation path: a
//      card-role BAC oracle (emrtd::crypto) answers the BAC handshake through
//      the typed-transmit filter and answers the SM-wrapped EF.CardAccess
//      re-read through the detached raw-responder seam, so establish ->
//      re-read -> verdict -> teardown is exercised end to end.
// ---------------------------------------------------------------------------

namespace {

using LibreSCRS::SecureChannel::ChannelActivationError;
using LibreSCRS::SmartCard::Internal::CardAccessReadResult;
using LibreSCRS::SmartCard::Internal::classifyPostBacCardAccess;
using LibreSCRS::SmartCard::Internal::PaceDowngradeVerdict;

CardAccessReadResult makeReadResult(bool mfSelected, bool efDefinitivelyAbsent, bool readSucceeded,
                                    std::vector<std::uint8_t> data)
{
    CardAccessReadResult r;
    r.mfSelected = mfSelected;
    r.efDefinitivelyAbsent = efDefinitivelyAbsent;
    r.readSucceeded = readSucceeded;
    r.data = std::move(data);
    return r;
}

} // namespace

// (A) Pure verdict — the three-outcome fail-closed security logic, proven
// directly. Proceed ONLY on an SM-authenticated definitive absence or a
// complete well-formed no-PACEInfo read; everything else is a downgrade.

TEST(PaceDowngradeVerdict, DefinitiveAbsenceProceeds)
{
    // Clean 6A82 after a real MF selection inside valid SM.
    EXPECT_EQ(classifyPostBacCardAccess(makeReadResult(true, true, false, {})), PaceDowngradeVerdict::Proceed);
}

TEST(PaceDowngradeVerdict, CompleteNoPaceReadProceeds)
{
    // A well-formed EF.CardAccess whose only SecurityInfo is non-PACE.
    ASSERT_TRUE(emrtd::crypto::parseCardAccess(presentNoPaceCardAccess()).empty());
    EXPECT_EQ(classifyPostBacCardAccess(makeReadResult(true, false, true, presentNoPaceCardAccess())),
              PaceDowngradeVerdict::Proceed);
}

TEST(PaceDowngradeVerdict, PaceOidPresentDowngrades)
{
    // >=1 PACE OID in the SM-authenticated answer -> forged Absent -> downgrade.
    ASSERT_FALSE(emrtd::crypto::parseCardAccess(presentPaceCardAccess()).empty());
    EXPECT_EQ(classifyPostBacCardAccess(makeReadResult(true, false, true, presentPaceCardAccess())),
              PaceDowngradeVerdict::Downgrade);
}

TEST(PaceDowngradeVerdict, ReadFailureDowngradesFailClosed)
{
    // MAC failure / anomaly: the helper reports readSucceeded == false and no
    // definitive absence -> fail closed.
    EXPECT_EQ(classifyPostBacCardAccess(makeReadResult(true, false, false, {})), PaceDowngradeVerdict::Downgrade);
    // MF selection itself never landed.
    EXPECT_EQ(classifyPostBacCardAccess(makeReadResult(false, false, false, {})), PaceDowngradeVerdict::Downgrade);
}

TEST(PaceDowngradeVerdict, EmptyOrNonSetReadDowngrades)
{
    // Read "succeeded" but yielded nothing, or not a SecurityInfos SET.
    EXPECT_EQ(classifyPostBacCardAccess(makeReadResult(true, false, true, {})), PaceDowngradeVerdict::Downgrade);
    EXPECT_EQ(classifyPostBacCardAccess(makeReadResult(true, false, true, {0x30, 0x03, 0x02, 0x01, 0x00})),
              PaceDowngradeVerdict::Downgrade);
}

TEST(PaceDowngradeVerdict, TruncatedReadDowngradesFailClosed)
{
    // Outer BER length declares 256 content bytes, only 6 present: a truncated
    // read a lenient scan would silently treat as "no PACE". Must fail closed.
    EXPECT_EQ(classifyPostBacCardAccess(makeReadResult(true, false, true, {0x31, 0x82, 0x01, 0x00, 0x30, 0x03})),
              PaceDowngradeVerdict::Downgrade);
}

// ---------------------------------------------------------------------------
// (B) Card-role BAC oracle + BacDowngradeGuard integration suite.
//
// The oracle plays the CARD side of ICAO 9303-11 BAC using emrtd::crypto:
//   * the typed-transmit filter answers GET CHALLENGE (fixed RND.ICC) and
//     EXTERNAL AUTHENTICATE (decrypts E.IFD to recover RND.IFD / K.IFD,
//     returns E.ICC || M.ICC, and derives the SAME session keys + SSC as
//     LM's BacChannel::establish);
//   * the detached raw-responder answers the SM-wrapped EF.CardAccess re-read
//     with LM's own SM framing (DO'87 / DO'99 / DO'8E over the shared session
//     keys, SSC advanced in lockstep).
// Correctness is cross-validated by LM's INDEPENDENT SecureMessaging accepting
// the oracle's frames (a wrong key/MAC/SSC would make establish or the SM
// re-read fail, reddening the proceed test); the ICAO worked-example vector
// test pins the key derivation against the published constants.
// ---------------------------------------------------------------------------

namespace {

// ICAO Doc 9303-11 BAC worked example (Appendix D): the document whose MRZ
// derives the published K_ENC / K_MAC below.
constexpr const char* kIcaoDocNo = "L898902C";
constexpr const char* kIcaoDob = "690806";
constexpr const char* kIcaoDoe = "940623";

enum class SmRereadScenario {
    AbsentConfirmed,      // SM re-read: EF.CardAccess 6A82 -> proceed
    DeactivatedConfirmed, // SM re-read: EF.CardAccess 6283 (authentic, MACed)
                          // -> proceed; READ must never be issued
    Terminated6285Read,   // SM re-read: EF.CardAccess 6285 + failing READ
                          // -> downgrade (scope guard: widening is exactly 6283)
    PacePresent,          // SM re-read: EF.CardAccess carries a PACE OID -> downgrade
    GarbledRead           // SM re-read: READ BINARY response MAC corrupted -> downgrade
};

// BER length prefix for the DO'87 body (mirrors secure_messaging.cpp).
void appendBerLength(std::vector<std::uint8_t>& out, std::size_t len)
{
    if (len < 0x80) {
        out.push_back(static_cast<std::uint8_t>(len));
    } else {
        out.push_back(0x81);
        out.push_back(static_cast<std::uint8_t>(len));
    }
}

// The card side of a BAC session. Shared (shared_ptr) by the typed-transmit
// filter and the detached raw-responder so the handshake-derived session keys
// reach the SM phase.
struct BacCardOracle
{
    std::vector<std::uint8_t> rndICC = std::vector<std::uint8_t>(8, 0xA5); // fixed card challenge
    std::vector<std::uint8_t> kICC = std::vector<std::uint8_t>(16, 0x5A);  // fixed card key
    emrtd::crypto::BACKeys bacKeys;                                        // deriveBACKeys(doc, dob, doe)

    // Session state populated during EXTERNAL AUTHENTICATE.
    std::vector<std::uint8_t> sessEnc, sessMac, ssc;
    bool established = false;

    SmRereadScenario scenario = SmRereadScenario::AbsentConfirmed;
    int selectCount = 0;     // MF-scoped selects seen in the SM phase
    int smInvocations = 0;   // wrapped APDUs the raw-responder handled
    int rawReadAttempts = 0; // SM READ BINARYs seen in the DeactivatedConfirmed
                             // scenario — the reader must never issue one

    // Handshake + pre-establish plain SELECT (typed transmit()).
    APDUResponse onTransmit(const APDUCommand& cmd)
    {
        namespace det = emrtd::crypto::detail;
        if (cmd.ins == 0xA4 && cmd.p1 == 0x04) {
            return APDUResponse{{}, 0x90, 0x00}; // pre-establish plain SELECT by AID
        }
        if (cmd.ins == 0x84) {
            return APDUResponse{rndICC, 0x90, 0x00}; // GET CHALLENGE
        }
        if (cmd.ins == 0x82) { // EXTERNAL AUTHENTICATE: E.IFD(32) || M.IFD(8)
            if (cmd.data.size() < 40)
                return APDUResponse{{}, 0x6A, 0x80};
            std::vector<std::uint8_t> eIFD(cmd.data.begin(), cmd.data.begin() + 32);
            const auto s = det::des3Decrypt(bacKeys.encKey, eIFD); // 32 bytes, no unpad
            std::vector<std::uint8_t> rndIFD(s.begin(), s.begin() + 8);
            std::vector<std::uint8_t> kIFD(s.begin() + 16, s.begin() + 32);

            std::vector<std::uint8_t> kSeed(16);
            for (std::size_t i = 0; i < 16; ++i)
                kSeed[i] = static_cast<std::uint8_t>(kIFD[i] ^ kICC[i]);
            sessEnc = det::kdf(kSeed, 1, true);
            sessMac = det::kdf(kSeed, 2, true);
            ssc.assign(8, 0);
            std::copy(rndICC.begin() + 4, rndICC.end(), ssc.begin());
            std::copy(rndIFD.begin() + 4, rndIFD.end(), ssc.begin() + 4);

            std::vector<std::uint8_t> r; // RND.ICC || RND.IFD || K.ICC
            r.insert(r.end(), rndICC.begin(), rndICC.end());
            r.insert(r.end(), rndIFD.begin(), rndIFD.end());
            r.insert(r.end(), kICC.begin(), kICC.end());
            auto eICC = det::des3Encrypt(bacKeys.encKey, r);
            auto mICC = det::retailMAC(bacKeys.macKey, det::pad(eICC, 8));
            mICC.resize(8);
            std::vector<std::uint8_t> resp;
            resp.insert(resp.end(), eICC.begin(), eICC.end());
            resp.insert(resp.end(), mICC.begin(), mICC.end());
            established = true;
            return APDUResponse{resp, 0x90, 0x00};
        }
        return APDUResponse{{}, 0x6D, 0x00};
    }

    // SM-wrapped EF.CardAccess re-read (detached raw-responder).
    APDUResponse onTransmitRaw(std::span<const std::uint8_t> wrapped)
    {
        ++smInvocations;
        if (wrapped.size() < 4)
            return APDUResponse{{}, 0x6F, 0x00};
        const std::uint8_t ins = wrapped[1];
        const std::uint8_t p1 = wrapped[2];

        std::vector<std::uint8_t> data;
        std::uint8_t sw1 = 0x90, sw2 = 0x00;
        bool corruptMac = false;

        if (ins == 0xA4 && p1 == 0x04) {
            // restore SELECT by AID after the MF navigation -> success
        } else if (ins == 0xA4 && p1 == 0x00) {
            const bool isMf = (selectCount == 0);
            ++selectCount;
            if (!isMf && scenario == SmRereadScenario::AbsentConfirmed) {
                sw1 = 0x6A;
                sw2 = 0x82; // definitive absence
            } else if (!isMf && scenario == SmRereadScenario::DeactivatedConfirmed) {
                sw1 = 0x62;
                sw2 = 0x83; // authentic "file deactivated" for BOTH EF selects
            } else if (!isMf && scenario == SmRereadScenario::Terminated6285Read) {
                sw1 = 0x62;
                sw2 = 0x85; // termination warning: reader proceeds to READ
            }
        } else if (ins == 0xB0) {
            if (scenario == SmRereadScenario::PacePresent) {
                data = presentPaceCardAccess();
            } else if (scenario == SmRereadScenario::GarbledRead) {
                data = presentPaceCardAccess();
                corruptMac = true; // a genuine bad-MAC frame, not a throw
            } else if (scenario == SmRereadScenario::DeactivatedConfirmed) {
                ++rawReadAttempts; // forbidden: reading a deactivated file
                sw1 = 0x69;
                sw2 = 0x85;
            } else if (scenario == SmRereadScenario::Terminated6285Read) {
                sw1 = 0x69; // authentic failing READ after the 6285 warning
                sw2 = 0x86;
            }
        }
        return wrapResponse(data, sw1, sw2, corruptMac);
    }

    // Build an SM-protected response frame that LM's unprotectWithSW accepts:
    // MAC over SSC || DO'87 || DO'99 (padded), SSC advanced twice per round to
    // stay in lockstep with the reader (protect +1, unprotect +1).
    APDUResponse wrapResponse(const std::vector<std::uint8_t>& data, std::uint8_t sw1, std::uint8_t sw2, bool corrupt)
    {
        namespace det = emrtd::crypto::detail;
        det::incrementSSC(ssc);
        det::incrementSSC(ssc);

        std::vector<std::uint8_t> do87;
        if (!data.empty()) {
            auto ct = det::des3Encrypt(sessEnc, det::pad(data, 8));
            do87.push_back(0x87);
            appendBerLength(do87, 1 + ct.size());
            do87.push_back(0x01);
            do87.insert(do87.end(), ct.begin(), ct.end());
        }
        std::vector<std::uint8_t> do99 = {0x99, 0x02, sw1, sw2};

        std::vector<std::uint8_t> macInput;
        macInput.insert(macInput.end(), ssc.begin(), ssc.end());
        macInput.insert(macInput.end(), do87.begin(), do87.end());
        macInput.insert(macInput.end(), do99.begin(), do99.end());
        auto mac = det::retailMAC(sessMac, det::pad(macInput, 8));
        mac.resize(8);
        if (corrupt)
            mac[0] = static_cast<std::uint8_t>(mac[0] ^ 0xFF);

        std::vector<std::uint8_t> do8e = {0x8E, 0x08};
        do8e.insert(do8e.end(), mac.begin(), mac.end());

        std::vector<std::uint8_t> body;
        body.insert(body.end(), do87.begin(), do87.end());
        body.insert(body.end(), do99.begin(), do99.end());
        body.insert(body.end(), do8e.begin(), do8e.end());
        return APDUResponse{body, 0x90, 0x00};
    }
};

std::shared_ptr<BacCardOracle> armBacDowngradeSession(LibreSCRS::SmartCard::CardSession& session,
                                                      SmRereadScenario scenario)
{
    auto oracle = std::make_shared<BacCardOracle>();
    oracle->scenario = scenario;
    oracle->bacKeys = emrtd::crypto::deriveBACKeys(kIcaoDocNo, kIcaoDob, kIcaoDoe);

    // Pre-cache the BAC input so activation drives establish without prompting.
    LibreSCRS::SecureChannel::BacInput input;
    input.documentNumber = LibreSCRS::Secure::String{kIcaoDocNo};
    input.dateOfBirth = LibreSCRS::Secure::String{kIcaoDob};
    input.dateOfExpiry = LibreSCRS::Secure::String{kIcaoDoe};
    session.setBacInput(std::move(input));

    auto& conn = LibreSCRS::SmartCard::detail::unwrap(session);
    conn.setTransmitFilter([oracle](const APDUCommand& cmd) { return oracle->onTransmit(cmd); });
    conn.setDetachedRawResponder([oracle](std::span<const std::uint8_t> b) { return oracle->onTransmitRaw(b); });
    return oracle;
}

LibreSCRS::SmartCard::AppletAid emrtdAid()
{
    return LibreSCRS::SmartCard::AppletAid{0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01};
}

} // namespace

// The oracle's key derivation matches the ICAO Doc 9303-11 worked example —
// pins the fixture against published constants (independent of LM's own path).
TEST(BacDowngradeGuard, OracleDerivesIcao9303WorkedExampleKeys)
{
    const auto keys = emrtd::crypto::deriveBACKeys(kIcaoDocNo, kIcaoDob, kIcaoDoe);
    const std::vector<std::uint8_t> expectedEnc = {0xAB, 0x94, 0xFD, 0xEC, 0xF2, 0x67, 0x4F, 0xDF,
                                                   0xB9, 0xB3, 0x91, 0xF8, 0x5D, 0x7F, 0x76, 0xF2};
    const std::vector<std::uint8_t> expectedMac = {0x79, 0x62, 0xD9, 0xEC, 0xE0, 0x3D, 0x1A, 0xCD,
                                                   0x4C, 0x76, 0x08, 0x9D, 0xCE, 0x13, 0x15, 0x43};
    EXPECT_EQ(keys.encKey, expectedEnc);
    EXPECT_EQ(keys.macKey, expectedMac);
}

// Forged-Absent: BAC establishes, but the SM-authenticated EF.CardAccess
// re-read carries a PACE OID -> abort via the PACE-detected verdict branch,
// channel torn down. The abort fires from a genuine authenticated re-read
// (the oracle was invoked), not the old throw path.
TEST(BacDowngradeGuard, BacEstablishAbortsWhenSmCardAccessShowsPace)
{
    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("Scripted Contactless Reader");
    ASSERT_NE(session, nullptr);
    auto oracle = armBacDowngradeSession(*session, SmRereadScenario::PacePresent);

    auto result =
        session->activateChannelWithSm(emrtdAid(), LibreSCRS::SmartCard::BacRequest{}, LibreSCRS::CancelToken{});
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), ChannelActivationError::PaceDowngradeDetected);
    EXPECT_TRUE(oracle->established) << "BAC must genuinely establish before the downgrade cross-check";
    EXPECT_GT(oracle->smInvocations, 0) << "the SM re-read must reach the card over the authenticated tunnel";
    EXPECT_FALSE(session->hasLiveSecureChannel()) << "the SM channel must be torn down on a detected downgrade";
}

// Garbled: BAC establishes, but the SM re-read's READ BINARY response carries a
// corrupted MAC -> abort via the fail-closed (read-failure) verdict branch, a
// DIFFERENT branch from the PACE-OID case, both landing PaceDowngradeDetected.
TEST(BacDowngradeGuard, BacEstablishAbortsOnGarbledSmReread)
{
    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("Scripted Contactless Reader");
    ASSERT_NE(session, nullptr);
    auto oracle = armBacDowngradeSession(*session, SmRereadScenario::GarbledRead);

    auto result =
        session->activateChannelWithSm(emrtdAid(), LibreSCRS::SmartCard::BacRequest{}, LibreSCRS::CancelToken{});
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), ChannelActivationError::PaceDowngradeDetected);
    EXPECT_TRUE(oracle->established);
    EXPECT_GT(oracle->smInvocations, 0) << "a real garbled frame must be delivered, not a transport throw";
    EXPECT_FALSE(session->hasLiveSecureChannel());
}

// Genuine BAC-only document: the SM re-read confirms EF.CardAccess is
// definitively absent (clean 6A82) -> activation proceeds, holder returned.
TEST(BacDowngradeGuard, BacEstablishProceedsWhenSmRereadConfirmsAbsence)
{
    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("Scripted Contactless Reader");
    ASSERT_NE(session, nullptr);
    auto oracle = armBacDowngradeSession(*session, SmRereadScenario::AbsentConfirmed);

    {
        auto result =
            session->activateChannelWithSm(emrtdAid(), LibreSCRS::SmartCard::BacRequest{}, LibreSCRS::CancelToken{});
        ASSERT_TRUE(result.has_value()) << "a genuine BAC-only document must not be punished by the downgrade guard";
        EXPECT_TRUE(oracle->established);
        EXPECT_GT(oracle->smInvocations, 0) << "the SM re-read must have actually run over the tunnel";
        // The holder owns the session lock; drop it before probing liveness.
    }
    EXPECT_TRUE(session->hasLiveSecureChannel()) << "the established BAC channel survives a confirmed-absence re-read";
}

// Genuine BAC-only personalization with a DEACTIVATED EF.CardAccess: the
// SM-authenticated 6283 is the chip's own MAC-covered declaration that the
// file is unusable — as definitive as a clean 6A82. Activation proceeds, no
// READ is ever issued against the deactivated file, and a MITM cannot forge
// this signal (the DO'99 status word is covered by the response MAC; a bare
// outer 6283 dies on the missing-DO'8E sentinel path).
TEST(BacDowngradeGuard, BacEstablishProceedsWhenSmRereadConfirmsDeactivation)
{
    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("Scripted Contactless Reader");
    ASSERT_NE(session, nullptr);
    auto oracle = armBacDowngradeSession(*session, SmRereadScenario::DeactivatedConfirmed);

    {
        auto result =
            session->activateChannelWithSm(emrtdAid(), LibreSCRS::SmartCard::BacRequest{}, LibreSCRS::CancelToken{});
        ASSERT_TRUE(result.has_value()) << "an authenticated deactivated EF.CardAccess must not abort BAC";
        EXPECT_TRUE(oracle->established);
        EXPECT_GT(oracle->smInvocations, 0) << "the SM re-read must have actually run over the tunnel";
        EXPECT_EQ(oracle->rawReadAttempts, 0) << "the reader must not READ a file the chip declared deactivated";
    }
    EXPECT_TRUE(session->hasLiveSecureChannel()) << "the established BAC channel survives a deactivated re-read";
}

// Scope guard on the authenticated side: the acceptance set widens by EXACTLY
// 6283. A 6285 termination warning followed by a failing READ stays a
// fail-closed downgrade abort.
TEST(BacDowngradeGuard, BacEstablishAbortsOnTerminationWarningSmReread)
{
    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("Scripted Contactless Reader");
    ASSERT_NE(session, nullptr);
    auto oracle = armBacDowngradeSession(*session, SmRereadScenario::Terminated6285Read);

    auto result =
        session->activateChannelWithSm(emrtdAid(), LibreSCRS::SmartCard::BacRequest{}, LibreSCRS::CancelToken{});
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), ChannelActivationError::PaceDowngradeDetected);
    EXPECT_TRUE(oracle->established);
    EXPECT_GT(oracle->smInvocations, 0);
    EXPECT_FALSE(session->hasLiveSecureChannel());
}

// Consumer (3) of the definitive-absence signal: CardSession's hoisted
// pre-prompt EF.CardAccess check. On a PACE-primary activation over a
// deactivated EF.CardAccess, PaceUnsupported surfaces BEFORE the credential
// provider is ever consulted — no prompt is burned on a card that cannot
// negotiate PACE.
TEST(BacDowngradeGuard, DeactivatedCardAccessSurfacesPaceUnsupportedBeforePrompt)
{
    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("Scripted Contactless Reader");
    ASSERT_NE(session, nullptr);
    auto rig = installLdsRig(*session, /*plainLds=*/false);
    setCardAccessMode(*rig, CardAccessMode::Deactivated);

    bool providerInvoked = false;
    session->setCredentialProvider([&providerInvoked](const LibreSCRS::Auth::AuthRequirement&) {
        providerInvoked = true;
        return LibreSCRS::Auth::CredentialResult::cancelled();
    });

    auto result = session->activateChannelWithSm(
        emrtdAid(), LibreSCRS::SmartCard::PaceRequest{LibreSCRS::Auth::PaceSecretKind::Can}, LibreSCRS::CancelToken{});
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), ChannelActivationError::PaceUnsupported)
        << "a deactivated EF.CardAccess must surface the structural PACE absence pre-prompt";
    EXPECT_FALSE(providerInvoked) << "no credential prompt may be burned on a definitively PACE-less card";
    EXPECT_EQ(rig->deactivatedReadAttempts, 0);
}

// ---------------------------------------------------------------------------
// Structural activation-failure surface (M4 LM half): a PACE-less document and
// a detected downgrade must NOT present as a wrong-credential failure — each
// carries its own structural message key, and the downgrade never wears the
// authenticationFailed shape (so downstream flows never punish the credential).
// ---------------------------------------------------------------------------

// A PACE-less (or unknown-then-empty) document surfaces PaceUnsupported after
// the credential prompt; the readCard mapping must name it distinctly rather
// than fold it into the generic authentication-failed key. SoftFail keeps the
// capability Unknown (fails closed to PACE-CAN); the MF EF.CardAccess
// read then yields no PACEInfo -> PaceUnsupported.
TEST(EmrtdInterfaceActivation, PaceUnsupportedReadCarriesStructuralKey)
{
    CardPluginService registry{pluginDir()};
    auto plugin = findEMRTD(registry);
    ASSERT_NE(plugin, nullptr);

    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("Scripted Contactless Reader");
    ASSERT_NE(session, nullptr);
    auto rig = installLdsRig(*session, /*plainLds=*/false);
    setCardAccessMode(*rig, CardAccessMode::SoftFail); // Unknown -> PaceRequest{Can}, fallback off

    session->setCredentialProvider([](const LibreSCRS::Auth::AuthRequirement&) {
        std::vector<LibreSCRS::Auth::CredentialEntry> values;
        values.push_back({"can", LibreSCRS::Secure::String{"123456"}});
        return LibreSCRS::Auth::CredentialResult::ok(std::move(values));
    });

    ASSERT_TRUE(plugin->canHandleConnection({}, *session));
    auto rr = plugin->readCard(*session);

    EXPECT_EQ(rr.status, ReadResult::Status::AuthenticationFailed);
    EXPECT_EQ(rr.userMessage.key, "librescrs.error.preRead.paceUnsupported")
        << "a structurally PACE-less document must not fold into the generic auth-failed key";
}

namespace {

// Minimal concrete plugin whose activationProfile is a fixed BAC request, so
// the base-class readCard mapping of a channel-activation error can be observed
// in isolation at the seam where it lives (CardPlugin::readCard).
class BacProfilePlugin final : public LibreSCRS::Plugin::CardPlugin
{
public:
    BacProfilePlugin()
    {
        setIdentity("fake-bac", "FakeBac", 0);
    }

    LibreSCRS::Plugin::CardCapabilities capabilities() const override
    {
        return {};
    }

    std::span<const LibreSCRS::Plugin::Atr> supportedAtrs() const noexcept override
    {
        return {};
    }

protected:
    LibreSCRS::Plugin::ActivationProfile
    activationProfile(LibreSCRS::SmartCard::CardSession& /*session*/) const override
    {
        LibreSCRS::Plugin::ActivationProfile profile;
        profile.aid = emrtdAid();
        profile.primary = LibreSCRS::SmartCard::SmProtocolRequest{LibreSCRS::SmartCard::BacRequest{}};
        return profile;
    }

    LibreSCRS::Plugin::ReadResult doReadCard(LibreSCRS::SmartCard::CardSession& /*session*/,
                                             GroupCallback /*onGroup*/) const override
    {
        return LibreSCRS::Plugin::ReadResult::ok({});
    }
};

} // namespace

// The :77-84 downgrade arm: BAC establishes, the SM-authenticated EF.CardAccess
// re-read shows PACE -> PaceDowngradeDetected. The readCard mapping must name it
// with the downgrade key AND must NOT use the authenticationFailed shape — an
// attack signal must never evict or punish a credential.
TEST(BacDowngradeGuard, PaceDowngradeReadCarriesStructuralKeyNotAuthFailed)
{
    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("Scripted Contactless Reader");
    ASSERT_NE(session, nullptr);
    auto oracle = armBacDowngradeSession(*session, SmRereadScenario::PacePresent);

    BacProfilePlugin plugin;
    auto rr = plugin.readCard(*session);

    EXPECT_TRUE(oracle->established) << "BAC must genuinely establish before the downgrade cross-check";
    EXPECT_NE(rr.status, ReadResult::Status::AuthenticationFailed)
        << "a detected downgrade must not present as a wrong-credential failure";
    EXPECT_EQ(rr.userMessage.key, "librescrs.error.preRead.paceDowngradeDetected");
}
