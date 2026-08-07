// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <gtest/gtest.h>
#include <LibreSCRS/Auth/AuthRequirement.h>
#include <LibreSCRS/Auth/CredentialProvider.h>
#include <LibreSCRS/Auth/CredentialResult.h>
#include <LibreSCRS/Auth/PaceSecretKind.h>
#include <LibreSCRS/Plugin/CardPluginService.h>
#include <LibreSCRS/Plugin/SecurityCheck.h>
#include <LibreSCRS/Secure/String.h>
#include <LibreSCRS/SmartCard/CardSession.h>
#include <LibreSCRS/SmartCard/SmProtocolRequest.h>
#include <LibreSCRS/SmartCard/detail/CardSessionInjection.h>
#include <LibreSCRS/SmartCard/detail/Unwrap.h>
#include <LibreSCRS_internal/Plugin/CardPluginActivationAccessor.h>
#include <pace.h>
#include <pcsc_connection.h>

#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <map>
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

// Scripted EF.CardAccess behaviour for the MF-scoped capability probe.
// The default SoftFail keeps every pre-existing rig test byte-for-byte
// identical: those tests never emit an MF-scoped (P1=0x00) SELECT, so the
// knob is inert for them. A test that wants a definitive verdict MUST set
// the knob explicitly — an unset knob asserts Unknown, not Absent.
enum class CardAccessMode {
    AbsentNotFound, // MF ok; SELECT 011C -> 6A82 (definitive absence)
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
    std::vector<APDUCommand> log;
    std::map<uint16_t, std::vector<uint8_t>> files;
    const std::vector<uint8_t>* current = nullptr;
    // MF-scoped EF.CardAccess model. @ref cardAccessData holds the
    // EF.CardAccess bytes served for Present*/Malformed/Truncated modes.
    CardAccessMode cardAccess = CardAccessMode::SoftFail;
    std::vector<uint8_t> cardAccessData;
};

APDUResponse ldsRigTransmit(LdsRigState& st, const APDUCommand& cmd)
{
    st.log.push_back(cmd);
    auto ok = [](std::vector<uint8_t> d = {}) { return APDUResponse{std::move(d), 0x90, 0x00}; };
    auto sw = [](uint8_t a, uint8_t b) { return APDUResponse{{}, a, b}; };

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
        if (!st.plainLds || fid == 0x011D) // whole LDS contactless, EF.SOD always: SM-gated
            return sw(0x69, 0x82);
        st.current = &it->second;
        return ok();
    }
    if (cmd.ins == 0xB0) { // READ BINARY
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

std::shared_ptr<LdsRigState> installLdsRig(LibreSCRS::SmartCard::CardSession& session, bool plainLds)
{
    auto st = std::make_shared<LdsRigState>();
    st->plainLds = plainLds;
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

TEST(EmrtdInterfaceActivation, ContactPlainReadLabelsAuthAndSkipsGenuineness)
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

    // The plain path must label itself honestly and must not run the
    // genuineness protocols: Chip Authentication's key replacement is a
    // documented no-op on a plain channel, so a PASSED/FAILED verdict there
    // would be unverifiable. DG14 raw bytes are still read (PA input).
    EXPECT_EQ(fieldText(*rr.data, "presence", "auth_method").value_or(""), "None (plain read)");
    EXPECT_EQ(fieldText(*rr.data, "security_status", "chip_auth").value_or(""), "NOT_PERFORMED");
    EXPECT_TRUE(logContainsSelectFid(*rig, 0x010E)) << "DG14 raw bytes must still be read on the plain path";
    EXPECT_FALSE(logContainsIns(*rig, 0x22));
    EXPECT_FALSE(logContainsIns(*rig, 0x86));

    // EF.SOD is SM-gated on this rig (as on the shipping document): the
    // plain path must not fabricate ANY passive-auth verdict from it — no
    // pa_* checks may appear, and nothing may be reported as FAILED.
    auto secIdx = rr.data->findGroup("security_status");
    ASSERT_TRUE(secIdx.has_value());
    for (const auto& field : rr.data->groupAt(*secIdx).fields) {
        EXPECT_FALSE(field.key.rfind("pa_", 0) == 0) << "unexpected passive-auth check: " << field.key;
        auto text = field.textValue();
        if (text.has_value()) {
            EXPECT_EQ(text->find("FAILED"), std::string::npos) << field.key << " reported FAILED on the plain path";
        }
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
