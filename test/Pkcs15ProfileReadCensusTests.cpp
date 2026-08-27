// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

// EF.ODF re-read census for pkcs15-plugin's public entry points.
//
// PKCS15Card::readProfile is the plugin's heavyweight structural read
// (applet SELECT + EF.ODF + EF.TokenInfo + CDF + PrKDF + AODF). Ten call
// sites in pkcs15_card_plugin.cpp invoke it, and two source comments there
// describe the repeated acquireChannel/readProfile/findPin shape as
// deliberate. This suite measures how many times readProfile actually
// EXECUTES per public entry point, so a proposal to cache the parsed
// profile is argued from a measured number rather than from the static
// call-site count.
//
// Counting method: SELECT-by-FID of EF.ODF (0x5031) is emitted by
// readProfile and by nothing else — `{0x50, 0x31}` occurs exactly once in
// lib/, inside readProfile — so the number of such APDUs on the wire IS
// the number of readProfile executions. readTokenInfo reads EF.TokenInfo
// (0x5032) without touching EF.ODF, which the census asserts explicitly so
// the marker's specificity is itself under test.
//
// Harness: the plugin .so through the registry against a scripted PKCS#15
// card behind the PCSCConnection transmit filter on a detached
// CardSession, mirroring Pkcs15PinLifecycleTests. Every APDU is recorded
// BY VALUE — assertions scan value snapshots and never hold pointers into
// the filter's state across transmits. No hardware, no PC/SC, no real
// credential values.

#include <LibreSCRS/Plugin/CardPlugin.h>
#include <LibreSCRS/Plugin/CardPluginService.h>
#include <LibreSCRS/Secure/String.h>
#include <LibreSCRS/SmartCard/AppletAid.h>
#include <LibreSCRS/SmartCard/CardSession.h>
#include <LibreSCRS/SmartCard/detail/CardSessionInjection.h>
#include <LibreSCRS/SmartCard/detail/ChannelInjection.h>
#include <LibreSCRS/SmartCard/detail/Unwrap.h>
#include <LibreSCRS_internal/SecureChannel/PlainChannel.h>

#include <apdu.h>
#include <pcsc_connection.h>

#include <gtest/gtest.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <map>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace {

using LibreSCRS::Plugin::CardPlugin;
using LibreSCRS::Plugin::CardPluginService;
using LibreSCRS::SecureChannel::PlainChannel;
using LibreSCRS::SmartCard::AppletAid;
using LibreSCRS::SmartCard::CardSession;
using LibreSCRS::SmartCard::detail::ChannelInjector;
using LibreSCRS::SmartCard::detail::makeDetachedCardSession;
using LibreSCRS::SmartCard::Internal::APDUCommand;
using LibreSCRS::SmartCard::Internal::APDUResponse;

// PKCS#15 application AID (A0 00 00 00 63 "PKCS-15").
AppletAid pkcs15Aid()
{
    return AppletAid{0xA0, 0x00, 0x00, 0x00, 0x63, 0x50, 0x4B, 0x43, 0x53, 0x2D, 0x31, 0x35};
}

constexpr std::uint16_t kEfOdf = 0x5031;
constexpr std::uint16_t kEfTokenInfo = 0x5032;
constexpr std::uint16_t kPrkdfFid = 0x4401;
constexpr std::uint16_t kCdfFid = 0x4404;
constexpr std::uint16_t kAodfFid = 0x4408;
constexpr std::uint16_t kCertFid = 0x4410;

// ---------------------------------------------------------------------------
// Scripted PKCS#15 card (the transmit-funnel test double).
// ---------------------------------------------------------------------------

struct ScriptedPkcs15Card
{
    std::map<std::uint16_t, std::vector<std::uint8_t>> files;
    std::vector<std::uint16_t> selectableDfs{0x3F00};
    /// Empty-VERIFY probe answers: PIN reference → remaining tries.
    std::map<std::uint8_t, int> probeTries;
    std::vector<APDUCommand> log;

    std::uint16_t selectedFid = 0;

    APDUResponse operator()(const APDUCommand& cmd)
    {
        log.push_back(cmd);

        if (cmd.ins == 0xA4 && cmd.p1 == 0x04) // SELECT by AID
            return {{}, 0x90, 0x00};

        if (cmd.ins == 0xA4 && cmd.p1 == 0x00 && cmd.data.size() == 2) { // SELECT by FID
            const auto fid = static_cast<std::uint16_t>((cmd.data[0] << 8) | cmd.data[1]);
            const bool known = files.contains(fid) ||
                               std::find(selectableDfs.begin(), selectableDfs.end(), fid) != selectableDfs.end();
            if (!known)
                return {{}, 0x6A, 0x82};
            selectedFid = fid;
            return {{}, 0x90, 0x00};
        }

        if (cmd.ins == 0xB0) { // READ BINARY
            const auto it = files.find(selectedFid);
            if (it == files.end())
                return {{}, 0x69, 0x86};
            const std::size_t offset = (static_cast<std::size_t>(cmd.p1 & 0x7F) << 8) | cmd.p2;
            if (offset >= it->second.size())
                return {{}, 0x62, 0x82}; // EOF
            const std::size_t n = std::min<std::size_t>(cmd.le != 0 ? cmd.le : 256, it->second.size() - offset);
            std::vector<std::uint8_t> chunk(it->second.begin() + static_cast<std::ptrdiff_t>(offset),
                                            it->second.begin() + static_cast<std::ptrdiff_t>(offset + n));
            return {std::move(chunk), 0x90, 0x00};
        }

        if (cmd.ins == 0x20 && cmd.data.empty()) { // empty-VERIFY retry-counter probe
            const auto it = probeTries.find(cmd.p2);
            if (it == probeTries.end())
                return {{}, 0x6A, 0x88};
            return {{}, 0x63, static_cast<std::uint8_t>(0xC0 | (it->second & 0x0F))};
        }

        return {{}, 0x6D, 0x00}; // anything else: instruction not supported
    }
};

/// The readProfile marker: SELECT-by-FID of EF.ODF. readProfile is the ONLY
/// producer of this APDU in the whole library, so counting it counts
/// readProfile executions exactly.
bool isSelectEfOdf(const APDUCommand& cmd)
{
    return cmd.ins == 0xA4 && cmd.p1 == 0x00 && cmd.data.size() == 2 && cmd.data[0] == 0x50 && cmd.data[1] == 0x31;
}

std::size_t countProfileReads(const std::vector<APDUCommand>& log)
{
    return static_cast<std::size_t>(std::count_if(log.begin(), log.end(), isSelectEfOdf));
}

// ---------------------------------------------------------------------------
// Fixture files.
// ---------------------------------------------------------------------------

// EF.ODF listing all three directories readProfile walks: [A0] PrKDF,
// [A4] CDF, [A8] AODF. A full-shape ODF is deliberate — a profile read
// against it performs the maximal structural walk, which is the shape a
// cache proposal would be trying to avoid repeating.
std::vector<std::uint8_t> fullOdf()
{
    return {
        0xA0, 0x06, 0x30, 0x04, 0x04, 0x02, 0x44, 0x01, // privateKeys → 4401
        0xA4, 0x06, 0x30, 0x04, 0x04, 0x02, 0x44, 0x04, // certificates → 4404
        0xA8, 0x06, 0x30, 0x04, 0x04, 0x02, 0x44, 0x08, // authObjects → 4408
    };
}

// Minimal EF.TokenInfo: SEQUENCE { INTEGER 0, OCTET STRING serial,
// [0] IMPLICIT label }.
std::vector<std::uint8_t> tokenInfoWithLabel(const std::string& label)
{
    std::vector<std::uint8_t> inner = {0x02, 0x01, 0x00, 0x04, 0x02, 0x30, 0x31};
    inner.push_back(0x80);
    inner.push_back(static_cast<std::uint8_t>(label.size()));
    inner.insert(inner.end(), label.begin(), label.end());
    std::vector<std::uint8_t> out = {0x30, static_cast<std::uint8_t>(inner.size())};
    out.insert(out.end(), inner.begin(), inner.end());
    return out;
}

// EF.AODF: ONE plain PIN ("PIN", ref 0x01, initialized, 4/4/8, path 3F00).
std::vector<std::uint8_t> plainPinAodf()
{
    return {0x30, 0x29,                               // SEQUENCE (41)
            0x30, 0x05, 0x0C, 0x03, 0x50, 0x49, 0x4E, //   CommonObjectAttributes "PIN"
            0x30, 0x03, 0x04, 0x01, 0x01,             //   CommonAuthObjectAttributes: id 01
            0xA1, 0x1B, 0x30, 0x19,                   //   [1] { PinAttributes
            0x03, 0x02, 0x00, 0x08,                   //     pinFlags 0x08 (initialized)
            0x0A, 0x01, 0x01,                         //     pinType ascii
            0x02, 0x01, 0x04,                         //     minLength 4
            0x02, 0x01, 0x04,                         //     storedLength 4
            0x02, 0x01, 0x08,                         //     maxLength 8
            0x80, 0x01, 0x01,                         //     pinReference 0x01
            0x30, 0x04, 0x04, 0x02, 0x3F, 0x00};      //     path 3F00 }
}

// EF.CDF: ONE certificate ("Cert", id 01) whose content lives at FID 4410.
// Present so readCertificates performs its per-certificate SELECT+READ work
// on top of the profile read — proving the census counts profile reads and
// not merely "entry point touched the card".
std::vector<std::uint8_t> oneCertCdf()
{
    return {0x30, 0x17,                                     // SEQUENCE (23)
            0x30, 0x06, 0x0C, 0x04, 0x43, 0x65, 0x72, 0x74, //   CommonObjectAttributes "Cert"
            0x30, 0x03, 0x04, 0x01, 0x01,                   //   CommonCertificateAttributes: id 01
            0xA1, 0x08, 0x30, 0x06, 0x04, 0x04,             //   [1] { SEQUENCE { OCTET STRING
            0x3F, 0x00, 0x44, 0x10};                        //     path 3F00/4410 } }
}

// EF.PrKDF: ONE RSA private key (id 01) at path 3F00/4410, so the key/cert
// pairing in readCertificates resolves and doSign has a key to match.
std::vector<std::uint8_t> onePrivateKeyPrkdf()
{
    return {0x30, 0x1A,                                     // SEQUENCE (26)
            0x30, 0x05, 0x0C, 0x03, 0x4B, 0x45, 0x59,       //   CommonObjectAttributes "KEY"
            0x30, 0x03, 0x04, 0x01, 0x01,                   //   CommonKeyAttributes: id 01
            0xA1, 0x0C, 0x30, 0x0A, 0x30, 0x08, 0x04, 0x04, //   [1] { ... OCTET STRING
            0x3F, 0x00, 0x44, 0x10, 0x02, 0x00};            //     path 3F00/4410 }
}

// Stand-in certificate content. The census never parses it as X.509; it only
// needs a non-empty READ BINARY payload so readCertificates keeps the entry.
std::vector<std::uint8_t> certBlob()
{
    return {0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02};
}

// ---------------------------------------------------------------------------
// Harness.
// ---------------------------------------------------------------------------

struct FakeCardRig
{
    std::shared_ptr<CardSession> session;
    std::shared_ptr<ScriptedPkcs15Card> card;
};

FakeCardRig makeRig(const char* readerName)
{
    FakeCardRig rig;
    rig.session = makeDetachedCardSession(readerName);
    rig.card = std::make_shared<ScriptedPkcs15Card>();
    rig.card->files = {
        {kEfOdf, fullOdf()},
        {kEfTokenInfo, tokenInfoWithLabel("Census Token")},
        {kPrkdfFid, onePrivateKeyPrkdf()},
        {kCdfFid, oneCertCdf()},
        {kAodfFid, plainPinAodf()},
        {kCertFid, certBlob()},
    };
    rig.card->probeTries = {{0x01, 3}};

    auto& conn = LibreSCRS::SmartCard::detail::unwrap(*rig.session);
    conn.setTransmitFilter([card = rig.card](const APDUCommand& cmd) { return (*card)(cmd); });

    // Pre-install a PlainChannel bound to the PKCS#15 AID so the plugin's
    // activateChannelFor takes the injected-channel fast path (a detached
    // session cannot run a real SELECT-based activation).
    ChannelInjector::installForTesting(*rig.session, std::make_unique<PlainChannel>(conn, pkcs15Aid()));
    return rig;
}

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

// One census row: drive `op` against a FRESH rig and return how many
// readProfile executions it produced.
template <typename Op>
std::size_t profileReadsFor(const char* readerName, Op&& op)
{
    auto rig = makeRig(readerName);
    CardPluginService registry{pluginDir()};
    auto plugin = findPkcs15(registry);
    EXPECT_NE(plugin, nullptr);
    if (plugin == nullptr)
        return 0;
    op(*plugin, *rig.session);
    return countProfileReads(rig.card->log);
}

} // namespace

// ---------------------------------------------------------------------------
// Marker validity: EF.ODF SELECT is emitted by readProfile and by nothing
// else. readTokenInfo reads EF.TokenInfo directly, so it must produce ZERO
// profile reads while still reaching the card. Without this anchor the
// census could be silently counting "any card touch".
// ---------------------------------------------------------------------------
TEST(Pkcs15ProfileReadCensus, ReadTokenInfoTouchesCardWithoutReadingTheProfile)
{
    auto rig = makeRig("Census Reader TokenInfo");
    CardPluginService registry{pluginDir()};
    auto plugin = findPkcs15(registry);
    ASSERT_NE(plugin, nullptr);

    const auto group = plugin->readTokenInfo(*rig.session);

    EXPECT_EQ(countProfileReads(rig.card->log), 0u) << "readTokenInfo must not perform a full profile read";
    EXPECT_FALSE(rig.card->log.empty()) << "readTokenInfo did not reach the card at all; the rig is not wired";
    EXPECT_EQ(group.groupKey, "token");
}

// ---------------------------------------------------------------------------
// The census proper. Each public entry point is driven against its own
// fresh rig, and the profile-read count is asserted. These expectations are
// the measurement of record: if a future change makes any entry point read
// the profile more than once, the corresponding row turns red.
// ---------------------------------------------------------------------------

TEST(Pkcs15ProfileReadCensus, ReadCardPerformsExactlyOneProfileRead)
{
    const auto n = profileReadsFor("Census Reader ReadCard", [](CardPlugin& p, CardSession& s) {
        const auto result = p.readCard(s);
        EXPECT_EQ(result.status, LibreSCRS::Plugin::ReadResult::Status::Ok)
            << "readCard did not complete against the scripted card";
    });
    EXPECT_EQ(n, 1u);
}

TEST(Pkcs15ProfileReadCensus, ReadCertificatesPerformsExactlyOneProfileRead)
{
    std::size_t certCount = 0;
    const auto n = profileReadsFor("Census Reader ReadCertificates", [&certCount](CardPlugin& p, CardSession& s) {
        certCount = p.readCertificates(s).size();
    });
    // The per-certificate SELECT+READ work happened on top of the profile
    // read; the count must still be one.
    EXPECT_EQ(certCount, 1u) << "fixture regression: the scripted CDF no longer yields a readable certificate";
    EXPECT_EQ(n, 1u);
}

TEST(Pkcs15ProfileReadCensus, GetPinListPerformsExactlyOneProfileRead)
{
    std::size_t pinCount = 0;
    const auto n = profileReadsFor("Census Reader GetPinList",
                                   [&pinCount](CardPlugin& p, CardSession& s) { pinCount = p.getPINList(s).size(); });
    EXPECT_EQ(pinCount, 1u) << "fixture regression: the scripted AODF no longer yields a PIN entry";
    EXPECT_EQ(n, 1u);
}

TEST(Pkcs15ProfileReadCensus, ReadCountersPerformsExactlyOneProfileRead)
{
    const auto n = profileReadsFor("Census Reader ReadCounters",
                                   [](CardPlugin& p, CardSession& s) { (void)p.readCounters(s, "PIN"); });
    EXPECT_EQ(n, 1u);
}

TEST(Pkcs15ProfileReadCensus, VerifyPinPerformsExactlyOneProfileRead)
{
    const auto n = profileReadsFor("Census Reader VerifyPin", [](CardPlugin& p, CardSession& s) {
        LibreSCRS::Secure::String value{std::string_view{"0000"}};
        (void)p.verifyPIN(s, value);
    });
    EXPECT_EQ(n, 1u);
}

TEST(Pkcs15ProfileReadCensus, ChangePinPerformsExactlyOneProfileRead)
{
    const auto n = profileReadsFor("Census Reader ChangePin", [](CardPlugin& p, CardSession& s) {
        LibreSCRS::Secure::String oldValue{std::string_view{"0000"}};
        LibreSCRS::Secure::String newValue{std::string_view{"1111"}};
        (void)p.changePIN(s, "PIN", oldValue, newValue);
    });
    EXPECT_EQ(n, 1u);
}

TEST(Pkcs15ProfileReadCensus, UnblockPinPerformsExactlyOneProfileRead)
{
    const auto n = profileReadsFor("Census Reader UnblockPin", [](CardPlugin& p, CardSession& s) {
        LibreSCRS::Secure::String puk{std::string_view{"00000000"}};
        LibreSCRS::Secure::String newValue{std::string_view{"1111"}};
        (void)p.unblockPIN(s, "PIN", puk, newValue);
    });
    EXPECT_EQ(n, 1u);
}

TEST(Pkcs15ProfileReadCensus, ActivateTransportPinPerformsExactlyOneProfileRead)
{
    const auto n = profileReadsFor("Census Reader ActivateTransportPin", [](CardPlugin& p, CardSession& s) {
        LibreSCRS::Secure::String transport{std::string_view{"00000000"}};
        LibreSCRS::Secure::String newValue{std::string_view{"1111"}};
        (void)p.activateTransportPin(s, "PIN", transport, newValue);
    });
    EXPECT_EQ(n, 1u);
}

TEST(Pkcs15ProfileReadCensus, ActivateSigningKeyPerformsExactlyOneProfileRead)
{
    const auto n = profileReadsFor("Census Reader ActivateSigningKey", [](CardPlugin& p, CardSession& s) {
        LibreSCRS::Secure::String signPin{std::string_view{"0000"}};
        (void)p.activateSigningKey(s, signPin);
    });
    EXPECT_EQ(n, 1u);
}

// ---------------------------------------------------------------------------
// Cross-entry-point census: the profile is invariant for the life of a card
// session, so ONE session pays for ONE read however many entry points run —
// the parsed profile is cached in the plugin's SessionContext and dies with
// it. This suite used to pin the numbers at 1/2/3 (each entry point opened
// its own transaction and re-read the profile); that measurement is what
// argued for a session-scoped cache, and these inverted expectations are the
// cache's regression guard. The invalidation contract is the test below.
// ---------------------------------------------------------------------------
TEST(Pkcs15ProfileReadCensus, SequentialEntryPointsShareOneProfileRead)
{
    auto rig = makeRig("Census Reader Sequential");
    CardPluginService registry{pluginDir()};
    auto plugin = findPkcs15(registry);
    ASSERT_NE(plugin, nullptr);

    const auto readResult = plugin->readCard(*rig.session);
    EXPECT_EQ(readResult.status, LibreSCRS::Plugin::ReadResult::Status::Ok);
    const auto afterReadCard = countProfileReads(rig.card->log);

    (void)plugin->readCertificates(*rig.session);
    const auto afterReadCertificates = countProfileReads(rig.card->log);

    (void)plugin->getPINList(*rig.session);
    const auto afterGetPinList = countProfileReads(rig.card->log);

    EXPECT_EQ(afterReadCard, 1u);
    EXPECT_EQ(afterReadCertificates, 1u) << "second entry point re-read the profile the cache should have served";
    EXPECT_EQ(afterGetPinList, 1u) << "third entry point re-read the profile the cache should have served";
}

// clearCredentials erases the whole SessionContext — the cached profile must
// go with it, so a session whose credentials were cleared re-reads from the
// card instead of serving structure that may have outlived a card swap.
TEST(Pkcs15ProfileReadCensus, ClearCredentialsDropsTheCachedProfile)
{
    auto rig = makeRig("Census Reader ClearCredentials");
    CardPluginService registry{pluginDir()};
    auto plugin = findPkcs15(registry);
    ASSERT_NE(plugin, nullptr);

    (void)plugin->readCard(*rig.session);
    EXPECT_EQ(countProfileReads(rig.card->log), 1u);

    plugin->clearCredentials(*rig.session);

    (void)plugin->readCertificates(*rig.session);
    EXPECT_EQ(countProfileReads(rig.card->log), 2u)
        << "a cleared session must not serve the previous session's profile";
}
