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

#include "pkcs15_card.h"
#include "pkcs15_pkcs11_card.h"

#include <internal/Crv.h>
#include <internal/PKCS11ObjectInfo.h>
#include <internal/PKCS11Slot.h>

#include <apdu.h>
#include <pcsc_connection.h>

#include <gtest/gtest.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <stdexcept>
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

    // --- Optional signing behaviour. The defaults answer exactly what the
    // census rows have always seen (6D00), so no profile count moves. ---

    /// VERIFY carrying a PIN: the PINs this card accepts. Empty answers 6D00.
    std::set<std::string> acceptedPins;
    int triesLeft = 3;
    /// The wrong PIN that spends the last try is answered 63C0 rather than
    /// 6983 (some cards do); the VERIFY after it is 6983 either way.
    bool lastTryAnswers63C0 = false;
    /// MSE SET and PSO COMPUTE DIGITAL SIGNATURE (a fixed 256-byte signature).
    bool answersSigning = false;

    /// Per log entry: whether a card transaction was held, and which one.
    struct TransactionMark
    {
        bool held = false;
        int number = 0;
    };
    std::vector<TransactionMark> transactions;
    /// Bumped each time the detached connection releases a transaction.
    int transaction = 0;
    const LibreSCRS::SmartCard::Internal::PCSCConnection* connection = nullptr;

    std::uint16_t selectedFid = 0;

    APDUResponse operator()(const APDUCommand& cmd)
    {
        log.push_back(cmd);
        transactions.push_back(TransactionMark{connection != nullptr && connection->isTransactionHeld(), transaction});

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

        if (cmd.ins == 0x20 && !acceptedPins.empty()) { // VERIFY with a PIN
            if (triesLeft == 0)
                return {{}, 0x69, 0x83};
            std::string pin(cmd.data.begin(), cmd.data.end());
            while (!pin.empty() && (pin.back() == '\0' || pin.back() == '\xFF'))
                pin.pop_back();
            if (acceptedPins.contains(pin)) {
                triesLeft = 3;
                return {{}, 0x90, 0x00};
            }
            --triesLeft;
            if (triesLeft == 0)
                return lastTryAnswers63C0 ? APDUResponse{{}, 0x63, 0xC0} : APDUResponse{{}, 0x69, 0x83};
            return {{}, 0x63, static_cast<std::uint8_t>(0xC0 | triesLeft)};
        }
        if (answersSigning && cmd.ins == 0x22) // MSE SET
            return {{}, 0x90, 0x00};
        if (answersSigning && cmd.ins == 0x2A && cmd.p1 == 0x9E && cmd.p2 == 0x9A) // PSO CDS
            return {std::vector<std::uint8_t>(256, 0x5A), 0x90, 0x00};

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
// pairing in readCertificates resolves and doSign has a key to match. With
// @p userConsent its CommonObjectAttributes carry userConsent INTEGER 1. Its
// modulusLength is the empty INTEGER the census has always read unless
// @p modulusBits is given: a signature needs it to pad the input.
std::vector<std::uint8_t> onePrivateKeyPrkdf(bool userConsent = false, std::uint16_t modulusBits = 0)
{
    std::vector<std::uint8_t> commonObject = {0x0C, 0x03, 0x4B, 0x45, 0x59}; // "KEY"
    if (userConsent)
        commonObject.insert(commonObject.end(), {0x02, 0x01, 0x01});
    std::vector<std::uint8_t> body = {0x30, static_cast<std::uint8_t>(commonObject.size())};
    body.insert(body.end(), commonObject.begin(), commonObject.end());
    // PrivateRSAKeyAttributes: { Path { 3F00/4410, index 0 } [, modulusLength] }
    std::vector<std::uint8_t> rsaAttributes = {0x30, 0x08, 0x04, 0x04, 0x3F, 0x00, 0x44, 0x10, 0x02, 0x00};
    if (modulusBits != 0)
        rsaAttributes.insert(rsaAttributes.end(), {0x02, 0x02, static_cast<std::uint8_t>(modulusBits >> 8),
                                                   static_cast<std::uint8_t>(modulusBits & 0xFF)});
    body.insert(body.end(), {0x30, 0x03, 0x04, 0x01, 0x01, // id 01
                             0xA1, static_cast<std::uint8_t>(rsaAttributes.size() + 2), 0x30,
                             static_cast<std::uint8_t>(rsaAttributes.size())});
    body.insert(body.end(), rsaAttributes.begin(), rsaAttributes.end());
    std::vector<std::uint8_t> out = {0x30, static_cast<std::uint8_t>(body.size())};
    out.insert(out.end(), body.begin(), body.end());
    return out;
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

FakeCardRig makeRig(const char* readerName, bool userConsent = false)
{
    FakeCardRig rig;
    rig.session = makeDetachedCardSession(readerName);
    rig.card = std::make_shared<ScriptedPkcs15Card>();
    rig.card->files = {
        {kEfOdf, fullOdf()},
        {kEfTokenInfo, tokenInfoWithLabel("Census Token")},
        {kPrkdfFid, onePrivateKeyPrkdf(userConsent)},
        {kCdfFid, oneCertCdf()},
        {kAodfFid, plainPinAodf()},
        {kCertFid, certBlob()},
    };
    rig.card->probeTries = {{0x01, 3}};

    auto& conn = LibreSCRS::SmartCard::detail::unwrap(*rig.session);
    rig.card->connection = &conn;
    conn.setDetachedTransactionReleaseObserver([card = rig.card] { ++card->transaction; });
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

// ===========================================================================
// CKA_ALWAYS_AUTHENTICATE from PKCS#15 userConsent, without hardware. The
// same scripted card, with its optional signing behaviour on, serves the
// PKCS#11 slot (a Pkcs15Card bound over the injected session): the slot must
// publish the flag, VERIFY a one-shot PIN, and present it in the SAME card
// transaction as the signature -- never the session login's PIN.
// ===========================================================================

namespace {

namespace Crv = LibreSCRS::Pkcs11::Internal::Crv;
using LibreSCRS::Pkcs11::Internal::PKCS11ObjectInfo;
using LibreSCRS::Pkcs11::Internal::PKCS11Slot;

constexpr unsigned long kCkuUser = 1UL;
constexpr unsigned long kCkmRsaPkcs = 0x0001UL;
constexpr unsigned long kCkoPrivateKey = 3UL;
const std::vector<std::uint8_t> kKeyId{0x01};
const std::vector<std::uint8_t> kToBeSigned(20, 0x42);

FakeCardRig makeSigningRig(const char* readerName, bool userConsent)
{
    auto rig = makeRig(readerName, userConsent);
    rig.card->files[kPrkdfFid] = onePrivateKeyPrkdf(userConsent, 2048);
    rig.card->acceptedPins = {"1234"};
    rig.card->answersSigning = true;
    return rig;
}

struct SlotRig
{
    FakeCardRig rig;
    std::shared_ptr<LibreSCRS::Pkcs15::Pkcs11::Pkcs15Card> p11;
    std::shared_ptr<PKCS11Slot> slot;
};

SlotRig makeSlotRig(const char* readerName, bool userConsent)
{
    SlotRig s;
    s.rig = makeSigningRig(readerName, userConsent);
    s.p11 = std::make_shared<LibreSCRS::Pkcs15::Pkcs11::Pkcs15Card>();
    EXPECT_EQ(s.p11->bindFromInjectedSession(readerName, s.rig.session), Crv::Ok);
    const auto slots = s.p11->enumerateSlots();
    EXPECT_EQ(slots.size(), 1U);
    if (!slots.empty())
        s.slot = slots[0];
    return s;
}

std::vector<std::uint8_t> pinBytes(std::string_view s)
{
    return {s.begin(), s.end()};
}

bool isVerifyWithPin(const APDUCommand& cmd)
{
    return cmd.ins == 0x20 && !cmd.data.empty();
}

bool isPso(const APDUCommand& cmd)
{
    return cmd.ins == 0x2A && cmd.p1 == 0x9E && cmd.p2 == 0x9A;
}

std::string pinOf(const APDUCommand& cmd)
{
    std::string pin(cmd.data.begin(), cmd.data.end());
    while (!pin.empty() && (pin.back() == '\0' || pin.back() == '\xFF'))
        pin.pop_back();
    return pin;
}

std::optional<PKCS11ObjectInfo> privateKeyOf(PKCS11Slot& slot)
{
    for (auto& object : slot.enumerateObjects()) {
        if (object.objectClass == kCkoPrivateKey)
            return object;
    }
    return std::nullopt;
}

// The first PSO after @p mark and the last VERIFY carrying a PIN before it.
struct SignTrace
{
    std::optional<std::size_t> verify;
    std::optional<std::size_t> pso;
};

SignTrace traceSince(const std::vector<APDUCommand>& log, std::size_t mark)
{
    SignTrace t;
    for (std::size_t i = mark; i < log.size(); ++i) {
        if (isPso(log[i])) {
            t.pso = i;
            break;
        }
    }
    if (t.pso) {
        for (std::size_t i = *t.pso; i-- > mark;) {
            if (isVerifyWithPin(log[i])) {
                t.verify = i;
                break;
            }
        }
    }
    return t;
}

} // namespace

TEST(Pkcs15SlotAlwaysAuthenticate, PerOperationKeyIsPublishedWithAlwaysAuthenticate)
{
    auto s = makeSlotRig("AA Slot Reader 0", true);
    ASSERT_NE(s.slot, nullptr);
    const auto key = privateKeyOf(*s.slot);
    ASSERT_TRUE(key.has_value());
    EXPECT_TRUE(key->alwaysAuthenticate);
}

TEST(Pkcs15SlotAlwaysAuthenticate, OrdinaryKeyIsPublishedWithoutAlwaysAuthenticate)
{
    auto s = makeSlotRig("AA Slot Reader 1", false);
    ASSERT_NE(s.slot, nullptr);
    const auto key = privateKeyOf(*s.slot);
    ASSERT_TRUE(key.has_value());
    EXPECT_FALSE(key->alwaysAuthenticate);
}

TEST(Pkcs15SlotAlwaysAuthenticate, CachedPinIsNeverPresentedForAPerOperationKey)
{
    auto s = makeSlotRig("AA Slot Reader 2", true);
    ASSERT_NE(s.slot, nullptr);
    ASSERT_EQ(s.slot->login(kCkuUser, pinBytes("1234")), Crv::Ok);
    const auto mark = s.rig.card->log.size();

    EXPECT_TRUE(s.slot->signData(kToBeSigned, kCkmRsaPkcs, kKeyId).empty());
    EXPECT_TRUE(s.slot->signWithDigestInfo(kToBeSigned, kToBeSigned, kCkmRsaPkcs, kKeyId).empty());

    const auto& log = s.rig.card->log;
    for (std::size_t i = mark; i < log.size(); ++i) {
        EXPECT_FALSE(isVerifyWithPin(log[i])) << "the session login's PIN reached the card";
        EXPECT_FALSE(isPso(log[i])) << "a signature was attempted without this operation's PIN";
    }
}

TEST(Pkcs15SlotAlwaysAuthenticate, ContextPinIsVerifiedAndSignedInOneTransaction)
{
    auto s = makeSlotRig("AA Slot Reader 3", true);
    ASSERT_NE(s.slot, nullptr);
    s.rig.card->acceptedPins = {"1234", "5678"};
    ASSERT_EQ(s.slot->login(kCkuUser, pinBytes("1234")), Crv::Ok);
    const auto mark = s.rig.card->log.size();

    const auto signature = s.slot->signDataWithContextPin(kToBeSigned, kCkmRsaPkcs, kKeyId,
                                                          LibreSCRS::Secure::String{std::string_view{"5678"}});
    ASSERT_TRUE(signature.has_value());
    ASSERT_FALSE(signature->empty());

    const auto& log = s.rig.card->log;
    const auto& marks = s.rig.card->transactions;
    const auto t = traceSince(log, mark);
    ASSERT_TRUE(t.pso.has_value());
    ASSERT_TRUE(t.verify.has_value()) << "no VERIFY preceded the signature";
    EXPECT_EQ(pinOf(log[*t.verify]), "5678") << "only the PIN armed for this operation may reach the card";
    EXPECT_TRUE(marks[*t.verify].held);
    EXPECT_TRUE(marks[*t.pso].held);
    EXPECT_EQ(marks[*t.verify].number, marks[*t.pso].number)
        << "VERIFY and the signature must share one card transaction";
}

TEST(Pkcs15SlotAlwaysAuthenticate, DigestInfoPathPresentsTheContextPinToo)
{
    auto s = makeSlotRig("AA Slot Reader 4", true);
    ASSERT_NE(s.slot, nullptr);
    s.rig.card->acceptedPins = {"1234", "5678"};
    ASSERT_EQ(s.slot->login(kCkuUser, pinBytes("1234")), Crv::Ok);
    const auto mark = s.rig.card->log.size();

    ASSERT_TRUE(s.slot
                    ->signWithDigestInfoAndContextPin(kToBeSigned, kToBeSigned, kCkmRsaPkcs, kKeyId,
                                                      LibreSCRS::Secure::String{std::string_view{"5678"}})
                    .has_value());
    const auto t = traceSince(s.rig.card->log, mark);
    ASSERT_TRUE(t.verify.has_value());
    EXPECT_EQ(pinOf(s.rig.card->log[*t.verify]), "5678");
}

// The library's single retry after a card reset reuses the one-shot PIN on a
// slot the reset has logged out.
TEST(Pkcs15SlotAlwaysAuthenticate, ContextPinSignsAfterACardResetDroppedTheLogin)
{
    auto s = makeSlotRig("AA Slot Reader 5", true);
    ASSERT_NE(s.slot, nullptr);
    ASSERT_EQ(s.slot->login(kCkuUser, pinBytes("1234")), Crv::Ok);
    s.slot->onCardReset();
    ASSERT_FALSE(s.slot->isLoggedIn());

    EXPECT_TRUE(s.slot
                    ->signDataWithContextPin(kToBeSigned, kCkmRsaPkcs, kKeyId,
                                             LibreSCRS::Secure::String{std::string_view{"1234"}})
                    .has_value());
}

TEST(Pkcs15SlotAlwaysAuthenticate, VerifyContextPinReportsAWrongPinWithoutSigning)
{
    auto s = makeSlotRig("AA Slot Reader 6", true);
    ASSERT_NE(s.slot, nullptr);
    ASSERT_EQ(s.slot->login(kCkuUser, pinBytes("1234")), Crv::Ok);
    const auto mark = s.rig.card->log.size();

    EXPECT_EQ(s.slot->verifyContextPin(kKeyId, pinBytes("0000")), Crv::PinIncorrect);
    EXPECT_EQ(s.slot->verifyContextPin(kKeyId, pinBytes("1234")), Crv::Ok);
    EXPECT_TRUE(s.slot->isLoggedIn()) << "the context login must leave the session login alone";

    const auto& log = s.rig.card->log;
    for (std::size_t i = mark; i < log.size(); ++i)
        EXPECT_FALSE(isPso(log[i])) << "verifying a PIN must not sign";
}

TEST(Pkcs15SlotAlwaysAuthenticate, VerifyContextPinRefusesAnOrdinaryKey)
{
    auto s = makeSlotRig("AA Slot Reader 7", false);
    ASSERT_NE(s.slot, nullptr);
    ASSERT_EQ(s.slot->login(kCkuUser, pinBytes("1234")), Crv::Ok);
    const auto mark = s.rig.card->log.size();

    EXPECT_EQ(s.slot->verifyContextPin(kKeyId, pinBytes("1234")), Crv::ArgumentsBad);
    const auto& log = s.rig.card->log;
    for (std::size_t i = mark; i < log.size(); ++i)
        EXPECT_FALSE(isVerifyWithPin(log[i]));
}

TEST(Pkcs15SlotAlwaysAuthenticate, OrdinaryKeyStillSignsWithTheCachedPin)
{
    auto s = makeSlotRig("AA Slot Reader 8", false);
    ASSERT_NE(s.slot, nullptr);
    ASSERT_EQ(s.slot->login(kCkuUser, pinBytes("1234")), Crv::Ok);
    const auto mark = s.rig.card->log.size();

    ASSERT_FALSE(s.slot->signData(kToBeSigned, kCkmRsaPkcs, kKeyId).empty());
    const auto t = traceSince(s.rig.card->log, mark);
    ASSERT_TRUE(t.verify.has_value());
    EXPECT_EQ(pinOf(s.rig.card->log[*t.verify]), "1234");
    EXPECT_EQ(s.rig.card->transactions[*t.verify].number, s.rig.card->transactions[*t.pso].number);
}

// A card that refuses the one-shot PIN inside the signing transaction must be
// told apart from a failure the PIN did not cause: the library retries an
// empty signature once after a card reset, and presenting a refused PIN again
// would cost a second try.
TEST(Pkcs15SlotAlwaysAuthenticate, RefusedContextPinIsReportedApartFromAFailedSignature)
{
    auto s = makeSlotRig("AA Slot Reader 9", true);
    ASSERT_NE(s.slot, nullptr);
    const auto mark = s.rig.card->log.size();

    const auto refused = s.slot->signDataWithContextPin(kToBeSigned, kCkmRsaPkcs, kKeyId,
                                                        LibreSCRS::Secure::String{std::string_view{"0000"}});
    ASSERT_FALSE(refused.has_value());
    EXPECT_EQ(refused.error(), Crv::PinIncorrect);
    const auto& log = s.rig.card->log;
    EXPECT_EQ(std::count_if(log.begin() + static_cast<std::ptrdiff_t>(mark), log.end(), isVerifyWithPin), 1)
        << "a refused PIN is presented once";

    // The PIN is accepted but the card cannot sign: a failure, not a refusal.
    s.rig.card->answersSigning = false;
    const auto failed = s.slot->signWithDigestInfoAndContextPin(kToBeSigned, kToBeSigned, kCkmRsaPkcs, kKeyId,
                                                                LibreSCRS::Secure::String{std::string_view{"1234"}});
    ASSERT_FALSE(failed.has_value());
    EXPECT_EQ(failed.error(), Crv::DeviceError);
}

TEST(Pkcs15SlotAlwaysAuthenticate, BlockedContextPinIsReportedAsLocked)
{
    for (const bool answers63C0 : {false, true}) {
        SCOPED_TRACE(answers63C0 ? "last try answered 63C0" : "last try answered 6983");
        auto s = makeSlotRig(answers63C0 ? "AA Slot Reader 11" : "AA Slot Reader 10", true);
        ASSERT_NE(s.slot, nullptr);
        s.rig.card->triesLeft = 1;
        s.rig.card->lastTryAnswers63C0 = answers63C0;

        const auto blocked = s.slot->signDataWithContextPin(kToBeSigned, kCkmRsaPkcs, kKeyId,
                                                            LibreSCRS::Secure::String{std::string_view{"0000"}});
        ASSERT_FALSE(blocked.has_value());
        EXPECT_EQ(blocked.error(), Crv::PinLocked);
    }
}

// The session login reads the card's refusal as the per-operation path does:
// a wrong PIN that leaves no tries (63C0) is a blocked PIN, not a wrong one.
TEST(Pkcs15SlotLogin, WrongPinThatSpendsTheLastTryIsLocked)
{
    for (const bool answers63C0 : {false, true}) {
        SCOPED_TRACE(answers63C0 ? "last try answered 63C0" : "last try answered 6983");
        auto s = makeSlotRig(answers63C0 ? "AA Login Reader 1" : "AA Login Reader 0", false);
        ASSERT_NE(s.slot, nullptr);
        s.rig.card->lastTryAnswers63C0 = answers63C0;
        s.rig.card->triesLeft = 2;
        EXPECT_EQ(s.slot->login(kCkuUser, pinBytes("0000")), Crv::PinIncorrect) << "one try left is not blocked";
        EXPECT_EQ(s.slot->login(kCkuUser, pinBytes("0000")), Crv::PinLocked);
    }
}

TEST(Pkcs15PinRefusal, NoTriesLeftIsABlockedPin)
{
    using pkcs15::PinResult;
    using pkcs15::refusalBlocksPin;
    EXPECT_TRUE(refusalBlocksPin(PinResult{false, 0, true}));   // 6983
    EXPECT_TRUE(refusalBlocksPin(PinResult{false, 0, false}));  // 63C0
    EXPECT_FALSE(refusalBlocksPin(PinResult{false, 1, false})); // 63C1
    EXPECT_FALSE(refusalBlocksPin(PinResult{false, -1, false})) << "an unknown count is not a blocked PIN";
    EXPECT_FALSE(refusalBlocksPin(PinResult{true, -1, false}));
}

// ---------------------------------------------------------------------------
// The card plugin's "pin" credential
// ---------------------------------------------------------------------------

// An empty "pin" erases the signing PIN and nothing else. NotImplemented
// would mean the whole session entry went -- the PACE requirement with it --
// which is clearCredentials, not this.
TEST(Pkcs15PluginPinCredential, ErasingThePinKeepsThePaceRequirement)
{
    auto rig = makeRig("AA Plugin Reader 0", true);
    CardPluginService registry{pluginDir()};
    auto plugin = findPkcs15(registry);
    ASSERT_NE(plugin, nullptr);

    plugin->setCredentials(*rig.session, "can", LibreSCRS::Secure::String{std::string_view{"123456"}});
    plugin->setCredentials(*rig.session, "pin", LibreSCRS::Secure::String{std::string_view{"1234"}});
    plugin->setCredentials(*rig.session, "pin", LibreSCRS::Secure::String{});

    const auto result = plugin->sign(*rig.session, 0x4410, kToBeSigned, LibreSCRS::Plugin::SignMechanism::RSA_SHA256);
    EXPECT_EQ(result.outcome, LibreSCRS::Plugin::SignResultOutcome::PluginError);
}

TEST(Pkcs15PluginPinCredential, ErasedPinStopsTheNextSignBeforeTheCard)
{
    auto rig = makeRig("AA Plugin Reader 1", true);
    CardPluginService registry{pluginDir()};
    auto plugin = findPkcs15(registry);
    ASSERT_NE(plugin, nullptr);
    plugin->setCredentials(*rig.session, "can", LibreSCRS::Secure::String{std::string_view{"123456"}});
    plugin->setCredentials(*rig.session, "pin", LibreSCRS::Secure::String{std::string_view{"1234"}});

    // Control: with a PIN deposited, the sign goes to the card.
    auto transactions = rig.card->transaction;
    auto apdus = rig.card->log.size();
    (void)plugin->sign(*rig.session, 0x4410, kToBeSigned, LibreSCRS::Plugin::SignMechanism::RSA_SHA256);
    ASSERT_TRUE(rig.card->transaction > transactions || rig.card->log.size() > apdus)
        << "rig regression: a deposited PIN no longer drives the sign to the card";

    plugin->setCredentials(*rig.session, "pin", LibreSCRS::Secure::String{});
    transactions = rig.card->transaction;
    apdus = rig.card->log.size();
    const auto result = plugin->sign(*rig.session, 0x4410, kToBeSigned, LibreSCRS::Plugin::SignMechanism::RSA_SHA256);

    EXPECT_EQ(result.outcome, LibreSCRS::Plugin::SignResultOutcome::PluginError);
    EXPECT_EQ(rig.card->transaction, transactions);
    EXPECT_EQ(rig.card->log.size(), apdus) << "an erased PIN must stop the sign before anything reaches the card";
}

// PKCS15Card::sign owns VERIFY + MSE + PSO, so the card's refusal of the PIN
// it presents must stay readable after the throw (pinRefusal) for the plugin
// to report PinIncorrect / PinBlocked instead of PluginError -- and a blocked
// PIN (6983) is a verdict like a wrong one: it is presented once, never again
// on another reference or path. (The plugin's own hash-on-card sign needs a
// PACE channel, which a detached session cannot establish, so the verdict is
// held at the layer the plugin reads it from.)
TEST(Pkcs15CardSignPin, RefusedPinIsPresentedOnceAndKeptForTheCaller)
{
    struct Case
    {
        int triesBefore;
        bool answers63C0;
        const char* reader;
    };
    for (const auto& c :
         {Case{3, false, "AA Card Reader 0"}, Case{1, false, "AA Card Reader 1"}, Case{1, true, "AA Card Reader 2"}}) {
        const int triesBefore = c.triesBefore;
        SCOPED_TRACE(c.reader);
        auto rig = makeSigningRig(c.reader, true);
        rig.card->triesLeft = triesBefore;
        rig.card->lastTryAnswers63C0 = c.answers63C0;
        auto& conn = LibreSCRS::SmartCard::detail::unwrap(*rig.session);
        PlainChannel channel(conn, pkcs15Aid());
        pkcs15::PKCS15Card card(channel);
        const auto profile = card.readProfile();
        ASSERT_FALSE(profile.privateKeys.empty());
        ASSERT_FALSE(profile.pins.empty());

        const auto mark = rig.card->log.size();
        EXPECT_THROW((void)card.sign(profile.privateKeys[0], "0000", profile.pins[0], kToBeSigned, kToBeSigned,
                                     pkcs15::SignScheme::RsaPkcs1),
                     std::runtime_error);
        const auto& log = rig.card->log;
        EXPECT_EQ(std::count_if(log.begin() + static_cast<std::ptrdiff_t>(mark), log.end(), isVerifyWithPin), 1)
            << "a refused PIN is presented once";

        ASSERT_TRUE(card.pinRefusal().has_value());
        EXPECT_FALSE(card.pinRefusal()->success);
        // The plugin reports PinBlocked exactly when refusalBlocksPin holds.
        if (triesBefore == 3) {
            EXPECT_FALSE(card.pinRefusal()->blocked);
            EXPECT_EQ(card.pinRefusal()->retriesLeft, 2);
            EXPECT_FALSE(pkcs15::refusalBlocksPin(*card.pinRefusal()));
        } else if (c.answers63C0) {
            EXPECT_EQ(card.pinRefusal()->retriesLeft, 0);
            EXPECT_TRUE(pkcs15::refusalBlocksPin(*card.pinRefusal())) << "63C0 leaves no tries: a blocked PIN";
        } else {
            EXPECT_TRUE(card.pinRefusal()->blocked) << "6983 is a blocked PIN, not 'no strategy worked'";
            EXPECT_TRUE(pkcs15::refusalBlocksPin(*card.pinRefusal()));
        }
    }
}

// ---------------------------------------------------------------------------
// The card plugin's CertificateData
// ---------------------------------------------------------------------------

TEST(Pkcs15PluginAlwaysAuthenticate, PerOperationKeyIsReportedInCertificateData)
{
    auto rig = makeRig("AA Plugin Reader 2", true);
    CardPluginService registry{pluginDir()};
    auto plugin = findPkcs15(registry);
    ASSERT_NE(plugin, nullptr);

    const auto certs = plugin->readCertificates(*rig.session);
    ASSERT_EQ(certs.size(), 1U);
    EXPECT_TRUE(certs[0].alwaysAuthenticate);
}

TEST(Pkcs15PluginAlwaysAuthenticate, OrdinaryKeyIsReportedWithoutTheFlag)
{
    auto rig = makeRig("AA Plugin Reader 3", false);
    CardPluginService registry{pluginDir()};
    auto plugin = findPkcs15(registry);
    ASSERT_NE(plugin, nullptr);

    const auto certs = plugin->readCertificates(*rig.session);
    ASSERT_EQ(certs.size(), 1U);
    EXPECT_FALSE(certs[0].alwaysAuthenticate);
}
