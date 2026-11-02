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
//
// The same scripted card also carries the plugin's signing cases, ECDSA and
// RSA: what each mechanism sends the card, and that the answer verifies.

#include <LibreSCRS/Plugin/CardPlugin.h>
#include <LibreSCRS/Plugin/CardPluginService.h>
#include <LibreSCRS/Logging.h>
#include <LibreSCRS/Secure/String.h>
#include <LibreSCRS/SmartCard/AppletAid.h>
#include <LibreSCRS/SmartCard/CardSession.h>
#include <LibreSCRS/SmartCard/testing/CardSessionTesting.h>
#include <LibreSCRS/SmartCard/detail/ChannelInjection.h>
#include <LibreSCRS/SmartCard/detail/Unwrap.h>
#include <LibreSCRS_internal/SecureChannel/PlainChannel.h>

#include "pkcs15_card.h"

#include "ec_test_key.h"
#include "fixtures/appletsuitegen1_aodf_20260718.h"
#include "pkcs15_test_vectors.h"
#include "rsa_test_key.h"

#include <LibreSCRS_internal/Crypto/DigestInfo.h>

#include "ScriptedPkcs15Card.h"

#include <apdu.h>
#include <pcsc_connection.h>

#include <gtest/gtest.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <initializer_list>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace {

using LibreSCRS::Plugin::CardPlugin;
using LibreSCRS::Plugin::CardPluginService;
using LibreSCRS::SecureChannel::PlainChannel;
using LibreSCRS::SmartCard::CardSession;
using LibreSCRS::SmartCard::detail::ChannelInjector;
using LibreSCRS::SmartCard::Internal::APDUCommand;
using LibreSCRS::SmartCard::Internal::APDUResponse;
using LibreSCRS::SmartCard::Testing::makeDetachedCardSession;
using LibreSCRS::TestSupport::pkcs15Aid;
using LibreSCRS::TestSupport::plainPinAodf;
using LibreSCRS::TestSupport::ScriptedPkcs15Card;
using LibreSCRS::TestSupport::tokenInfoWithLabel;

constexpr std::uint16_t kEfOdf = 0x5031;
constexpr std::uint16_t kEfTokenInfo = 0x5032;
constexpr std::uint16_t kPrkdfFid = 0x4401;
constexpr std::uint16_t kCdfFid = 0x4404;
constexpr std::uint16_t kAodfFid = 0x4408;
constexpr std::uint16_t kCertFid = 0x4410;

// ---------------------------------------------------------------------------
// Scripted PKCS#15 card (the transmit-funnel test double).
// ---------------------------------------------------------------------------

/// The shared scripted card with the retry-counter probe answered, plus the
/// optional signing behaviour and a record of the card transaction each
/// command arrived under.
struct CensusCard : ScriptedPkcs15Card
{
    CensusCard()
    {
        answersRetryProbe = true;
    }

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
    /// PSO COMPUTE DIGITAL SIGNATURE body when signing is answered. Unset: the
    /// fixed 256-byte RSA-shaped answer the census has always seen.
    std::function<std::vector<std::uint8_t>(const APDUCommand&)> psoReply;
    /// A real RSA key (borrowed). When set, MSE SET takes only one-byte
    /// algorithm references and refuses those in @ref refusedAlgorithms, and
    /// PSO answers what a card holding the key signs for the chosen one.
    const LibreSCRS::TestSupport::RsaTestKey* rsaKey = nullptr;
    std::set<std::uint8_t> refusedAlgorithms;
    std::optional<std::uint8_t> mseAlgorithm;
    /// PSO COMPUTE DIGITAL SIGNATURE data longer than this is refused (6700),
    /// as a card refuses a message it cannot take in one short APDU.
    std::size_t maxPsoData = static_cast<std::size_t>(-1);

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

    /// The PKCS#1 v1.5 signature this card's key makes for @p input under
    /// @p algorithm: a DigestInfo it pads (0x02, 0x08), or a message it
    /// hashes first (0x0A, 0x28, 0x29, 0x2A). Empty for anything else.
    [[nodiscard]] std::vector<std::uint8_t> rsaCardSignature(std::uint8_t algorithm,
                                                             std::span<const std::uint8_t> input) const;

protected:
    void observe(const APDUCommand&) override
    {
        transactions.push_back(TransactionMark{connection != nullptr && connection->isTransactionHeld(), transaction});
    }

    std::optional<APDUResponse> answer(const APDUCommand& cmd) override
    {
        if (cmd.ins == 0x20 && !acceptedPins.empty()) { // VERIFY with a PIN
            if (triesLeft == 0)
                return APDUResponse{{}, 0x69, 0x83};
            std::string pin(cmd.data.begin(), cmd.data.end());
            while (!pin.empty() && (pin.back() == '\0' || pin.back() == '\xFF'))
                pin.pop_back();
            if (acceptedPins.contains(pin)) {
                triesLeft = 3;
                return APDUResponse{{}, 0x90, 0x00};
            }
            --triesLeft;
            if (triesLeft == 0)
                return lastTryAnswers63C0 ? APDUResponse{{}, 0x63, 0xC0} : APDUResponse{{}, 0x69, 0x83};
            return APDUResponse{{}, 0x63, static_cast<std::uint8_t>(0xC0 | triesLeft)};
        }
        if (rsaKey != nullptr && cmd.ins == 0x22) { // MSE SET
            mseAlgorithm.reset();
            if (cmd.data.size() < 3 || cmd.data[0] != 0x80 || cmd.data[1] != 0x01 ||
                refusedAlgorithms.contains(cmd.data[2]))
                return APDUResponse{{}, 0x6A, 0x80};
            mseAlgorithm = cmd.data[2];
            return APDUResponse{{}, 0x90, 0x00};
        }
        if (rsaKey != nullptr && cmd.ins == 0x2A && cmd.p1 == 0x9E && cmd.p2 == 0x9A) { // PSO CDS
            if (cmd.data.size() > maxPsoData)
                return APDUResponse{{}, 0x67, 0x00};
            auto signature = mseAlgorithm ? rsaCardSignature(*mseAlgorithm, cmd.data) : std::vector<std::uint8_t>{};
            if (signature.empty())
                return APDUResponse{{}, 0x6A, 0x80};
            return APDUResponse{std::move(signature), 0x90, 0x00};
        }
        if (answersSigning && cmd.ins == 0x22) // MSE SET
            return APDUResponse{{}, 0x90, 0x00};
        if (answersSigning && cmd.ins == 0x2A && cmd.p1 == 0x9E && cmd.p2 == 0x9A) // PSO CDS
            return APDUResponse{psoReply ? psoReply(cmd) : std::vector<std::uint8_t>(256, 0x5A), 0x90, 0x00};

        return std::nullopt;
    }
};

std::vector<std::uint8_t> CensusCard::rsaCardSignature(std::uint8_t algorithm,
                                                       std::span<const std::uint8_t> input) const
{
    switch (algorithm) {
    case 0x02:
    case 0x08:
        return rsaKey->signPkcs1(nullptr, input);
    case 0x0A:
        return rsaKey->signPkcs1(EVP_sha1(), input);
    case 0x28:
        return rsaKey->signPkcs1(EVP_sha256(), input);
    case 0x29:
        return rsaKey->signPkcs1(EVP_sha384(), input);
    case 0x2A:
        return rsaKey->signPkcs1(EVP_sha512(), input);
    default:
        return {};
    }
}

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

// EF.PrKDF: ONE RSA private key (id 01, protected by PIN 01) at path
// 3F00/4410, so the key/cert
// pairing in readCertificates resolves and doSign has a key to match. With
// @p userConsent its CommonObjectAttributes carry userConsent INTEGER 1. Its
// modulusLength is the empty INTEGER the census has always read unless
// @p modulusBits is given: a signature needs it to pad the input.
std::vector<std::uint8_t> onePrivateKeyPrkdf(bool userConsent = false, std::uint16_t modulusBits = 0)
{
    // "KEY", protected by the PIN whose id is 01.
    std::vector<std::uint8_t> commonObject = {0x0C, 0x03, 0x4B, 0x45, 0x59, 0x04, 0x01, 0x01};
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
    std::shared_ptr<CensusCard> card;
};

FakeCardRig makeRig(const char* readerName, bool userConsent = false)
{
    FakeCardRig rig;
    rig.session = makeDetachedCardSession(readerName);
    rig.card = std::make_shared<CensusCard>();
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

TEST(Pkcs15ProfileReadCensus, ChangePinPerformsExactlyOneProfileRead)
{
    const auto n = profileReadsFor("Census Reader ChangePin", [](CardPlugin& p, CardSession& s) {
        LibreSCRS::Secure::String oldValue{std::string_view{"0000"}};
        LibreSCRS::Secure::String newValue{std::string_view{"1111"}};
        (void)p.changePIN(s, "PIN", oldValue, newValue);
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
// Signing through the plugin and PKCS15Card over the same scripted card, with
// its optional signing behaviour on.
// ===========================================================================

namespace {

const std::vector<std::uint8_t> kToBeSigned(20, 0x42);

FakeCardRig makeSigningRig(const char* readerName, bool userConsent)
{
    auto rig = makeRig(readerName, userConsent);
    rig.card->files[kPrkdfFid] = onePrivateKeyPrkdf(userConsent, 2048);
    rig.card->acceptedPins = {"1234"};
    rig.card->answersSigning = true;
    return rig;
}

bool isVerifyWithPin(const APDUCommand& cmd)
{
    return cmd.ins == 0x20 && !cmd.data.empty();
}

bool isPso(const APDUCommand& cmd)
{
    return cmd.ins == 0x2A && cmd.p1 == 0x9E && cmd.p2 == 0x9A;
}

} // namespace

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

// ---------------------------------------------------------------------------
// The key handle readCertificates hands out and doSign resolves
// ---------------------------------------------------------------------------

namespace {

std::vector<std::uint8_t> derTlv(std::uint8_t tag, const std::vector<std::uint8_t>& content)
{
    std::vector<std::uint8_t> out{tag, static_cast<std::uint8_t>(content.size())};
    out.insert(out.end(), content.begin(), content.end());
    return out;
}

std::vector<std::uint8_t> joined(std::initializer_list<std::vector<std::uint8_t>> parts)
{
    std::vector<std::uint8_t> out;
    for (const auto& part : parts)
        out.insert(out.end(), part.begin(), part.end());
    return out;
}

// One [0] privateECKey record shaped like the Serbian eID's: no field size,
// the key addressed by @p keyReference inside DF 3F00/@p df, usage
// decrypt|sign|unwrap and -- with @p derive -- derive.
std::vector<std::uint8_t> ecPrivateKeyRecord(std::uint8_t id, std::uint8_t keyReference, bool derive,
                                             std::uint16_t df = 0x5015)
{
    const std::vector<std::uint8_t> usage =
        derive ? std::vector<std::uint8_t>{0x00, 0x64, 0x80} : std::vector<std::uint8_t>{0x00, 0x64};
    const std::vector<std::uint8_t> path = {0x3F, 0x00, static_cast<std::uint8_t>(df >> 8),
                                            static_cast<std::uint8_t>(df & 0xFF)};
    return derTlv(0xA0,
                  joined({derTlv(0x30, {0x0C, 0x03, 0x4B, 0x45, 0x59, 0x04, 0x01, 0x01}), // "KEY", authId 01
                          derTlv(0x30, joined({derTlv(0x04, {id}), derTlv(0x03, usage), derTlv(0x02, {keyReference})})),
                          derTlv(0xA1, derTlv(0x30, derTlv(0x30, derTlv(0x04, path))))}));
}

// One EF.CDF record: certificate @p id ("Cert") stored at 3F00/@p fid.
std::vector<std::uint8_t> certificateRecord(std::uint8_t id, std::uint16_t fid)
{
    return derTlv(0x30, joined({derTlv(0x30, {0x0C, 0x04, 0x43, 0x65, 0x72, 0x74}), derTlv(0x30, derTlv(0x04, {id})),
                                derTlv(0xA1, derTlv(0x30, derTlv(0x04, {0x3F, 0x00, static_cast<std::uint8_t>(fid >> 8),
                                                                        static_cast<std::uint8_t>(fid & 0xFF)})))}));
}

constexpr std::uint16_t kSecondCertFid = 0x4411;

} // namespace

// Two EC keys in ONE DF, told apart only by their key references. A handle
// taken from the path's last two bytes gave both 5015.
TEST(Pkcs15PluginKeyHandle, KeysInOneDfGetTheirOwnHandles)
{
    auto rig = makeRig("Key Handle Reader 0");
    rig.card->files[kPrkdfFid] = joined({ecPrivateKeyRecord(0x01, 0x47, false), ecPrivateKeyRecord(0x02, 0x48, false)});
    rig.card->files[kCdfFid] = joined({certificateRecord(0x01, kCertFid), certificateRecord(0x02, kSecondCertFid)});
    rig.card->files[kSecondCertFid] = certBlob();
    CardPluginService registry{pluginDir()};
    auto plugin = findPkcs15(registry);
    ASSERT_NE(plugin, nullptr);

    const auto certs = plugin->readCertificates(*rig.session);

    ASSERT_EQ(certs.size(), 2U);
    ASSERT_TRUE(certs[0].keyFID.has_value());
    ASSERT_TRUE(certs[1].keyFID.has_value());
    EXPECT_EQ(*certs[0].keyFID, std::uint16_t{0x47});
    EXPECT_EQ(*certs[1].keyFID, std::uint16_t{0x48});
}

// A key stored in its own file, without a reference, keeps the handle it has
// always had: the file's id.
TEST(Pkcs15PluginKeyHandle, KeyFileWithoutAReferenceKeepsItsPathHandle)
{
    auto rig = makeRig("Key Handle Reader 1");
    CardPluginService registry{pluginDir()};
    auto plugin = findPkcs15(registry);
    ASSERT_NE(plugin, nullptr);

    const auto certs = plugin->readCertificates(*rig.session);

    ASSERT_EQ(certs.size(), 1U);
    ASSERT_TRUE(certs[0].keyFID.has_value());
    EXPECT_EQ(*certs[0].keyFID, std::uint16_t{0x4410});
}

// ---------------------------------------------------------------------------
// ECDSA through the card plugin: the contract's fixed-width r || s
// ---------------------------------------------------------------------------

namespace {

using LibreSCRS::Plugin::SignMechanism;
using LibreSCRS::Plugin::SignResultOutcome;
using LibreSCRS::TestSupport::EcTestKey;

const std::vector<std::uint8_t> kHash384(48, 0x37);

struct EcSigningRig
{
    FakeCardRig rig;
    std::shared_ptr<const EcTestKey> key;
};

// The PKCS#15 card with one EC P-384 key shaped like the Serbian eID's (no
// field size in the PrKDF, reference 0x47 in DF 3F00/5015) and a real
// certificate over it. It answers the signature in DER, as that card does.
EcSigningRig makeEcSigningRig(const char* readerName, bool derive = false)
{
    EcSigningRig r;
    r.rig = makeRig(readerName);
    r.key = std::make_shared<const EcTestKey>(LibreSCRS::TestSupport::makeEcTestKey("P-384"));
    r.rig.card->files[kPrkdfFid] = ecPrivateKeyRecord(0x01, 0x47, derive);
    r.rig.card->files[kCertFid] = r.key->certDer;
    r.rig.card->acceptedPins = {"1234"};
    r.rig.card->answersSigning = true;
    r.rig.card->psoReply = [key = r.key](const APDUCommand& cmd) { return key->signDer(cmd.data); };
    return r;
}

void depositPin(CardPlugin& plugin, CardSession& session)
{
    plugin.setCredentials(session, "pin", LibreSCRS::Secure::String{std::string_view{"1234"}});
}

bool isMseSet(const APDUCommand& cmd)
{
    return cmd.ins == 0x22 && cmd.p1 == 0x41 && cmd.p2 == 0xB6;
}

std::size_t countSince(const std::vector<APDUCommand>& log, std::size_t mark, bool (*matches)(const APDUCommand&))
{
    return static_cast<std::size_t>(std::count_if(log.begin() + static_cast<std::ptrdiff_t>(mark), log.end(), matches));
}

std::optional<APDUCommand> lastMseSince(const std::vector<APDUCommand>& log, std::size_t mark)
{
    std::optional<APDUCommand> found;
    for (std::size_t i = mark; i < log.size(); ++i) {
        if (isMseSet(log[i]))
            found = log[i];
    }
    return found;
}

} // namespace

// ---------------------------------------------------------------------------
// RSA through the card plugin: every RSA mechanism the plugin offers
// ---------------------------------------------------------------------------

namespace {

struct RsaSigningRig
{
    FakeCardRig rig;
    std::shared_ptr<const LibreSCRS::TestSupport::RsaTestKey> key;
};

// A plain PKCS#15 card -- no PACE -- with one 2048-bit RSA key and its
// certificate. @p refused names the algorithm references its MSE SET refuses:
// {0x02, 0x08} makes a card that signs only what it hashes itself.
RsaSigningRig makeRsaSigningRig(const char* readerName, std::set<std::uint8_t> refused = {})
{
    RsaSigningRig r;
    r.rig = makeSigningRig(readerName, false);
    r.key = std::make_shared<const LibreSCRS::TestSupport::RsaTestKey>(LibreSCRS::TestSupport::makeRsaTestKey());
    r.rig.card->files[kCertFid] = r.key->certDer;
    r.rig.card->rsaKey = r.key.get();
    r.rig.card->refusedAlgorithms = std::move(refused);
    return r;
}

const std::vector<std::uint8_t> kMessage{'t', 'o', ' ', 'b', 'e', ' ', 's', 'i', 'g', 'n', 'e', 'd'};

struct RsaDigestCase
{
    LibreSCRS::Plugin::SignMechanism mechanism;
    const EVP_MD* (*md)();
    LibreSCRS::Internal::Crypto::DigestInfoHash hash;
    std::uint8_t onCardAlgorithm;
    const char* name;
};

const RsaDigestCase kRsaDigestCases[] = {
    {LibreSCRS::Plugin::SignMechanism::RSA_SHA1, &EVP_sha1, LibreSCRS::Internal::Crypto::DigestInfoHash::Sha1, 0x0A,
     "RSA_SHA1"},
    {LibreSCRS::Plugin::SignMechanism::RSA_SHA256, &EVP_sha256, LibreSCRS::Internal::Crypto::DigestInfoHash::Sha256,
     0x28, "RSA_SHA256"},
    {LibreSCRS::Plugin::SignMechanism::RSA_SHA384, &EVP_sha384, LibreSCRS::Internal::Crypto::DigestInfoHash::Sha384,
     0x29, "RSA_SHA384"},
    {LibreSCRS::Plugin::SignMechanism::RSA_SHA512, &EVP_sha512, LibreSCRS::Internal::Crypto::DigestInfoHash::Sha512,
     0x2A, "RSA_SHA512"},
};

std::optional<APDUCommand> lastPsoSince(const std::vector<APDUCommand>& log, std::size_t mark)
{
    std::optional<APDUCommand> found;
    for (std::size_t i = mark; i < log.size(); ++i) {
        if (log[i].ins == 0x2A && log[i].p1 == 0x9E && log[i].p2 == 0x9A)
            found = log[i];
    }
    return found;
}

} // namespace

// The caller's DigestInfo is signed as given, with no secure channel: a plain
// PKCS#15 card signs RSA without PACE.
TEST(Pkcs15PluginRsa, DigestInfoIsSignedWithoutPace)
{
    auto r = makeRsaSigningRig("RSA Reader 0");
    CardPluginService registry{pluginDir()};
    auto plugin = findPkcs15(registry);
    ASSERT_NE(plugin, nullptr);
    plugin->setCredentials(*r.rig.session, "pin", LibreSCRS::Secure::String{std::string_view{"1234"}});

    const auto digestInfo =
        LibreSCRS::Internal::Crypto::digestInfoOf(LibreSCRS::Internal::Crypto::DigestInfoHash::Sha256, kMessage);
    const auto result = plugin->sign(*r.rig.session, 0x4410, digestInfo, SignMechanism::RSA_PKCS);

    ASSERT_EQ(result.outcome, SignResultOutcome::Ok);
    EXPECT_TRUE(r.key->verifies(EVP_sha256(), kMessage, result.signature));
}

// A raw message under every RSA_SHA* mechanism: the card is handed the
// DigestInfo over that hash, built on the host, as the module hands it.
TEST(Pkcs15PluginRsa, RawMessageIsSignedOverEachHashWithoutPace)
{
    for (const auto& c : kRsaDigestCases) {
        SCOPED_TRACE(c.name);
        auto r = makeRsaSigningRig(c.name);
        CardPluginService registry{pluginDir()};
        auto plugin = findPkcs15(registry);
        ASSERT_NE(plugin, nullptr);
        plugin->setCredentials(*r.rig.session, "pin", LibreSCRS::Secure::String{std::string_view{"1234"}});
        const auto mark = r.rig.card->log.size();

        const auto result = plugin->sign(*r.rig.session, 0x4410, kMessage, c.mechanism);

        ASSERT_EQ(result.outcome, SignResultOutcome::Ok);
        EXPECT_TRUE(r.key->verifies(c.md(), kMessage, result.signature));
        const auto pso = lastPsoSince(r.rig.card->log, mark);
        ASSERT_TRUE(pso.has_value());
        EXPECT_EQ(pso->data, LibreSCRS::Internal::Crypto::digestInfoOf(c.hash, kMessage));
    }
}

// A card that signs only what it hashes itself refuses the DigestInfo forms;
// the plugin then reaches the card's own algorithm for that hash with the raw
// message, as the module's ladder does.
TEST(Pkcs15PluginRsa, HashOnCardCardGetsItsAlgorithmAndTheMessage)
{
    for (const auto& c : kRsaDigestCases) {
        SCOPED_TRACE(c.name);
        auto r = makeRsaSigningRig(c.name, {0x02, 0x08});
        CardPluginService registry{pluginDir()};
        auto plugin = findPkcs15(registry);
        ASSERT_NE(plugin, nullptr);
        plugin->setCredentials(*r.rig.session, "pin", LibreSCRS::Secure::String{std::string_view{"1234"}});
        const auto mark = r.rig.card->log.size();

        const auto result = plugin->sign(*r.rig.session, 0x4410, kMessage, c.mechanism);

        ASSERT_EQ(result.outcome, SignResultOutcome::Ok);
        EXPECT_TRUE(r.key->verifies(c.md(), kMessage, result.signature));
        EXPECT_EQ(r.rig.card->mseAlgorithm, std::optional<std::uint8_t>{c.onCardAlgorithm});
        const auto pso = lastPsoSince(r.rig.card->log, mark);
        ASSERT_TRUE(pso.has_value());
        EXPECT_EQ(pso->data, kMessage);
    }
}

// A card that hashes on card refuses the long message, and then "signs" the
// hash it is handed under its hash-on-card algorithm -- a well-formed RSA
// signature over SHA-256 of the hash, not of the message. It does not verify
// with the certificate's key, so it is never returned as the signature.
TEST(Pkcs15PluginRsa, SignatureThatDoesNotVerifyIsNeverReturned)
{
    auto r = makeRsaSigningRig("RSA Reader Verify", {0x02, 0x08});
    r.rig.card->maxPsoData = 64;
    CardPluginService registry{pluginDir()};
    auto plugin = findPkcs15(registry);
    ASSERT_NE(plugin, nullptr);
    plugin->setCredentials(*r.rig.session, "pin", LibreSCRS::Secure::String{std::string_view{"1234"}});
    const std::vector<std::uint8_t> longMessage(300, 0x6D);

    const auto result = plugin->sign(*r.rig.session, 0x4410, longMessage, SignMechanism::RSA_SHA256);

    if (result.outcome == SignResultOutcome::Ok) {
        EXPECT_TRUE(r.key->verifies(EVP_sha256(), longMessage, result.signature))
            << "an Ok signature must be one over the message";
    }
    EXPECT_NE(result.outcome, SignResultOutcome::Ok) << "no attempt this card answers signs the message";
}

// A card that answers ECDSA in DER and whose PrKDF records no field size:
// the plugin takes the width from the certificate, reads the reply and
// checks it with that certificate's key. No CAN is deposited -- ECDSA input
// is always the hash, so it needs no PACE gate.
TEST(Pkcs15PluginEcdsa, DerReplyComesBackAsFixedWidthRawSignature)
{
    auto r = makeEcSigningRig("ECDSA Reader 0");
    CardPluginService registry{pluginDir()};
    auto plugin = findPkcs15(registry);
    ASSERT_NE(plugin, nullptr);
    depositPin(*plugin, *r.rig.session);

    const auto result = plugin->sign(*r.rig.session, 0x47, kHash384, SignMechanism::ECDSA_SHA384);

    ASSERT_EQ(result.outcome, SignResultOutcome::Ok);
    EXPECT_EQ(result.signature.size(), 96U);
    EXPECT_TRUE(r.key->verifiesRaw(kHash384, result.signature));
    const auto mse = lastMseSince(r.rig.card->log, 0);
    ASSERT_TRUE(mse.has_value());
    EXPECT_EQ(mse->data, (std::vector<std::uint8_t>{0x80, 0x01, 0x04, 0x84, 0x01, 0x47}))
        << "ECDSA-plain with the key's reference";
}

// A real signature whose r is below 2^376 (about one in 256): DER writes r
// at least a byte short, the contract wants it left-padded.
TEST(Pkcs15PluginEcdsa, ShortIntegerIsLeftPadded)
{
    auto r = makeEcSigningRig("ECDSA Reader 1");
    const auto shortRs =
        r.key->rawSignatureWhere(kHash384, [](std::span<const std::uint8_t> raw) { return raw[0] == 0x00; });
    r.rig.card->psoReply =
        [der = LibreSCRS::TestSupport::ecdsaDer(std::span(shortRs).first(48), std::span(shortRs).subspan(48))](
            const APDUCommand&) { return der; };
    CardPluginService registry{pluginDir()};
    auto plugin = findPkcs15(registry);
    ASSERT_NE(plugin, nullptr);
    depositPin(*plugin, *r.rig.session);

    const auto result = plugin->sign(*r.rig.session, 0x47, kHash384, SignMechanism::ECDSA_SHA384);

    ASSERT_EQ(result.outcome, SignResultOutcome::Ok);
    ASSERT_EQ(result.signature.size(), 96U);
    EXPECT_EQ(result.signature[0], 0x00);
    EXPECT_EQ(result.signature, shortRs);
}

TEST(Pkcs15PluginEcdsa, RawReplyOfTheKeysWidthIsKept)
{
    auto r = makeEcSigningRig("ECDSA Reader 2");
    r.rig.card->psoReply = [key = r.key](const APDUCommand& cmd) {
        return LibreSCRS::TestSupport::ecdsaRawOf(key->signDer(cmd.data), key->fieldBytes);
    };
    CardPluginService registry{pluginDir()};
    auto plugin = findPkcs15(registry);
    ASSERT_NE(plugin, nullptr);
    depositPin(*plugin, *r.rig.session);

    const auto result = plugin->sign(*r.rig.session, 0x47, kHash384, SignMechanism::ECDSA_SHA384);

    ASSERT_EQ(result.outcome, SignResultOutcome::Ok);
    EXPECT_TRUE(r.key->verifiesRaw(kHash384, result.signature));
}

// A valid signature whose DER is exactly 96 bytes also reads as raw r || s.
// The plugin settles it with the certificate's public key.
TEST(Pkcs15PluginEcdsa, AmbiguousReplyIsSettledByTheCertificate)
{
    auto r = makeEcSigningRig("ECDSA Reader 3");
    const auto chosen = r.key->signatureWithRawWidthDer();
    r.rig.card->psoReply = [der = chosen.der](const APDUCommand&) { return der; };
    CardPluginService registry{pluginDir()};
    auto plugin = findPkcs15(registry);
    ASSERT_NE(plugin, nullptr);
    depositPin(*plugin, *r.rig.session);

    const auto result = plugin->sign(*r.rig.session, 0x47, chosen.hash, SignMechanism::ECDSA_SHA384);

    ASSERT_EQ(result.outcome, SignResultOutcome::Ok);
    EXPECT_NE(result.signature, chosen.der);
    EXPECT_TRUE(r.key->verifiesRaw(chosen.hash, result.signature));
}

TEST(Pkcs15PluginEcdsa, ReplyOfNeitherShapeIsAPluginError)
{
    auto r = makeEcSigningRig("ECDSA Reader 4");
    r.rig.card->psoReply = [](const APDUCommand&) { return std::vector<std::uint8_t>(50, 0xA5); };
    CardPluginService registry{pluginDir()};
    auto plugin = findPkcs15(registry);
    ASSERT_NE(plugin, nullptr);
    depositPin(*plugin, *r.rig.session);

    const auto result = plugin->sign(*r.rig.session, 0x47, kHash384, SignMechanism::ECDSA_SHA384);

    EXPECT_EQ(result.outcome, SignResultOutcome::PluginError);
    EXPECT_TRUE(result.signature.empty());
}

// Without a readable EC certificate there is no width to sign with; the plugin
// stops before the PIN reaches the card, so no try is spent.
TEST(Pkcs15PluginEcdsa, NoCertificateWidthStopsBeforeThePin)
{
    auto r = makeEcSigningRig("ECDSA Reader 5");
    r.rig.card->files[kCertFid] = certBlob(); // not X.509
    CardPluginService registry{pluginDir()};
    auto plugin = findPkcs15(registry);
    ASSERT_NE(plugin, nullptr);
    depositPin(*plugin, *r.rig.session);

    const auto result = plugin->sign(*r.rig.session, 0x47, kHash384, SignMechanism::ECDSA_SHA384);

    EXPECT_EQ(result.outcome, SignResultOutcome::PluginError);
    EXPECT_EQ(countSince(r.rig.card->log, 0, isVerifyWithPin), 0U);
    EXPECT_EQ(countSince(r.rig.card->log, 0, isPso), 0U);
}

TEST(Pkcs15PluginEcdsa, RsaKeyRefusesAnEcdsaMechanism)
{
    auto rig = makeSigningRig("ECDSA Reader 6", false);
    CardPluginService registry{pluginDir()};
    auto plugin = findPkcs15(registry);
    ASSERT_NE(plugin, nullptr);
    depositPin(*plugin, *rig.session);

    const auto result = plugin->sign(*rig.session, 0x4410, kHash384, SignMechanism::ECDSA_SHA384);

    EXPECT_EQ(result.outcome, SignResultOutcome::NotImplemented);
    EXPECT_EQ(countSince(rig.card->log, 0, isVerifyWithPin), 0U) << "no PIN try spent";
    EXPECT_EQ(countSince(rig.card->log, 0, isPso), 0U);
}

TEST(Pkcs15PluginEcdsa, WrongHashLengthNeverReachesTheCard)
{
    auto r = makeEcSigningRig("ECDSA Reader 7");
    CardPluginService registry{pluginDir()};
    auto plugin = findPkcs15(registry);
    ASSERT_NE(plugin, nullptr);
    depositPin(*plugin, *r.rig.session);
    const auto apdus = r.rig.card->log.size();

    const auto result =
        plugin->sign(*r.rig.session, 0x47, std::vector<std::uint8_t>(20, 0x01), SignMechanism::ECDSA_SHA384);

    EXPECT_EQ(result.outcome, SignResultOutcome::PluginError);
    EXPECT_EQ(r.rig.card->log.size(), apdus);
}

// A wrong PIN must read as a wrong PIN: a host that sees PluginError cannot
// tell it from a broken card, and the agent would read it as a lost channel.
TEST(Pkcs15PluginEcdsa, RefusedPinIsReportedAsPinIncorrect)
{
    auto r = makeEcSigningRig("ECDSA Reader 8");
    r.rig.card->acceptedPins = {"9999"};
    CardPluginService registry{pluginDir()};
    auto plugin = findPkcs15(registry);
    ASSERT_NE(plugin, nullptr);
    depositPin(*plugin, *r.rig.session);

    const auto result = plugin->sign(*r.rig.session, 0x47, kHash384, SignMechanism::ECDSA_SHA384);

    EXPECT_EQ(result.outcome, SignResultOutcome::PinIncorrect);
    EXPECT_EQ(countSince(r.rig.card->log, 0, isVerifyWithPin), 1U) << "a refused PIN is presented once";
    EXPECT_EQ(countSince(r.rig.card->log, 0, isPso), 0U);
}

TEST(Pkcs15PluginEcdsa, EachKeyInOneDfSignsWithItsOwnReference)
{
    auto r = makeEcSigningRig("ECDSA Reader 9");
    r.rig.card->files[kPrkdfFid] =
        joined({ecPrivateKeyRecord(0x01, 0x47, false), ecPrivateKeyRecord(0x02, 0x48, false)});
    r.rig.card->files[kCdfFid] = joined({certificateRecord(0x01, kCertFid), certificateRecord(0x02, kSecondCertFid)});
    r.rig.card->files[kSecondCertFid] = r.key->certDer;
    CardPluginService registry{pluginDir()};
    auto plugin = findPkcs15(registry);
    ASSERT_NE(plugin, nullptr);
    depositPin(*plugin, *r.rig.session);

    for (const std::uint8_t reference : {std::uint8_t{0x48}, std::uint8_t{0x47}}) {
        SCOPED_TRACE(static_cast<int>(reference));
        const auto mark = r.rig.card->log.size();
        const auto result = plugin->sign(*r.rig.session, reference, kHash384, SignMechanism::ECDSA_SHA384);
        ASSERT_EQ(result.outcome, SignResultOutcome::Ok);
        const auto mse = lastMseSince(r.rig.card->log, mark);
        ASSERT_TRUE(mse.has_value());
        ASSERT_FALSE(mse->data.empty());
        EXPECT_EQ(mse->data.back(), reference);
    }
}

// Cards that write r and s at the full field width answer
// 30 66 02 31 00 r 02 31 00 s or 30 64 02 30 r 02 30 s -- not DER for about
// half of all signatures. Both are the key's signature, and come back as one.
TEST(Pkcs15PluginEcdsa, FixedWidthIntegersFromTheCardAreAccepted)
{
    for (const bool zeroPrefix : {true, false}) {
        SCOPED_TRACE(zeroPrefix);
        auto r = makeEcSigningRig(zeroPrefix ? "ECDSA Reader 10" : "ECDSA Reader 11");
        r.rig.card->psoReply = [key = r.key, zeroPrefix](const APDUCommand& cmd) {
            return LibreSCRS::TestSupport::fixedWidthSequence(
                LibreSCRS::TestSupport::ecdsaRawOf(key->signDer(cmd.data), key->fieldBytes), zeroPrefix);
        };
        CardPluginService registry{pluginDir()};
        auto plugin = findPkcs15(registry);
        ASSERT_NE(plugin, nullptr);
        depositPin(*plugin, *r.rig.session);

        const auto result = plugin->sign(*r.rig.session, 0x47, kHash384, SignMechanism::ECDSA_SHA384);

        ASSERT_EQ(result.outcome, SignResultOutcome::Ok);
        EXPECT_EQ(result.signature.size(), 96U);
        EXPECT_TRUE(r.key->verifiesRaw(kHash384, result.signature));
    }
}

// Every signature is checked with the certificate's key before it leaves: a
// well-formed signature by ANOTHER key is never returned, though the card
// answered.
TEST(Pkcs15PluginEcdsa, SignatureThatDoesNotVerifyIsAPluginError)
{
    auto r = makeEcSigningRig("ECDSA Reader 12");
    const auto other = std::make_shared<const EcTestKey>(LibreSCRS::TestSupport::makeEcTestKey("P-384"));
    r.rig.card->psoReply = [other](const APDUCommand& cmd) { return other->signDer(cmd.data); };
    CardPluginService registry{pluginDir()};
    auto plugin = findPkcs15(registry);
    ASSERT_NE(plugin, nullptr);
    depositPin(*plugin, *r.rig.session);

    const auto result = plugin->sign(*r.rig.session, 0x47, kHash384, SignMechanism::ECDSA_SHA384);

    EXPECT_EQ(result.outcome, SignResultOutcome::PluginError);
    EXPECT_TRUE(result.signature.empty());
    EXPECT_EQ(countSince(r.rig.card->log, 0, isPso), 1U) << "the card signed; the plugin refused what came back";
}

// Key references are local to a DF: two keys in two DFs may carry the same
// one and so share a handle. Such a request names no single key; none is
// guessed, and no PIN try is spent on it.
TEST(Pkcs15PluginEcdsa, KeysSharingAHandleAreNeverGuessed)
{
    auto r = makeEcSigningRig("ECDSA Reader 13");
    r.rig.card->files[kPrkdfFid] =
        joined({ecPrivateKeyRecord(0x01, 0x47, false), ecPrivateKeyRecord(0x02, 0x47, false, 0x5016)});
    // Both keys have a readable certificate, so only the shared handle can
    // stop the request: without the check either key would sign.
    r.rig.card->files[kCdfFid] = joined({certificateRecord(0x01, kCertFid), certificateRecord(0x02, kSecondCertFid)});
    r.rig.card->files[kSecondCertFid] = r.key->certDer;
    CardPluginService registry{pluginDir()};
    auto plugin = findPkcs15(registry);
    ASSERT_NE(plugin, nullptr);
    depositPin(*plugin, *r.rig.session);

    const auto result = plugin->sign(*r.rig.session, 0x47, kHash384, SignMechanism::ECDSA_SHA384);

    EXPECT_EQ(result.outcome, SignResultOutcome::PluginError);
    EXPECT_EQ(countSince(r.rig.card->log, 0, isVerifyWithPin), 0U);
    EXPECT_EQ(countSince(r.rig.card->log, 0, isPso), 0U);

    // The handle that doSign refuses is not handed out either: a host reads a
    // disengaged keyFID as "verify-only", not as a key it may ask to sign.
    const auto certs = plugin->readCertificates(*r.rig.session);
    ASSERT_EQ(certs.size(), 2U);
    for (const auto& cert : certs)
        EXPECT_FALSE(cert.keyFID.has_value());
}

// A hash longer than the key's field -- SHA-512 with a P-384 key, a pair TLS
// allows: the card gets its leftmost 48 bytes, the ones FIPS 186-4 signs and
// the ones OpenSC sends. This card refuses a wider input, as one under PACE
// might with a plain reply that ends the session. The signature verifies
// over the whole hash.
TEST(Pkcs15PluginEcdsa, HashLongerThanTheFieldReachesTheCardCut)
{
    auto r = makeEcSigningRig("ECDSA Reader 14");
    std::vector<std::uint8_t> hash512(64);
    for (std::size_t i = 0; i < hash512.size(); ++i)
        hash512[i] = static_cast<std::uint8_t>(0xB0 + i);
    r.rig.card->psoReply = [key = r.key](const APDUCommand& cmd) {
        return cmd.data.size() == key->fieldBytes ? key->signDer(cmd.data) : std::vector<std::uint8_t>{};
    };
    CardPluginService registry{pluginDir()};
    auto plugin = findPkcs15(registry);
    ASSERT_NE(plugin, nullptr);
    depositPin(*plugin, *r.rig.session);

    const auto result = plugin->sign(*r.rig.session, 0x47, hash512, SignMechanism::ECDSA_SHA512);

    std::optional<APDUCommand> pso;
    for (const auto& cmd : r.rig.card->log) {
        if (isPso(cmd))
            pso = cmd;
    }
    ASSERT_TRUE(pso.has_value());
    EXPECT_EQ(pso->data, std::vector<std::uint8_t>(hash512.begin(), hash512.begin() + 48))
        << "the card was sent " << pso->data.size() << " bytes";
    ASSERT_EQ(result.outcome, SignResultOutcome::Ok);
    EXPECT_TRUE(r.key->verifiesRaw(hash512, result.signature));
}

// ---------------------------------------------------------------------------
// Key agreement: the card may allow it, this plugin does not perform it
// ---------------------------------------------------------------------------

class Pkcs15PluginDerive : public ::testing::Test
{
protected:
    void SetUp() override
    {
        LibreSCRS::log::init([this](LibreSCRS::log::Level, std::string_view line) { lines.emplace_back(line); },
                             "test.pkcs15");
    }
    void TearDown() override
    {
        LibreSCRS::log::resetForTest();
    }

    [[nodiscard]] std::size_t linesMentioningKeyAgreement() const
    {
        return static_cast<std::size_t>(std::count_if(lines.begin(), lines.end(), [](const std::string& line) {
            return line.find("key agreement") != std::string::npos;
        }));
    }

    std::vector<std::string> lines;
};

// canDerive means "this plugin will run ECDH", not "the card allows it". The
// card's bit is not lost: one line per card session says why the key is not
// offered for it.
TEST_F(Pkcs15PluginDerive, CardAllowsDeriveButThisPluginDoesNot)
{
    auto r = makeEcSigningRig("Derive Reader 0", /*derive=*/true);
    CardPluginService registry{pluginDir()};
    auto plugin = findPkcs15(registry);
    ASSERT_NE(plugin, nullptr);

    const auto certs = plugin->readCertificates(*r.rig.session);

    ASSERT_EQ(certs.size(), 1U);
    EXPECT_FALSE(certs[0].canDerive);
    EXPECT_EQ(linesMentioningKeyAgreement(), 1U);

    // A host resolves its key through readCertificates on every operation;
    // the line belongs to the card session, not to each of those reads.
    (void)plugin->readCertificates(*r.rig.session);
    (void)plugin->readCertificates(*r.rig.session);
    EXPECT_EQ(linesMentioningKeyAgreement(), 1U) << "once per card session";

    // Control: a key without the bit says nothing.
    auto quiet = makeEcSigningRig("Derive Reader 1", /*derive=*/false);
    lines.clear();
    (void)plugin->readCertificates(*quiet.rig.session);
    EXPECT_EQ(linesMentioningKeyAgreement(), 0U);
}

TEST_F(Pkcs15PluginDerive, EcdhIsNotImplemented)
{
    auto r = makeEcSigningRig("Derive Reader 2", /*derive=*/true);
    CardPluginService registry{pluginDir()};
    auto plugin = findPkcs15(registry);
    ASSERT_NE(plugin, nullptr);
    depositPin(*plugin, *r.rig.session);
    std::vector<std::uint8_t> point(97, 0x3C);
    point[0] = 0x04;
    const auto apdus = r.rig.card->log.size();

    const auto result = plugin->decipher(*r.rig.session, 0x47, point, LibreSCRS::Plugin::DecipherMechanism::ECDH_RAW);

    EXPECT_EQ(result.outcome, LibreSCRS::Plugin::DecipherResultOutcome::NotImplemented);
    EXPECT_EQ(r.rig.card->log.size(), apdus);
}

// ---------------------------------------------------------------------------
// The PIN a key names, and one user-PIN rule for every operation
// ---------------------------------------------------------------------------

namespace {

// One RSA private key record: object id @p id, protected by the PIN whose
// object id is @p authId (none when empty), its file at 3F00/@p fid.
std::vector<std::uint8_t> rsaKeyRecord(std::uint8_t id, std::vector<std::uint8_t> authId, std::uint16_t fid)
{
    std::vector<std::uint8_t> common = {0x0C, 0x03, 0x4B, 0x45, 0x59}; // "KEY"
    if (!authId.empty()) {
        const auto encoded = derTlv(0x04, authId);
        common.insert(common.end(), encoded.begin(), encoded.end());
    }
    const std::vector<std::uint8_t> path = {0x3F, 0x00, static_cast<std::uint8_t>(fid >> 8),
                                            static_cast<std::uint8_t>(fid & 0xFF)};
    return derTlv(0x30,
                  joined({derTlv(0x30, common), derTlv(0x30, derTlv(0x04, {id})),
                          derTlv(0xA1, derTlv(0x30, joined({derTlv(0x30, joined({derTlv(0x04, path), {0x02, 0x00}})),
                                                            {0x02, 0x02, 0x08, 0x00}})))}));
}

// The PIN reference of the one VERIFY carrying a PIN after @p mark.
std::vector<std::uint8_t> verifyReferencesSince(const std::vector<APDUCommand>& log, std::size_t mark)
{
    std::vector<std::uint8_t> refs;
    for (std::size_t i = mark; i < log.size(); ++i) {
        if (isVerifyWithPin(log[i]))
            refs.push_back(log[i].p2);
    }
    return refs;
}

// The hardware-scanned AppletSuiteGen1 AODF (User PIN id 06 ref 0x86,
// Signature PIN id 22 ref 0x92) and a PrKDF of two keys, one protected by
// each, plus a key that names no PIN.
FakeCardRig makeTwoPinRig(const char* readerName)
{
    auto rig = makeRig(readerName);
    const auto& aodf = LibreSCRS::test::fixtures::kAppletSuiteGen1Aodf20260718;
    rig.card->files[kAodfFid] = std::vector<std::uint8_t>(aodf.begin(), aodf.end());
    rig.card->files[kPrkdfFid] = joined(
        {rsaKeyRecord(0x01, {0x06}, 0x4410), rsaKeyRecord(0x02, {0x22}, 0x4411), rsaKeyRecord(0x03, {}, 0x4412)});
    rig.card->selectableDfs.push_back(0x0DF5);
    rig.card->acceptedPins = {"123456"};
    rig.card->answersSigning = true;
    return rig;
}

} // namespace

// Each key is signed with the PIN its authId names: the authentication key
// with the User PIN (0x86), the signing key with the Signature PIN (0x92).
// "The first user PIN" for both would present one PIN to the other's key and
// spend the other's tries.
TEST(Pkcs15PluginKeyPin, EachKeyIsSignedWithThePinItNames)
{
    auto rig = makeTwoPinRig("Two PIN Reader 0");
    CardPluginService registry{pluginDir()};
    auto plugin = findPkcs15(registry);
    ASSERT_NE(plugin, nullptr);
    plugin->setCredentials(*rig.session, "pin", LibreSCRS::Secure::String{std::string_view{"123456"}});
    const auto digestInfo =
        LibreSCRS::Internal::Crypto::digestInfoOf(LibreSCRS::Internal::Crypto::DigestInfoHash::Sha256, kToBeSigned);

    auto mark = rig.card->log.size();
    (void)plugin->sign(*rig.session, 0x4410, digestInfo, LibreSCRS::Plugin::SignMechanism::RSA_PKCS);
    EXPECT_EQ(verifyReferencesSince(rig.card->log, mark), (std::vector<std::uint8_t>{0x86}));

    mark = rig.card->log.size();
    (void)plugin->sign(*rig.session, 0x4411, digestInfo, LibreSCRS::Plugin::SignMechanism::RSA_PKCS);
    EXPECT_EQ(verifyReferencesSince(rig.card->log, mark), (std::vector<std::uint8_t>{0x92}));
}

TEST(Pkcs15PluginKeyPin, KeyThatNamesNoPinNeverReachesTheCard)
{
    auto rig = makeTwoPinRig("Two PIN Reader 1");
    CardPluginService registry{pluginDir()};
    auto plugin = findPkcs15(registry);
    ASSERT_NE(plugin, nullptr);
    plugin->setCredentials(*rig.session, "pin", LibreSCRS::Secure::String{std::string_view{"123456"}});
    const auto digestInfo =
        LibreSCRS::Internal::Crypto::digestInfoOf(LibreSCRS::Internal::Crypto::DigestInfoHash::Sha256, kToBeSigned);

    (void)plugin->readCertificates(*rig.session); // the profile is read; the count starts after it
    const auto mark = rig.card->log.size();
    const auto result = plugin->sign(*rig.session, 0x4412, digestInfo, LibreSCRS::Plugin::SignMechanism::RSA_PKCS);

    EXPECT_EQ(result.outcome, LibreSCRS::Plugin::SignResultOutcome::PluginError);
    EXPECT_TRUE(verifyReferencesSince(rig.card->log, mark).empty()) << "no PIN is guessed for it";
}

// A PIN longer than the AODF allows is refused before any VERIFY: the card's
// counter is not spent on a value that cannot be its PIN.
TEST(Pkcs15PluginKeyPin, PinOfTheWrongLengthNeverReachesTheCard)
{
    auto rig = makeTwoPinRig("Two PIN Reader 2");
    CardPluginService registry{pluginDir()};
    auto plugin = findPkcs15(registry);
    ASSERT_NE(plugin, nullptr);
    plugin->setCredentials(*rig.session, "pin", LibreSCRS::Secure::String{std::string_view{"1234567890123"}});
    const auto digestInfo =
        LibreSCRS::Internal::Crypto::digestInfoOf(LibreSCRS::Internal::Crypto::DigestInfoHash::Sha256, kToBeSigned);

    const auto mark = rig.card->log.size();
    const auto result = plugin->sign(*rig.session, 0x4410, digestInfo, LibreSCRS::Plugin::SignMechanism::RSA_PKCS);

    EXPECT_EQ(result.outcome, LibreSCRS::Plugin::SignResultOutcome::PinIncorrect);
    EXPECT_TRUE(verifyReferencesSince(rig.card->log, mark).empty());
}

// The PIN an operation without a named PIN uses is the one the PIN list shows
// as the user PIN: a "PACE CAN" label without the CAN's shape is listed as a
// user PIN, and is then the PIN a change with an empty selector addresses,
// not one a label rule skips to.
TEST(Pkcs15PluginUserPin, ChangeAddressesTheUserPinTheListShows)
{
    auto rig = makeRig("User PIN Reader 0");
    // SAMPLE_AODF's first two entries -- "PACE CAN" (ref 0x02) and "User PIN"
    // (ref 0x86) -- with the User PIN's local flag cleared, so neither is a
    // local PIN and the rule's order alone decides.
    const auto& sample = pkcs15::test_vectors::SAMPLE_AODF;
    std::vector<std::uint8_t> aodf(sample.begin(), sample.begin() + 96);
    for (std::size_t i = 48; i + 3 < aodf.size(); ++i) {
        if (aodf[i] == 0x03 && aodf[i + 1] == 0x02 && aodf[i + 2] == 0x03 && aodf[i + 3] == 0x48) {
            aodf[i + 3] = 0x08;
            break;
        }
    }
    rig.card->files[kAodfFid] = aodf;
    rig.card->acceptedPins = {"123456"};
    CardPluginService registry{pluginDir()};
    auto plugin = findPkcs15(registry);
    ASSERT_NE(plugin, nullptr);

    const auto list = plugin->getPINList(*rig.session);
    std::optional<std::uint8_t> listed;
    for (const auto& entry : list) {
        if (entry.kind == LibreSCRS::Plugin::PinKind::UserPin &&
            entry.state != LibreSCRS::Plugin::PinState::Transport) {
            listed = entry.reference;
            break;
        }
    }
    ASSERT_TRUE(listed.has_value());

    const auto mark = rig.card->log.size();
    (void)plugin->changePIN(*rig.session, "", LibreSCRS::Secure::String{std::string_view{"123456"}},
                            LibreSCRS::Secure::String{std::string_view{"654321"}});
    std::vector<std::uint8_t> changed;
    for (std::size_t i = mark; i < rig.card->log.size(); ++i) {
        if (rig.card->log[i].ins == 0x24) // CHANGE REFERENCE DATA
            changed.push_back(rig.card->log[i].p2);
    }
    EXPECT_EQ(changed, (std::vector<std::uint8_t>{*listed}));
}
