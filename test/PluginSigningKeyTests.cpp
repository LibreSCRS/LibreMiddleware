// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

// PluginSigningKey against a plugin that records every deposit and sign: what
// reaches the card, how often the PIN is presented, and when it is erased.

#include <gtest/gtest.h>

#include "native/native_utils.h"
#include "native/plugin_signing_key.h"

#include <LibreSCRS/Plugin/PinDeposit.h>
#include "types.h"

#include "signing_stub_plugin.h"

#include <LibreSCRS/CancelToken.h>
#include <LibreSCRS/Logging.h>
#include <LibreSCRS/Secure/Buffer.h>
#include <LibreSCRS/SmartCard/testing/CardSessionTesting.h>
#include <LibreSCRS_internal/Crypto/OpenSslPtr.h>

#include <openssl/evp.h>
#include <openssl/x509.h>

#include <pcsc_connection.h>

#include <cstdint>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

using LibreSCRS::Plugin::SignMechanism;
using LibreSCRS::Plugin::SignResult;
using LibreSCRS::Plugin::SignResultOutcome;
using LibreSCRS::TestSupport::SigningStubPlugin;
using libresign::PluginSigningKey;
using libresign::SignFailureException;
using libresign::SignFailureKind;

const std::vector<std::uint8_t> kDigestInfo{0x30, 0x31, 0x30, 0x0d, 0xAA, 0xBB};
const std::vector<std::uint8_t> kMessage{'m', 'e', 's', 's', 'a', 'g', 'e'};
const std::vector<std::uint8_t> kSignature{0x5A, 0x5A, 0x5A};

SignResult outcome(SignResultOutcome o)
{
    SignResult r;
    r.outcome = o;
    if (o == SignResultOutcome::Ok)
        r.signature = kSignature;
    return r;
}

LibreSCRS::Plugin::CertificateData candidate(bool alwaysAuthenticate = false)
{
    LibreSCRS::Plugin::CertificateData c;
    c.derBytes = {0x30, 0x03, 0x02, 0x01, 0x01};
    c.keyFID = 0x4410;
    c.ckaId = {0x45};
    c.alwaysAuthenticate = alwaysAuthenticate;
    return c;
}

struct Rig
{
    explicit Rig(bool alwaysAuthenticate = false, LibreSCRS::CancelToken token = {},
                 std::vector<std::uint8_t> keyId = {})
        : plugin(std::make_shared<SigningStubPlugin>()),
          session(LibreSCRS::SmartCard::Testing::makeDetachedCardSession("Plugin Key Reader")),
          key(plugin, session, candidate(alwaysAuthenticate), LibreSCRS::Secure::Buffer{std::string_view{"1234"}},
              {candidate().derBytes}, keyId, std::move(token))
    {}

    std::shared_ptr<SigningStubPlugin> plugin;
    std::shared_ptr<LibreSCRS::SmartCard::CardSession> session;
    PluginSigningKey key;
};

SignFailureKind kindOf(const std::function<void()>& f)
{
    try {
        f();
    } catch (const SignFailureException& e) {
        return e.kind;
    }
    ADD_FAILURE() << "no SignFailureException";
    return SignFailureKind::EngineError;
}

using LibreSCRS::Internal::Crypto::EvpPkeyPtr;
using LibreSCRS::Internal::Crypto::X509Ptr;

EvpPkeyPtr makeEcKey()
{
    return EvpPkeyPtr(EVP_EC_gen("P-256"));
}

// A v3 certificate CN=subjectCn issued by CN=issuerCn, signed with issuerKey.
std::vector<std::uint8_t> makeCertDer(const std::string& subjectCn, const std::string& issuerCn, EVP_PKEY* subjectKey,
                                      EVP_PKEY* issuerKey)
{
    X509Ptr x(X509_new());
    X509_set_version(x.get(), 2);
    ASN1_INTEGER_set(X509_get_serialNumber(x.get()), 1);
    X509_gmtime_adj(X509_getm_notBefore(x.get()), -3600);
    X509_gmtime_adj(X509_getm_notAfter(x.get()), 60L * 60 * 24 * 365);
    X509_set_pubkey(x.get(), subjectKey);
    X509_NAME_add_entry_by_txt(X509_get_subject_name(x.get()), "CN", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char*>(subjectCn.c_str()), -1, -1, 0);
    X509_NAME_add_entry_by_txt(X509_get_issuer_name(x.get()), "CN", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char*>(issuerCn.c_str()), -1, -1, 0);
    X509_sign(x.get(), issuerKey, EVP_sha256());
    const int len = i2d_X509(x.get(), nullptr);
    std::vector<std::uint8_t> der(static_cast<std::size_t>(len));
    unsigned char* p = der.data();
    i2d_X509(x.get(), &p);
    return der;
}

} // namespace

// A card with two keys of one holder lists the authentication certificate
// before the signing one, and both before their CA. The chain the formats
// embed is the signer first, then its issuer, and never the sibling.
TEST(PluginSigningKey, ChainIsTheSignerThenItsIssuersWithoutSiblings)
{
    auto caKey = makeEcKey();
    auto authKey = makeEcKey();
    auto signKey = makeEcKey();
    ASSERT_TRUE(caKey && authKey && signKey);
    const auto caDer = makeCertDer("Holder CA", "Holder CA", caKey.get(), caKey.get());
    const auto authDer = makeCertDer("Holder Auth", "Holder CA", authKey.get(), caKey.get());
    const auto signDer = makeCertDer("Holder Sign", "Holder CA", signKey.get(), caKey.get());

    auto signer = candidate();
    signer.derBytes = signDer;
    PluginSigningKey key(std::make_shared<SigningStubPlugin>(),
                         LibreSCRS::SmartCard::Testing::makeDetachedCardSession("Plugin Key Reader"), signer,
                         LibreSCRS::Secure::Buffer{std::string_view{"1234"}}, {authDer, signDer, caDer}, {}, {});

    const auto chain = key.certificateChain();
    ASSERT_EQ(chain.size(), 2U);
    EXPECT_EQ(chain[0], signDer) << "x5c[0] and the leaf of buildOrderedChain must be the signer";
    EXPECT_EQ(chain[1], caDer);
    const auto ordered = libresign::native_utils::buildOrderedChain(chain, {caDer});
    ASSERT_FALSE(ordered.empty());
    EXPECT_EQ(ordered.front(), signDer);
}

TEST(PluginSigningKey, SignsRsaSha256OnCardWhenPluginHasIt)
{
    Rig r;
    r.plugin->respond = [](const SigningStubPlugin::SignCall&) { return outcome(SignResultOutcome::Ok); };

    EXPECT_EQ(r.key.sign(kDigestInfo, "SHA256withRSA", kMessage), kSignature);
    ASSERT_EQ(r.plugin->signCalls.size(), 1U);
    EXPECT_EQ(r.plugin->signCalls[0].mechanism, SignMechanism::RSA_SHA256);
    EXPECT_EQ(r.plugin->signCalls[0].data, kMessage) << "the raw message, which the plugin hashes";
    EXPECT_EQ(r.plugin->signCalls[0].keyReference, 0x4410);
    EXPECT_EQ(r.plugin->events, (std::vector<std::string>{"pin:deposit", "sign"}));
}

TEST(PluginSigningKey, FallsBackToDigestInfoOnlyBeforeThePinWasPresented)
{
    {
        SCOPED_TRACE("NotImplemented: the plugin refused before the card, so the PIN was never presented");
        Rig r;
        r.plugin->respond = [](const SigningStubPlugin::SignCall& c) {
            return outcome(c.mechanism == SignMechanism::RSA_SHA256 ? SignResultOutcome::NotImplemented
                                                                    : SignResultOutcome::Ok);
        };
        EXPECT_EQ(r.key.sign(kDigestInfo, "SHA256withRSA", kMessage), kSignature);
        ASSERT_EQ(r.plugin->signCalls.size(), 2U);
        EXPECT_EQ(r.plugin->signCalls[1].mechanism, SignMechanism::RSA_PKCS);
        EXPECT_EQ(r.plugin->signCalls[1].data, kDigestInfo);
        EXPECT_EQ(r.plugin->count("pin:deposit"), 1);
    }
    {
        SCOPED_TRACE("PluginError: the card may have seen the PIN, so it is not presented again");
        Rig r;
        r.plugin->respond = [](const SigningStubPlugin::SignCall&) { return outcome(SignResultOutcome::PluginError); };
        EXPECT_EQ(kindOf([&] { (void)r.key.sign(kDigestInfo, "SHA256withRSA", kMessage); }),
                  SignFailureKind::CardError);
        EXPECT_EQ(r.plugin->signCalls.size(), 1U);
    }
}

TEST(PluginSigningKey, NoFallbackAfterPinIncorrect)
{
    Rig r;
    r.plugin->respond = [](const SigningStubPlugin::SignCall&) { return outcome(SignResultOutcome::PinIncorrect); };

    EXPECT_EQ(kindOf([&] { (void)r.key.sign(kDigestInfo, "SHA256withRSA", kMessage); }), SignFailureKind::PinFailed);
    EXPECT_EQ(r.plugin->signCalls.size(), 1U);
    EXPECT_EQ(r.plugin->count("pin:erase"), 1) << "a refused PIN is not left for the next operation";
}

TEST(PluginSigningKey, PerOperationKeyErasesPinOnEveryExit)
{
    for (const auto o : {SignResultOutcome::Ok, SignResultOutcome::PluginError}) {
        SCOPED_TRACE(static_cast<int>(o));
        Rig r(/*alwaysAuthenticate=*/true);
        r.plugin->respond = [o](const SigningStubPlugin::SignCall&) { return outcome(o); };
        try {
            (void)r.key.sign(kDigestInfo, "SHA256withRSA", kMessage);
        } catch (const SignFailureException&) {
        }
        EXPECT_EQ(r.plugin->events, (std::vector<std::string>{"pin:deposit", "sign", "pin:erase"}));
        EXPECT_TRUE(r.plugin->depositedPin.empty());
    }
}

TEST(PluginSigningKey, OrdinaryKeyKeepsPinAfterOk)
{
    Rig r;
    r.plugin->respond = [](const SigningStubPlugin::SignCall&) { return outcome(SignResultOutcome::Ok); };

    (void)r.key.sign(kDigestInfo, "SHA256withRSA", kMessage);
    EXPECT_EQ(r.plugin->count("pin:erase"), 0);
    EXPECT_EQ(r.plugin->depositedPin, "1234");
}

TEST(PluginSigningKey, NeverRetriesAfterCancel)
{
    {
        SCOPED_TRACE("cancelled before the signature: nothing reaches the plugin");
        LibreSCRS::CancelSource source;
        source.requestCancel();
        Rig r(false, source.token());
        r.plugin->respond = [](const SigningStubPlugin::SignCall&) { return outcome(SignResultOutcome::Ok); };
        EXPECT_EQ(kindOf([&] { (void)r.key.sign(kDigestInfo, "SHA256withRSA", kMessage); }),
                  SignFailureKind::UserCancelled);
        EXPECT_TRUE(r.plugin->events.empty());
    }
    {
        SCOPED_TRACE("the plugin reports a cancel: no second attempt");
        Rig r;
        r.plugin->respond = [](const SigningStubPlugin::SignCall&) { return outcome(SignResultOutcome::Cancelled); };
        EXPECT_EQ(kindOf([&] { (void)r.key.sign(kDigestInfo, "SHA256withRSA", kMessage); }),
                  SignFailureKind::UserCancelled);
        EXPECT_EQ(r.plugin->signCalls.size(), 1U);
        EXPECT_EQ(r.plugin->count("pin:erase"), 1);
    }
}

TEST(PluginSigningKey, NeverPresentsThePinAgainAfterASessionLoss)
{
    // The plugin's sign carries the VERIFY: after the card was reset under it,
    // sending the PIN again is exactly the sensitive APDU that must never be
    // re-sent. The loss goes to the caller -- as a card failure, since the
    // plugin's throw is contained at the plugin boundary.
    Rig r;
    r.plugin->respond = [](const SigningStubPlugin::SignCall&) -> SignResult {
        throw LibreSCRS::SmartCard::Internal::PCSCError("card reset",
                                                        static_cast<LONG>(0x80100068)); // SCARD_W_RESET_CARD
    };

    EXPECT_EQ(kindOf([&] { (void)r.key.sign(kDigestInfo, "SHA256withRSA", kMessage); }), SignFailureKind::CardError);
    EXPECT_EQ(r.plugin->signCalls.size(), 1U);
    EXPECT_EQ(r.plugin->count("pin:deposit"), 1);
    EXPECT_EQ(r.plugin->count("pin:erase"), 1);
}

TEST(PluginSigningKey, PinBlockedMapsToCardBlocked)
{
    Rig r;
    r.plugin->respond = [](const SigningStubPlugin::SignCall&) { return outcome(SignResultOutcome::PinBlocked); };

    EXPECT_EQ(kindOf([&] { (void)r.key.sign(kDigestInfo, "SHA256withRSA", kMessage); }), SignFailureKind::PinBlocked);
    EXPECT_EQ(r.plugin->signCalls.size(), 1U);
}

TEST(PluginSigningKey, KeyIdLengthIsValidatedBeforeAnyCardCall)
{
    auto plugin = std::make_shared<SigningStubPlugin>();
    auto session = LibreSCRS::SmartCard::Testing::makeDetachedCardSession("Plugin Key Reader");
    const LibreSCRS::Secure::Buffer pin{std::string_view{"1234"}};
    const auto make = [&](std::vector<std::uint8_t> keyId) {
        PluginSigningKey key(plugin, session, candidate(), pin, {}, keyId, {});
    };

    EXPECT_THROW(make(std::vector<std::uint8_t>(PluginSigningKey::kMaxKeyIdLength + 1, 0x45)), std::invalid_argument);
    EXPECT_THROW(make({0x46}), std::invalid_argument) << "a CKA_ID that names another key";
    EXPECT_NO_THROW(make({0x45}));
    EXPECT_NO_THROW(make({}));
    EXPECT_TRUE(plugin->events.empty());
}

TEST(PluginSigningKey, EmptyPinIsRefusedBeforeAnyCardCall)
{
    // An empty "pin" deposit means "erase the deposit": the card would then
    // sign on whatever the held session is already verified for.
    auto plugin = std::make_shared<SigningStubPlugin>();
    auto session = LibreSCRS::SmartCard::Testing::makeDetachedCardSession("Plugin Key Reader");
    EXPECT_THROW(PluginSigningKey(plugin, session, candidate(), LibreSCRS::Secure::Buffer{}, {}, {}, {}),
                 std::invalid_argument);
    EXPECT_TRUE(plugin->events.empty());
}

TEST(PluginSigningKey, EcdsaSignsTheHashAndUnknownAlgorithmsNeverReachTheCard)
{
    Rig r;
    r.plugin->respond = [](const SigningStubPlugin::SignCall&) { return outcome(SignResultOutcome::Ok); };
    const std::vector<std::uint8_t> hash384(48, 0x11);

    EXPECT_EQ(r.key.sign(hash384, "SHA384withECDSA", {}), kSignature);
    ASSERT_EQ(r.plugin->signCalls.size(), 1U);
    EXPECT_EQ(r.plugin->signCalls[0].mechanism, SignMechanism::ECDSA_SHA384);
    EXPECT_EQ(r.plugin->signCalls[0].data, hash384);

    EXPECT_THROW((void)r.key.sign(hash384, "SHA256withRSA-PSS", {}), std::invalid_argument);
    EXPECT_THROW((void)r.key.sign(std::vector<std::uint8_t>(20, 0x11), "SHA1withECDSA", {}), std::invalid_argument);
    EXPECT_EQ(r.plugin->signCalls.size(), 1U);
}

// The deposit every host uses: erased when the scope ends unless the host
// keeps it for the session's lease, and erased even when the scope ends by
// an exception.
TEST(ScopedPinDeposit, ErasesThePinUnlessKeptForTheLease)
{
    auto session = LibreSCRS::SmartCard::Testing::makeDetachedCardSession("Deposit Reader");
    {
        SigningStubPlugin plugin;
        {
            LibreSCRS::Plugin::ScopedPinDeposit deposit{plugin, *session,
                                                        LibreSCRS::Secure::String{std::string_view{"1234"}}};
        }
        EXPECT_EQ(plugin.events, (std::vector<std::string>{"pin:deposit", "pin:erase"}));
    }
    {
        SigningStubPlugin plugin;
        {
            LibreSCRS::Plugin::ScopedPinDeposit deposit{plugin, *session,
                                                        LibreSCRS::Secure::String{std::string_view{"1234"}}};
            deposit.keepForLease();
        }
        EXPECT_EQ(plugin.events, (std::vector<std::string>{"pin:deposit"}));
    }
    {
        SigningStubPlugin plugin;
        try {
            LibreSCRS::Plugin::ScopedPinDeposit deposit{plugin, *session,
                                                        LibreSCRS::Secure::String{std::string_view{"1234"}}};
            throw std::runtime_error("the operation failed");
        } catch (const std::runtime_error&) {
        }
        EXPECT_EQ(plugin.events, (std::vector<std::string>{"pin:deposit", "pin:erase"}));
    }
}

namespace {

// A plugin whose erase fails, as one whose session is already gone can.
class EraseRefusingPlugin final : public SigningStubPlugin
{
public:
    void setCredentials(LibreSCRS::SmartCard::CardSession& session, std::string_view key,
                        const LibreSCRS::Secure::String& value) override
    {
        SigningStubPlugin::setCredentials(session, key, value);
        if (value.view().empty())
            throw std::runtime_error("the plugin cannot erase");
    }
};

class ScopedPinDepositLog : public ::testing::Test
{
protected:
    void TearDown() override
    {
        LibreSCRS::log::resetForTest();
    }
};

} // namespace

// An erase that fails is said, not swallowed: the PIN may still be in the
// plugin, and the destructor still lets nothing out.
TEST_F(ScopedPinDepositLog, AnEraseThatFailsIsLogged)
{
    std::vector<std::pair<LibreSCRS::log::Level, std::string>> lines;
    LibreSCRS::log::init(
        [&lines](LibreSCRS::log::Level level, std::string_view line) { lines.emplace_back(level, std::string(line)); },
        "test.deposit");
    auto session = LibreSCRS::SmartCard::Testing::makeDetachedCardSession("Deposit Log Reader");
    EraseRefusingPlugin plugin;

    const auto scope = [&] {
        LibreSCRS::Plugin::ScopedPinDeposit deposit{plugin, *session,
                                                    LibreSCRS::Secure::String{std::string_view{"1234"}}};
    };
    EXPECT_NO_THROW(scope());

    EXPECT_EQ(plugin.events, (std::vector<std::string>{"pin:deposit", "pin:erase"}));
    ASSERT_EQ(lines.size(), 1U);
    EXPECT_EQ(lines[0].first, LibreSCRS::log::Level::Warn);
    EXPECT_NE(lines[0].second.find("erase"), std::string::npos) << lines[0].second;
}

// The report itself may fail -- the host's sink is code the deposit does not
// own -- and still nothing leaves the destructor.
TEST_F(ScopedPinDepositLog, ASinkThatThrowsDoesNotEscapeTheDestructor)
{
    LibreSCRS::log::init([](LibreSCRS::log::Level, std::string_view) { throw std::runtime_error("sink down"); },
                         "test.deposit");
    auto session = LibreSCRS::SmartCard::Testing::makeDetachedCardSession("Deposit Log Reader 1");
    EraseRefusingPlugin plugin;

    const auto scope = [&] {
        LibreSCRS::Plugin::ScopedPinDeposit deposit{plugin, *session,
                                                    LibreSCRS::Secure::String{std::string_view{"1234"}}};
    };
    EXPECT_NO_THROW(scope());
    EXPECT_EQ(plugin.events, (std::vector<std::string>{"pin:deposit", "pin:erase"}));
}
