// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

// PluginSigningKey against a plugin that records every deposit and sign: what
// reaches the card, how often the PIN is presented, and when it is erased.

#include <gtest/gtest.h>

#include "native/plugin_signing_key.h"
#include "types.h"

#include "signing_stub_plugin.h"

#include <LibreSCRS/CancelToken.h>
#include <LibreSCRS/Secure/Buffer.h>
#include <LibreSCRS/SmartCard/detail/CardSessionInjection.h>

#include <pcsc_connection.h>

#include <cstdint>
#include <memory>
#include <stdexcept>
#include <string>
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
          session(LibreSCRS::SmartCard::detail::makeDetachedCardSession("Plugin Key Reader")),
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

} // namespace

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
    // re-sent. The loss goes to the caller.
    Rig r;
    r.plugin->respond = [](const SigningStubPlugin::SignCall&) -> SignResult {
        throw LibreSCRS::SmartCard::Internal::PCSCError("card reset",
                                                        static_cast<LONG>(0x80100068)); // SCARD_W_RESET_CARD
    };

    EXPECT_THROW((void)r.key.sign(kDigestInfo, "SHA256withRSA", kMessage), LibreSCRS::SmartCard::Internal::PCSCError);
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
    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("Plugin Key Reader");
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
    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("Plugin Key Reader");
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
