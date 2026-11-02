// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

/// @file
/// @brief The @ref LibreSCRS::Plugin::CardPlugin entry points report a
///        plugin that throws as that call's failure; nothing a plugin throws
///        reaches the host.
///
/// A host loads plugins it did not build. Whether a plugin catches its own
/// exceptions was once up to each plugin, so a host either wrapped every call
/// or met an exception from one plugin where another returned an outcome.
/// The base class now owns that: every public entry point is a non-virtual
/// wrapper over a protected virtual, and the wrapper turns a throw into the
/// failure its result type already has.

#include <LibreSCRS/Logging.h>
#include <LibreSCRS/Plugin/CardPlugin.h>
#include <LibreSCRS/Secure/String.h>
#include <LibreSCRS/SmartCard/CardSession.h>
#include <LibreSCRS/SmartCard/testing/CardSessionTesting.h>

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <memory>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {
using namespace LibreSCRS::Plugin;
using LibreSCRS::Secure::String;
using LibreSCRS::SmartCard::CardSession;

// Throws from every override. A non-standard exception as well as a
// std::exception, because a plugin is free to throw either and the
// wrapper's answer must not depend on which.
class ThrowingPlugin final : public CardPlugin
{
public:
    explicit ThrowingPlugin(bool standard) : standard(standard)
    {
        setIdentity("throwing", 0);
    }

    CardCapabilities capabilities() const override
    {
        return CardCapabilities::PKI;
    }

    std::span<const Atr> supportedAtrs() const noexcept override
    {
        return {};
    }

protected:
    ReadResult doReadCard(CardSession&, GroupCallback) const override
    {
        fail("doReadCard");
    }
    std::vector<CertificateData> doReadCertificates(CardSession&) const override
    {
        fail("doReadCertificates");
    }
    std::vector<PinStatusEntry> doGetPINList(CardSession&) const override
    {
        fail("doGetPINList");
    }
    PINResult doChangePIN(CardSession&, std::string_view, const String&, const String&) const override
    {
        fail("doChangePIN");
    }
    SignResult doSign(CardSession&, std::uint16_t, std::span<const std::uint8_t>, SignMechanism) const override
    {
        fail("doSign");
    }
    DecipherResult doDecipher(CardSession&, std::uint16_t, std::span<const std::uint8_t>,
                              DecipherMechanism) const override
    {
        fail("doDecipher");
    }
    PINResult doActivateTransportPin(CardSession&, std::string_view, const String&, const String&) const override
    {
        fail("doActivateTransportPin");
    }
    PINResult doActivateSigningKey(CardSession&, const String&) const override
    {
        fail("doActivateSigningKey");
    }

private:
    [[noreturn]] void fail(const char* where) const
    {
        if (standard)
            throw std::runtime_error(std::string{where} + ": card went away");
        throw 42;
    }

    bool standard;
};

class CardPluginContainment : public ::testing::TestWithParam<bool>
{
protected:
    void SetUp() override
    {
        LibreSCRS::log::init([this](LibreSCRS::log::Level level,
                                    std::string_view line) { lines.emplace_back(level, std::string(line)); },
                             "test.containment");
        session = LibreSCRS::SmartCard::Testing::makeDetachedCardSession("Containment Reader");
        ASSERT_NE(session, nullptr);
    }

    void TearDown() override
    {
        LibreSCRS::log::resetForTest();
    }

    // One report per contained throw, naming the entry point the host called
    // so a log reader can tell which operation the plugin failed.
    void expectOneReportNaming(std::string_view entry)
    {
        ASSERT_EQ(lines.size(), 1U);
        EXPECT_EQ(lines[0].first, LibreSCRS::log::Level::Error);
        EXPECT_NE(lines[0].second.find(entry), std::string::npos) << lines[0].second;
        EXPECT_NE(lines[0].second.find("throwing"), std::string::npos) << lines[0].second;
        lines.clear();
    }

    ThrowingPlugin plugin{GetParam()};
    std::shared_ptr<CardSession> session;
    std::vector<std::pair<LibreSCRS::log::Level, std::string>> lines;
    const String pin{std::string_view{"1234"}};
    const String other{std::string_view{"5678"}};
    const std::array<std::uint8_t, 32> data{};
};

TEST_P(CardPluginContainment, PinEntryPointsReportAPluginError)
{
    PINResult r;
    ASSERT_NO_THROW(r = plugin.changePIN(*session, "UserPIN", pin, other));
    EXPECT_EQ(r.outcome, PINResultOutcome::PluginError);
    EXPECT_FALSE(r.retriesLeft.has_value());
    expectOneReportNaming("changePIN");

    ASSERT_NO_THROW(r = plugin.activateTransportPin(*session, "SignaturePIN", pin, other));
    EXPECT_EQ(r.outcome, PINResultOutcome::PluginError);
    expectOneReportNaming("activateTransportPin");

    ASSERT_NO_THROW(r = plugin.activateSigningKey(*session, pin));
    EXPECT_EQ(r.outcome, PINResultOutcome::PluginError);
    expectOneReportNaming("activateSigningKey");
}

// These results have no failure value of their own: a plugin that throws is
// reported as having nothing to show, which is what a host already handles
// for a card without certificates or PINs.
TEST_P(CardPluginContainment, ListingEntryPointsReportNothing)
{
    std::vector<CertificateData> certs{CertificateData{}};
    ASSERT_NO_THROW(certs = plugin.readCertificates(*session));
    EXPECT_TRUE(certs.empty());
    expectOneReportNaming("readCertificates");

    std::vector<PinStatusEntry> pins{PinStatusEntry{}};
    ASSERT_NO_THROW(pins = plugin.getPINList(*session));
    EXPECT_TRUE(pins.empty());
    expectOneReportNaming("getPINList");
}

TEST_P(CardPluginContainment, OperationEntryPointsReportAPluginError)
{
    ReadResult read = ReadResult::ok({});
    ASSERT_NO_THROW(read = plugin.readCard(*session));
    EXPECT_EQ(read.status, ReadResult::Status::CommunicationError);
    EXPECT_FALSE(read.data.has_value());
    expectOneReportNaming("readCard");

    SignResult sig;
    ASSERT_NO_THROW(sig = plugin.sign(*session, 0x01, data, SignMechanism::RSA_PKCS));
    EXPECT_EQ(sig.outcome, SignResultOutcome::PluginError);
    EXPECT_TRUE(sig.signature.empty());
    expectOneReportNaming("sign");

    DecipherResult plain;
    ASSERT_NO_THROW(plain = plugin.decipher(*session, 0x01, data, DecipherMechanism::RSA_PKCS1_V15));
    EXPECT_EQ(plain.outcome, DecipherResultOutcome::PluginError);
    expectOneReportNaming("decipher");
}

// The report runs a sink the host installed; a sink that throws must not
// turn a contained failure back into an escaping one.
TEST_P(CardPluginContainment, ASinkThatThrowsDoesNotUndoTheContainment)
{
    LibreSCRS::log::init([](LibreSCRS::log::Level, std::string_view) { throw std::runtime_error("sink down"); },
                         "test.containment");
    PINResult r;
    ASSERT_NO_THROW(r = plugin.changePIN(*session, "UserPIN", pin, other));
    EXPECT_EQ(r.outcome, PINResultOutcome::PluginError);
    std::vector<CertificateData> certs;
    ASSERT_NO_THROW(certs = plugin.readCertificates(*session));
    EXPECT_TRUE(certs.empty());
}

INSTANTIATE_TEST_SUITE_P(StdAndOther, CardPluginContainment, ::testing::Values(true, false),
                         [](const ::testing::TestParamInfo<bool>& info) {
                             return info.param ? std::string{"StdException"} : std::string{"NonStdException"};
                         });

} // namespace
