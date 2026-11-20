// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

/// @file
/// @brief Which path each shipped card plugin's commands take to the card.
///
/// The plugins load as they ship (dlopen from the build tree) and run on a
/// detached session whose connection counts the two ways a command reaches
/// the wire: the typed transmit (the plain path, which completes a chained
/// answer) and the raw single exchange. A stand-in channel takes the place of
/// a live secure-messaging tunnel. A plugin that reaches the card through the
/// session's public calls keeps every command on the path it had, and sends
/// nothing plain past a live tunnel.

#include <LibreSCRS/Plugin/CardPlugin.h>
#include <LibreSCRS/Plugin/CardPluginService.h>
#include <LibreSCRS/SmartCard/CardSession.h>
#include <LibreSCRS/SmartCard/testing/CardSessionTesting.h>
#include <LibreSCRS/SmartCard/detail/ChannelInjection.h>

#include <apdu.h>
#include <pcsc_connection.h>
#include <session_access.h>
#include <fake_channel.h>
#include <session_access.h>

#include <gtest/gtest.h>

#include <cstdint>
#include <functional>
#include <filesystem>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace {

using LibreSCRS::SmartCard::CardSession;
using LibreSCRS::SmartCard::Internal::APDUCommand;
using LibreSCRS::SmartCard::Internal::APDUResponse;
using LibreSCRS::SmartCard::Testing::SessionAccess;
using LibreSCRS::SmartCard::Testing::StandInChannel;
using Bytes = std::vector<std::uint8_t>;

LibreSCRS::Plugin::CardPluginService& registry()
{
    static LibreSCRS::Plugin::CardPluginService service{std::filesystem::path(PLUGIN_DIR)};
    return service;
}

std::shared_ptr<LibreSCRS::Plugin::CardPlugin> plugin(std::string_view id)
{
    for (const auto& p : registry().plugins()) {
        if (p->pluginId() == id)
            return p;
    }
    return nullptr;
}

// A detached session whose connection answers every command "file not found"
// and counts each by the path it took.
struct WireRig
{
    explicit WireRig(Bytes atr = {})
    {
        session = SessionAccess::detached("plugin-path-reader");
        auto& conn = LibreSCRS::SmartCard::Internal::connectionOf(*session);
        if (!atr.empty())
            conn.setDetachedAtr(atr);                    // what the connection reports
        SessionAccess::setAtr(*session, std::move(atr)); // what the session recorded at open
        conn.setTransmitFilter([this](const APDUCommand& cmd) {
            plain.push_back(cmd.toBytes());
            return APDUResponse{{}, 0x6A, 0x82};
        });
        conn.setDetachedRawResponder([this](std::span<const std::uint8_t> bytes) {
            raw.emplace_back(bytes.begin(), bytes.end());
            return APDUResponse{{}, 0x6A, 0x82};
        });
    }

    bool probe(std::string_view id)
    {
        auto p = plugin(id);
        EXPECT_NE(p, nullptr) << id << " did not load from " << PLUGIN_DIR;
        return p && p->canHandleConnection(session->atr(), *session);
    }

    std::shared_ptr<CardSession> session;
    std::vector<Bytes> plain;
    std::vector<Bytes> raw;
};

// A Gemalto-family ATR: the rs-eid probe then SELECTs its applications.
const Bytes kGemaltoAtr{0x3B, 0xFF, 0x94, 0x00, 0x00};

// Each plugin's probe of a card that answers "not found" to everything: the
// commands it sends go plain (typed, the reader layer completing a chained
// answer) or raw, exactly as before the plugin reached the card through the
// session's public calls.
TEST(PluginSessionPath, TheHealthCardProbeGoesPlain)
{
    WireRig rig;
    EXPECT_FALSE(rig.probe("rs-health"));
    EXPECT_FALSE(rig.plain.empty());
    EXPECT_TRUE(rig.raw.empty());
}

TEST(PluginSessionPath, TheVehicleCardProbeGoesPlain)
{
    WireRig rig;
    EXPECT_FALSE(rig.probe("eu-vrc"));
    EXPECT_FALSE(rig.plain.empty());
    EXPECT_TRUE(rig.raw.empty());
}

TEST(PluginSessionPath, TheEidProbeGoesPlain)
{
    WireRig rig(kGemaltoAtr);
    EXPECT_FALSE(rig.probe("rs-eid"));
    EXPECT_FALSE(rig.plain.empty());
    EXPECT_TRUE(rig.raw.empty());
}

TEST(PluginSessionPath, TheEmrtdProbeGoesPlain)
{
    WireRig rig;
    EXPECT_FALSE(rig.probe("emrtd"));
    EXPECT_FALSE(rig.plain.empty());
    EXPECT_TRUE(rig.raw.empty());
}

TEST(PluginSessionPath, ThePkcs15ProbeGoesPlain)
{
    WireRig rig;
    EXPECT_FALSE(rig.probe("pkcs15"));
    EXPECT_FALSE(rig.plain.empty());
    EXPECT_TRUE(rig.raw.empty());
}

TEST(PluginSessionPath, TheOpenScProbeSelectsPlainThenBindsRaw)
{
    // One plain SELECT looks for the PACE gate; the bind then goes through
    // libopensc, which does its own GET RESPONSE and length retries: the
    // bridge hands it the card's raw answer, one exchange per command.
    WireRig rig;
    (void)rig.probe("opensc");
    EXPECT_EQ(rig.plain.size(), 1U);
    EXPECT_FALSE(rig.raw.empty());
}

// Past a live secure-messaging tunnel nothing goes plain: each command rides
// the tunnel (the stand-in answers 6F00) or is refused. Before the plugins
// reached the card through the session, the plain probes went to the wire
// and ended the card's secure-messaging session.
TEST(PluginSessionPath, NoProbeSendsPlainPastALiveTunnel)
{
    for (const char* id : {"rs-health", "eu-vrc", "rs-eid", "emrtd", "pkcs15", "opensc"}) {
        SCOPED_TRACE(id);
        WireRig rig(kGemaltoAtr);
        LibreSCRS::SmartCard::Testing::installStandInChannel(*rig.session, StandInChannel::LiveSecureMessaging);
        (void)rig.probe(id);
        EXPECT_TRUE(rig.plain.empty());
        EXPECT_TRUE(rig.raw.empty());
    }
}

// Under another provider's live tunnel the eMRTD probe does not read EF.COM:
// that read would ride the tunnel and be recorded as "readable without PACE".
TEST(PluginSessionPath, TheEmrtdProbeDoesNotJudgePlainAccessThroughATunnel)
{
    WireRig rig;
    std::vector<Bytes> tunnelled;
    auto tunnel = std::make_unique<LibreSCRS::SecureChannel::TestSupport::FakeChannel>(
        LibreSCRS::SmartCard::AppletAid{}, LibreSCRS::SecureChannel::ChannelState::Open, /*carriesSm=*/true);
    tunnel->transmitHandler = [&tunnelled](const APDUCommand& cmd) {
        tunnelled.push_back(cmd.toBytes());
        return APDUResponse{{}, 0x90, 0x00};
    };
    LibreSCRS::SmartCard::detail::ChannelInjector::installForTesting(*rig.session, std::move(tunnel),
                                                                     LibreSCRS::SmartCard::PaceRequest{});
    (void)rig.probe("emrtd");
    ASSERT_FALSE(tunnelled.empty()) << "the probe rides the tunnel";
    for (const auto& cmd : tunnelled) {
        const bool selectsCom = cmd.size() >= 7 && cmd[1] == 0xA4 && cmd[5] == 0x01 && cmd[6] == 0x1E;
        EXPECT_FALSE(selectsCom) << "EF.COM was read through the tunnel";
    }
    EXPECT_TRUE(rig.plain.empty());
}

// A tunnel that failed refuses every probe command when a plugin probes the
// session directly: nothing goes plain on the session's own decision.
TEST(PluginSessionPath, ADirectProbeSendsNothingPastAFailedTunnel)
{
    for (const char* id : {"rs-health", "eu-vrc", "rs-eid", "emrtd", "pkcs15"}) {
        SCOPED_TRACE(id);
        WireRig rig(kGemaltoAtr);
        LibreSCRS::SmartCard::Testing::installStandInChannel(*rig.session, StandInChannel::FailedSecureMessaging);
        (void)rig.probe(id);
        EXPECT_TRUE(rig.plain.empty());
        EXPECT_TRUE(rig.raw.empty());
        EXPECT_TRUE(rig.session->carriesSecureMessaging()) << "the session dropped the dead tunnel on its own";
    }
}

// Identifying the card through the plugin service starts a new, plain
// interaction: it removes the failed tunnel, and every plugin probes the
// card exactly as on a session that never had one. Two ATRs: with the
// Gemalto one rs-eid is matched by ATR and probes nothing; with none every
// plugin probes.
TEST(PluginSessionPath, PlainProbesWorkAfterATunnelFailed)
{
    for (const Bytes& atr : {kGemaltoAtr, Bytes{}}) {
        SCOPED_TRACE(atr.empty() ? "no ATR" : "Gemalto ATR");
        WireRig fresh(atr);
        const auto freshCandidates = registry().findAllCandidates(fresh.session->atr(), *fresh.session);
        ASSERT_FALSE(fresh.plain.empty())
            << "the probes send nothing on a fresh session; the comparison proves nothing";

        WireRig rig(atr);
        LibreSCRS::SmartCard::Testing::installStandInChannel(*rig.session, StandInChannel::FailedSecureMessaging);
        const auto candidates = registry().findAllCandidates(rig.session->atr(), *rig.session);

        EXPECT_FALSE(rig.session->carriesSecureMessaging()) << "the dead tunnel stayed installed";
        EXPECT_EQ(rig.plain, fresh.plain) << "a probe went nowhere: the dead tunnel refused it";
        EXPECT_EQ(rig.raw, fresh.raw);
        EXPECT_EQ(candidates.size(), freshCandidates.size());
    }
}

// A plugin operation that starts plain I/O by design discards a tunnel that
// failed earlier, with no identification pass first: the hybrid-card case of
// a PACE operation that failed, then a plain plugin's read on the same
// session.
TEST(PluginSessionPath, APlainOperationAfterATunnelFailedReachesTheCard)
{
    struct Case
    {
        const char* id;
        const char* what;
        std::function<void(const LibreSCRS::Plugin::CardPlugin&, CardSession&)> run;
    };
    const std::vector<Case> cases{
        {"rs-health", "readCard", [](const LibreSCRS::Plugin::CardPlugin& p, CardSession& s) { (void)p.readCard(s); }},
        {"eu-vrc", "readCard", [](const LibreSCRS::Plugin::CardPlugin& p, CardSession& s) { (void)p.readCard(s); }},
        {"rs-eid", "readCard", [](const LibreSCRS::Plugin::CardPlugin& p, CardSession& s) { (void)p.readCard(s); }},
        {"pkcs15", "readCertificates",
         [](const LibreSCRS::Plugin::CardPlugin& p, CardSession& s) { (void)p.readCertificates(s); }},
        {"pkcs15", "getPINList", [](const LibreSCRS::Plugin::CardPlugin& p, CardSession& s) { (void)p.getPINList(s); }},
    };
    // The PKCS#15 cases pass with or without the wrapper's discard: that
    // plugin activates its channel in each operation, and the activation
    // replaces a failed one. They show the end-to-end path stays working;
    // PlainProfileOperationsDiscardAFailedTunnelFirst below is the test of
    // each wrapper.
    for (const auto& c : cases) {
        SCOPED_TRACE(std::string{c.id} + " " + c.what);
        WireRig rig(kGemaltoAtr);
        LibreSCRS::SmartCard::Testing::installStandInChannel(*rig.session, StandInChannel::FailedSecureMessaging);
        const auto p = plugin(c.id);
        ASSERT_NE(p, nullptr);
        c.run(*p, *rig.session);
        EXPECT_FALSE(rig.plain.empty() && rig.raw.empty()) << "the operation was locked out by the failed tunnel";
        EXPECT_FALSE(rig.session->carriesSecureMessaging()) << "the failed tunnel stayed installed";
    }
}

// A plugin with the default (plain) activation profile whose every
// operation sends one command of its own through the session first.
class PlainOpsPlugin : public LibreSCRS::Plugin::CardPlugin
{
public:
    PlainOpsPlugin()
    {
        setIdentity("plain-ops", /*priority=*/1000);
    }

    LibreSCRS::Plugin::CardCapabilities capabilities() const override
    {
        return LibreSCRS::Plugin::CardCapabilities::PKI;
    }

    std::span<const LibreSCRS::Plugin::Atr> supportedAtrs() const noexcept override
    {
        return {};
    }

    // GET DATA with P2 naming the operation: what each one sends first.
    static Bytes firstCommand(std::uint8_t op)
    {
        return {0x00, 0xCA, 0x01, op, 0x00};
    }

protected:
    LibreSCRS::Plugin::ReadResult doReadCard(CardSession& s, GroupCallback) const override
    {
        send(s, 1);
        return LibreSCRS::Plugin::ReadResult::ok(LibreSCRS::Plugin::CardData{});
    }
    std::vector<LibreSCRS::Plugin::CertificateData> doReadCertificates(CardSession& s) const override
    {
        send(s, 2);
        return {};
    }
    std::vector<LibreSCRS::Plugin::PinStatusEntry> doGetPINList(CardSession& s) const override
    {
        send(s, 3);
        return {};
    }
    LibreSCRS::Plugin::PINResult doChangePIN(CardSession& s, std::string_view, const LibreSCRS::Secure::String&,
                                             const LibreSCRS::Secure::String&) const override
    {
        send(s, 4);
        return {};
    }
    LibreSCRS::Plugin::SignResult doSign(CardSession& s, std::uint16_t, std::span<const std::uint8_t>,
                                         LibreSCRS::Plugin::SignMechanism) const override
    {
        send(s, 5);
        return {};
    }
    LibreSCRS::Plugin::DecipherResult doDecipher(CardSession& s, std::uint16_t, std::span<const std::uint8_t>,
                                                 LibreSCRS::Plugin::DecipherMechanism) const override
    {
        send(s, 6);
        return {};
    }
    LibreSCRS::Plugin::PINResult doActivateTransportPin(CardSession& s, std::string_view,
                                                        const LibreSCRS::Secure::String&,
                                                        const LibreSCRS::Secure::String&) const override
    {
        send(s, 7);
        return {};
    }
    LibreSCRS::Plugin::PINResult doActivateSigningKey(CardSession& s, const LibreSCRS::Secure::String&) const override
    {
        send(s, 8);
        return {};
    }

private:
    static void send(CardSession& s, std::uint8_t op)
    {
        (void)s.transmit(firstCommand(op));
    }
};

// Every operation wrapper of a plain-profile plugin discards a failed tunnel
// before the operation runs: its first command goes out plain. A wrapper
// without the discard leaves that command refused (6F02, nothing sent).
TEST(PluginSessionPath, PlainProfileOperationsDiscardAFailedTunnelFirst)
{
    using LibreSCRS::Plugin::CardPlugin;
    const LibreSCRS::Secure::String pin{"1234"};
    const std::vector<std::uint8_t> data(32, 0x11);
    struct Case
    {
        const char* what;
        std::uint8_t op;
        std::function<void(const CardPlugin&, CardSession&)> run;
    };
    const std::vector<Case> cases{
        {"readCard", 1, [](const CardPlugin& p, CardSession& s) { (void)p.readCard(s); }},
        {"readCertificates", 2, [](const CardPlugin& p, CardSession& s) { (void)p.readCertificates(s); }},
        {"getPINList", 3, [](const CardPlugin& p, CardSession& s) { (void)p.getPINList(s); }},
        {"changePIN", 4, [&](const CardPlugin& p, CardSession& s) { (void)p.changePIN(s, "pin", pin, pin); }},
        {"sign", 5,
         [&](const CardPlugin& p, CardSession& s) {
             (void)p.sign(s, 0x01, data, LibreSCRS::Plugin::SignMechanism::RSA_PKCS);
         }},
        {"decipher", 6,
         [&](const CardPlugin& p, CardSession& s) {
             (void)p.decipher(s, 0x01, data, LibreSCRS::Plugin::DecipherMechanism::RSA_PKCS1_V15);
         }},
        {"activateTransportPin", 7,
         [&](const CardPlugin& p, CardSession& s) { (void)p.activateTransportPin(s, "pin", pin, pin); }},
        {"activateSigningKey", 8, [&](const CardPlugin& p, CardSession& s) { (void)p.activateSigningKey(s, pin); }},
    };
    const PlainOpsPlugin plugin;
    for (const auto& c : cases) {
        SCOPED_TRACE(c.what);
        WireRig rig;
        LibreSCRS::SmartCard::Testing::installStandInChannel(*rig.session, StandInChannel::FailedSecureMessaging);
        c.run(plugin, *rig.session);
        EXPECT_FALSE(rig.session->carriesSecureMessaging()) << "the failed tunnel stayed installed";
        ASSERT_FALSE(rig.plain.empty()) << "the operation's first command was refused";
        EXPECT_EQ(rig.plain.front(), PlainOpsPlugin::firstCommand(c.op));
    }
}

} // namespace
