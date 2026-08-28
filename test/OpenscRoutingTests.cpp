// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

// Routing tests for the opensc plugin's second-generation contactless claim
// (no hardware): the REAL plugin registry (every shipped .so) walks a
// detached CardSession whose injected FakeChannel scripts the card's answers,
// so the two-phase candidate lookup runs the actual canHandleConnection
// probes of every plugin against the same scripted card.
//
// What is deliberately NOT here (hardware-gated): the related family's raw
// contactless walk (no live SM), where the generic pkcs15 plugin claims the
// card after this plugin's deferred gates decline — a raw-path probe needs a
// real PC/SC connection; and the credential-list lazy-fallback integration,
// which lives on the agent flow above this repo and needs a bindable card.

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>
#include <vector>

#include <LibreSCRS/CancelToken.h>
#include <LibreSCRS/Plugin/CardPlugin.h>
#include <LibreSCRS/Plugin/CardPluginService.h>
#include <LibreSCRS/SmartCard/CardSession.h>
#include <LibreSCRS/SmartCard/detail/CardSessionInjection.h>
#include <LibreSCRS/SmartCard/detail/ChannelInjection.h>

#include <apdu.h>
#include <fake_channel.h>

using LibreSCRS::SecureChannel::ChannelState;
using LibreSCRS::SecureChannel::TestSupport::FakeChannel;
using LibreSCRS::SmartCard::AppletAid;
using LibreSCRS::SmartCard::PaceRequest;
using LibreSCRS::SmartCard::SmProtocolRequest;
using LibreSCRS::SmartCard::Internal::APDUCommand;
using LibreSCRS::SmartCard::Internal::APDUResponse;

namespace {

const std::vector<std::uint8_t> kPkcs15Aid{0xA0, 0x00, 0x00, 0x00, 0x63, 0x50, 0x4B, 0x43, 0x53, 0x2D, 0x31, 0x35};
const std::vector<std::uint8_t> kTestAtr{0x3B, 0x00};

APDUResponse sw(std::uint8_t sw1, std::uint8_t sw2)
{
    APDUResponse r;
    r.sw1 = sw1;
    r.sw2 = sw2;
    return r;
}

bool isSelectPkcs15Aid(const APDUCommand& cmd)
{
    return cmd.ins == 0xA4 && cmd.p1 == 0x04 && cmd.data == kPkcs15Aid;
}

struct ScriptedContactlessCard
{
    explicit ScriptedContactlessCard(const std::string& readerName)
        : session(LibreSCRS::SmartCard::detail::makeDetachedCardSession(readerName))
    {
        AppletAid aid{0xA0, 0x00, 0x00, 0x00, 0x63, 0x50, 0x4B, 0x43, 0x53, 0x2D, 0x31, 0x35};
        auto owned = std::make_unique<FakeChannel>(aid, ChannelState::Open, /*carriesSm=*/true,
                                                   /*crossAppletReuse=*/true);
        channel = owned.get();
        LibreSCRS::SmartCard::detail::ChannelInjector::installForTesting(
            *session, std::move(owned), SmProtocolRequest{PaceRequest{LibreSCRS::Auth::PaceSecretKind::Can}});
    }

    std::shared_ptr<LibreSCRS::SmartCard::CardSession> session;
    FakeChannel* channel = nullptr; // borrowed; owned by the session
};

std::vector<std::string> candidateIds(const std::vector<std::shared_ptr<LibreSCRS::Plugin::CardPlugin>>& candidates)
{
    std::vector<std::string> ids;
    ids.reserve(candidates.size());
    for (const auto& c : candidates)
        ids.push_back(c->pluginId());
    return ids;
}

} // namespace

// The second-generation contactless shape as its live-PACE tunnel presents
// it: the PKCS#15 applet answers a wrapped SELECT with 9000, every other
// applet probe misses. BOTH generic PKCS#15 consumers claim the card; the
// routing guarantee is that the opensc plugin (priority 800) precedes the
// generic pkcs15 parser (priority 900) so its full driver chain, not the
// generic parser, fronts the card's PKI. This asserts that ordering
// explicitly rather than as a side effect of a hardware flow. (It does NOT
// assert opensc is the absolute front candidate: on a real card the eMRTD
// plugin also claims and precedes both — the scripted double omits that
// applet, so front()==opensc would only hold as an artifact of the
// incomplete double.)
TEST(OpenscRouting, OpenscOutranksPkcs15ForSecondGenContactless)
{
    LibreSCRS::Plugin::CardPluginService registry{std::filesystem::path(PLUGIN_DIR)};
    ASSERT_TRUE(registry.isUsable());

    ScriptedContactlessCard card("RoutingReaderGen2");
    card.channel->transmitHandler = [](const APDUCommand& cmd) {
        return isSelectPkcs15Aid(cmd) ? sw(0x90, 0x00) : sw(0x6A, 0x82);
    };

    const auto candidates = registry.findAllCandidates(kTestAtr, *card.session);
    const auto ids = candidateIds(candidates);

    const auto opensc = std::find(ids.begin(), ids.end(), "opensc");
    const auto pkcs15 = std::find(ids.begin(), ids.end(), "pkcs15");
    ASSERT_NE(opensc, ids.end()) << "opensc plugin did not claim the scripted card";
    ASSERT_NE(pkcs15, ids.end()) << "pkcs15 plugin did not claim the scripted card";
    EXPECT_LT(opensc - ids.begin(), pkcs15 - ids.begin());
}

// A PACE-gated card of the RELATED family under a live SM tunnel: the
// wrapped PKCS#15 SELECT answers 6982, so the opensc plugin's deferred
// gates decline (today at the driver-presence gate; with the driver merged,
// at the EF.DIR discriminator), and the generic pkcs15 plugin's own live-SM
// probe declines the same answer. Nobody new claims the card away from the
// display-flow owner. (On the RAW contactless walk the pkcs15 plugin DOES
// claim it via its needs-PACE probe — that half is a hardware test.)
TEST(OpenscRouting, RelatedFamilyContactlessUnderLiveSmClaimsNoPkcs15Consumer)
{
    LibreSCRS::Plugin::CardPluginService registry{std::filesystem::path(PLUGIN_DIR)};
    ASSERT_TRUE(registry.isUsable());

    ScriptedContactlessCard card("RoutingReaderRelated");
    card.channel->transmitHandler = [](const APDUCommand& cmd) {
        return isSelectPkcs15Aid(cmd) ? sw(0x69, 0x82) : sw(0x6A, 0x82);
    };

    const auto candidates = registry.findAllCandidates(kTestAtr, *card.session);
    const auto ids = candidateIds(candidates);

    EXPECT_EQ(std::find(ids.begin(), ids.end(), "opensc"), ids.end());
    EXPECT_EQ(std::find(ids.begin(), ids.end(), "pkcs15"), ids.end());
}
