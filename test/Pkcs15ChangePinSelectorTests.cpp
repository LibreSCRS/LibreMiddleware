// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

// pkcs15-plugin changePIN selector correctness, driven end-to-end (plugin
// .so via the registry, real PKCS15Card parser path) against a scripted
// PKCS#15 card behind the PCSCConnection transmit filter on a detached
// CardSession — no hardware, no PC/SC (the Pkcs15PinLifecycleTests
// harness). The scripted card additionally answers CHANGE REFERENCE DATA
// (INS 0x24) so the default-PIN regression guard can observe the mutation
// reaching the wire. Every APDU is recorded BY VALUE — assertions scan
// value snapshots only and never hold pointers into the filter's state
// across transmits.
//
// Contract under test: a NON-EMPTY selector that matches no AODF object
// must be refused as PluginError with ZERO card mutation — resolving the
// selector requires reading the profile (read-only SELECT / READ BINARY),
// but no mutating or consuming APDU may reach the wire. An EMPTY selector
// keeps the legacy default-PIN fallback.

#include <LibreSCRS/CancelToken.h>
#include <LibreSCRS/Plugin/CardPlugin.h>
#include <LibreSCRS/Plugin/CardPluginService.h>
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
#include <ios>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace {

using LibreSCRS::Plugin::CardPlugin;
using LibreSCRS::Plugin::CardPluginService;
using LibreSCRS::Plugin::PINResultOutcome;
using LibreSCRS::SecureChannel::PlainChannel;
using LibreSCRS::SmartCard::AppletAid;
using LibreSCRS::SmartCard::CardSession;
using LibreSCRS::SmartCard::detail::ChannelInjector;
using LibreSCRS::SmartCard::detail::makeDetachedCardSession;
using LibreSCRS::SmartCard::Internal::APDUCommand;
using LibreSCRS::SmartCard::Internal::APDUResponse;

// PKCS#15 application AID (A0 00 00 00 63 "PKCS-15") — the AID the plugin
// activates its channel for.
AppletAid pkcs15Aid()
{
    return AppletAid{0xA0, 0x00, 0x00, 0x00, 0x63, 0x50, 0x4B, 0x43, 0x53, 0x2D, 0x31, 0x35};
}

// ---------------------------------------------------------------------------
// Scripted PKCS#15 card (the transmit-funnel test double).
// ---------------------------------------------------------------------------

struct ScriptedPkcs15Card
{
    /// EF contents by FID (ODF / TokenInfo / AODF ...).
    std::map<std::uint16_t, std::vector<std::uint8_t>> files;
    /// FIDs that select OK but have no readable content (DFs on the path).
    std::vector<std::uint16_t> selectableDfs{0x3F00};
    /// Every APDU seen, copied by value (snapshot — the UAF-safe form).
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

        if (cmd.ins == 0x24) // CHANGE REFERENCE DATA — accepted as scripted
            return {{}, 0x90, 0x00};

        return {{}, 0x6D, 0x00}; // anything else: instruction not supported
    }
};

bool isChangeReferenceData(const APDUCommand& cmd)
{
    return cmd.ins == 0x24;
}

/// Read-only whitelist: SELECT and READ BINARY are the only APDUs a
/// refused changePIN may legitimately emit (profile resolution).
bool isReadOnlyApdu(const APDUCommand& cmd)
{
    return cmd.ins == 0xA4 || cmd.ins == 0xB0;
}

// ---------------------------------------------------------------------------
// Fixture files.
// ---------------------------------------------------------------------------

// EF.ODF with a single authObjects entry pointing at FID 4408.
std::vector<std::uint8_t> odfPointingAtAodf()
{
    return {0xA8, 0x06, 0x30, 0x04, 0x04, 0x02, 0x44, 0x08};
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

// Synthetic AODF of an unseen PKCS#15 card: ONE plain PIN ("PIN", ref 0x01,
// initialized, 4/4/8, path 3F00) with no soPin / unblocking / PACE marks.
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

// ---------------------------------------------------------------------------
// Harness.
// ---------------------------------------------------------------------------

struct FakeCardRig
{
    std::shared_ptr<CardSession> session;
    std::shared_ptr<ScriptedPkcs15Card> card;
};

FakeCardRig makeRigWithAodf(const char* readerName, std::vector<std::uint8_t> aodf)
{
    FakeCardRig rig;
    rig.session = makeDetachedCardSession(readerName);
    rig.card = std::make_shared<ScriptedPkcs15Card>();
    rig.card->files = {
        {0x5031, odfPointingAtAodf()}, {0x5032, tokenInfoWithLabel("PKI Token")}, {0x4408, std::move(aodf)}};

    auto& conn = LibreSCRS::SmartCard::detail::unwrap(*rig.session);
    conn.setTransmitFilter([card = rig.card](const APDUCommand& cmd) { return (*card)(cmd); });

    // Pre-install a PlainChannel bound to the PKCS#15 AID so the plugin's
    // activateChannelFor takes the injected-channel fast path (the
    // detached session cannot run a real SELECT-based activation).
    ChannelInjector::installForTesting(*rig.session, std::make_unique<PlainChannel>(conn, pkcs15Aid()));
    return rig;
}

// Generic PKCS#15 card with the single plain "PIN" object (ref 0x01) —
// the default-PIN fallback target.
FakeCardRig makeRig(const char* readerName)
{
    return makeRigWithAodf(readerName, plainPinAodf());
}

// The plain "PIN" object (ref 0x01) followed by a second auth object
// whose CommonObjectAttributes carries NO label (ref 0x05).
std::vector<std::uint8_t> emptyLabelSecondPinAodf()
{
    auto out = plainPinAodf();
    const std::vector<std::uint8_t> second = {0x30, 0x24, // SEQUENCE (36)
                                              0x30, 0x00, //   CommonObjectAttributes: empty (no label)
                                              0x30, 0x03, 0x04, 0x01, 0x05, //   CommonAuthObjectAttributes: id 05
                                              0xA1, 0x1B, 0x30, 0x19,       //   [1] { PinAttributes
                                              0x03, 0x02, 0x00, 0x08,       //     pinFlags 0x08 (initialized)
                                              0x0A, 0x01, 0x01,             //     pinType ascii
                                              0x02, 0x01, 0x04,             //     minLength 4
                                              0x02, 0x01, 0x04,             //     storedLength 4
                                              0x02, 0x01, 0x08,             //     maxLength 8
                                              0x80, 0x01, 0x05,             //     pinReference 0x05
                                              0x30, 0x04, 0x04, 0x02, 0x3F, 0x00}; //     path 3F00 }
    out.insert(out.end(), second.begin(), second.end());
    return out;
}

// A bare-numeric-label PIN ("4", reference 0x07) plus an EMPTY-label PIN
// (reference 0x04): the advertised "pin_4" selector must resolve by
// REFERENCE (0x04), never via the legacy suffix-label form to the record
// whose label happens to be the digit "4".
std::vector<std::uint8_t> numericLabelCollisionAodf()
{
    std::vector<std::uint8_t> out = {0x30, 0x27,                          // SEQUENCE (39)
                                     0x30, 0x03, 0x0C, 0x01, 0x34,        //   CommonObjectAttributes label "4"
                                     0x30, 0x03, 0x04, 0x01, 0x02,        //   CommonAuthObjectAttributes: id 02
                                     0xA1, 0x1B, 0x30, 0x19,              //   [1] { PinAttributes
                                     0x03, 0x02, 0x00, 0x08,              //     pinFlags 0x08 (initialized)
                                     0x0A, 0x01, 0x01,                    //     pinType ascii
                                     0x02, 0x01, 0x04,                    //     minLength 4
                                     0x02, 0x01, 0x04,                    //     storedLength 4
                                     0x02, 0x01, 0x08,                    //     maxLength 8
                                     0x80, 0x01, 0x07,                    //     pinReference 0x07
                                     0x30, 0x04, 0x04, 0x02, 0x3F, 0x00}; //     path 3F00 }
    const std::vector<std::uint8_t> emptyLabelRef4 = {
        0x30, 0x24,                                           // SEQUENCE (36)
        0x30, 0x00,                                           //   CommonObjectAttributes: empty
        0x30, 0x03, 0x04, 0x01, 0x03,                         //   CommonAuthObjectAttributes: id 03
        0xA1, 0x1B, 0x30, 0x19,                               //   [1] { PinAttributes
        0x03, 0x02, 0x00, 0x08, 0x0A, 0x01, 0x01,             //     initialized, ascii
        0x02, 0x01, 0x04, 0x02, 0x01, 0x04, 0x02, 0x01, 0x08, //     4/4/8
        0x80, 0x01, 0x04,                                     //     pinReference 0x04
        0x30, 0x04, 0x04, 0x02, 0x3F, 0x00};                  //     path 3F00 }
    out.insert(out.end(), emptyLabelRef4.begin(), emptyLabelRef4.end());
    return out;
}

std::shared_ptr<CardPlugin> loadPkcs15Plugin(CardPluginService& registry)
{
    for (const auto& p : registry.plugins()) {
        if (p->pluginId() == "pkcs15")
            return p;
    }
    return nullptr;
}

} // namespace

// ---------------------------------------------------------------------------
// A non-empty selector that matches no AODF object is a refusal, not a
// fallback: PluginError with retriesLeft unset, not blocked, and no
// mutating APDU on the wire (silently changing a different credential on
// a multi-PIN card is never acceptable).
// ---------------------------------------------------------------------------

TEST(Pkcs15ChangePinSelector, UnknownSelectorRefusesWithoutMutatingApdu)
{
    CardPluginService registry{std::filesystem::path(PLUGIN_DIR)};
    auto plugin = loadPkcs15Plugin(registry);
    ASSERT_NE(plugin, nullptr);

    auto rig = makeRig("Pkcs15 ChangePin Selector Reader 0");
    const LibreSCRS::Secure::String oldPin{"1234"};
    const LibreSCRS::Secure::String newPin{"5678"};
    const auto result = plugin->changePIN(*rig.session, "no-such-pin", oldPin, newPin);

    EXPECT_EQ(result.outcome, PINResultOutcome::PluginError);
    EXPECT_EQ(result.retriesLeft, std::nullopt);
    EXPECT_FALSE(result.blocked);

    // Zero card mutation: only the read-only profile resolution may have
    // reached the wire — no CHANGE REFERENCE DATA, no VERIFY of any form.
    for (const auto& cmd : rig.card->log)
        EXPECT_TRUE(isReadOnlyApdu(cmd)) << "non-read-only APDU reached the card: ins=0x" << std::hex
                                         << static_cast<int>(cmd.ins);
    EXPECT_TRUE(std::none_of(rig.card->log.begin(), rig.card->log.end(), isChangeReferenceData));
}

// ---------------------------------------------------------------------------
// Regression guard for the legacy host path: an EMPTY selector keeps
// today's default-PIN fallback — the change goes to the resolved User PIN
// (reference 0x01) and the card's acceptance is reported as Ok.
// ---------------------------------------------------------------------------

TEST(Pkcs15ChangePinSelector, EmptySelectorKeepsDefaultPinBehaviour)
{
    CardPluginService registry{std::filesystem::path(PLUGIN_DIR)};
    auto plugin = loadPkcs15Plugin(registry);
    ASSERT_NE(plugin, nullptr);

    auto rig = makeRig("Pkcs15 ChangePin Selector Reader 1");
    const LibreSCRS::Secure::String oldPin{"1234"};
    const LibreSCRS::Secure::String newPin{"5678"};
    const auto result = plugin->changePIN(*rig.session, "", oldPin, newPin);

    EXPECT_EQ(result.outcome, PINResultOutcome::Ok);
    EXPECT_FALSE(result.blocked);

    // Exactly one CHANGE REFERENCE DATA, addressed to the default User
    // PIN's reference, carrying old+new at the AODF stored length (4+4).
    std::vector<APDUCommand> changes;
    std::copy_if(rig.card->log.begin(), rig.card->log.end(), std::back_inserter(changes), isChangeReferenceData);
    ASSERT_EQ(changes.size(), 1u);
    EXPECT_EQ(changes[0].p2, 0x01);
    EXPECT_EQ(changes[0].data.size(), 8u);
}

// ---------------------------------------------------------------------------
// An empty-label record must never alias the legacy default-PIN fallback:
// getPINList advertises it as "pin_<reference>", and addressing THAT
// selector mutates exactly the empty-label record's reference — while the
// EMPTY selector still addresses the default User PIN. A mix-up here
// would burn the retry counter of a credential the host never addressed.
// ---------------------------------------------------------------------------

// The reference form of the synthesized selector outranks the legacy
// suffix-label form: on a card carrying BOTH a PIN labeled "4" (ref 0x07)
// and an empty-label PIN with reference 0x04, "pin_4" is the empty-label
// record's ADVERTISED selector and must mutate reference 0x04 — hitting
// the "4"-labeled record would burn a retry counter the host never
// addressed.
TEST(Pkcs15ChangePinSelector, ReferenceFormOutranksNumericSuffixLabel)
{
    CardPluginService registry{std::filesystem::path(PLUGIN_DIR)};
    auto plugin = loadPkcs15Plugin(registry);
    ASSERT_NE(plugin, nullptr);

    auto rig = makeRigWithAodf("Pkcs15 ChangePin NumericLabel Reader 0", numericLabelCollisionAodf());
    const LibreSCRS::Secure::String oldPin{"1234"};
    const LibreSCRS::Secure::String newPin{"5678"};
    const auto result = plugin->changePIN(*rig.session, "pin_4", oldPin, newPin);
    EXPECT_EQ(result.outcome, PINResultOutcome::Ok);

    std::vector<APDUCommand> changes;
    std::copy_if(rig.card->log.begin(), rig.card->log.end(), std::back_inserter(changes), isChangeReferenceData);
    ASSERT_EQ(changes.size(), 1u);
    EXPECT_EQ(changes[0].p2, 0x04) << "pin_4 must resolve by reference, not to the record labeled \"4\"";
}

TEST(Pkcs15ChangePinSelector, ReferenceSelectorTargetsEmptyLabelRecord)
{
    CardPluginService registry{std::filesystem::path(PLUGIN_DIR)};
    auto plugin = loadPkcs15Plugin(registry);
    ASSERT_NE(plugin, nullptr);

    const LibreSCRS::Secure::String oldPin{"1234"};
    const LibreSCRS::Secure::String newPin{"5678"};

    {
        // Addressed mutation: the advertised "pin_5" selector reaches the
        // empty-label record (reference 0x05), not the default User PIN.
        auto rig = makeRigWithAodf("Pkcs15 ChangePin EmptyLabel Reader 0", emptyLabelSecondPinAodf());
        const auto result = plugin->changePIN(*rig.session, "pin_5", oldPin, newPin);
        EXPECT_EQ(result.outcome, PINResultOutcome::Ok);

        std::vector<APDUCommand> changes;
        std::copy_if(rig.card->log.begin(), rig.card->log.end(), std::back_inserter(changes), isChangeReferenceData);
        ASSERT_EQ(changes.size(), 1u);
        EXPECT_EQ(changes[0].p2, 0x05);
    }
    {
        // Legacy fallback intact: the EMPTY selector still addresses the
        // default User PIN (reference 0x01) on the same card shape.
        auto rig = makeRigWithAodf("Pkcs15 ChangePin EmptyLabel Reader 1", emptyLabelSecondPinAodf());
        const auto result = plugin->changePIN(*rig.session, "", oldPin, newPin);
        EXPECT_EQ(result.outcome, PINResultOutcome::Ok);

        std::vector<APDUCommand> changes;
        std::copy_if(rig.card->log.begin(), rig.card->log.end(), std::back_inserter(changes), isChangeReferenceData);
        ASSERT_EQ(changes.size(), 1u);
        EXPECT_EQ(changes[0].p2, 0x01);
    }
}
