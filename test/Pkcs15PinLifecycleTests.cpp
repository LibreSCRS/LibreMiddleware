// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

// pkcs15-plugin getPINList lifecycle classification + probeSafe gating,
// driven end-to-end (plugin .so via the registry, real PKCS15Card parser
// path) against a scripted PKCS#15 card behind the PCSCConnection
// transmit filter on a detached CardSession — no hardware, no PC/SC.
//
// The scripted card serves SELECT AID / SELECT FID / READ BINARY from a
// FID→bytes map and answers empty-VERIFY retry-counter probes from a
// per-reference script. Every APDU is recorded BY VALUE — assertions
// scan value snapshots only and never hold pointers into the filter's
// state across transmits.
//
// Non-consumption invariant: getPINList must never send a real VERIFY
// (INS 0x20 with data); the only permitted INS 0x20 form is the empty
// status probe, and only on probeSafe families.

#include "fixtures/appletsuitegen1_aodf_20260718.h"
#include "fixtures/appletsuitegen1_docp_20260721.h"

#include <LibreSCRS/CancelToken.h>
#include <LibreSCRS/Plugin/CardPlugin.h>
#include <LibreSCRS/Plugin/CardPluginService.h>
#include <LibreSCRS/Plugin/PinStatusEntry.h>
#include <LibreSCRS/SmartCard/AppletAid.h>
#include <LibreSCRS/SmartCard/CardSession.h>
#include <LibreSCRS/SmartCard/detail/CardSessionInjection.h>
#include <LibreSCRS/SmartCard/detail/ChannelInjection.h>
#include <LibreSCRS/SmartCard/detail/Unwrap.h>
#include <LibreSCRS_internal/SecureChannel/PlainChannel.h>

#include "fake_pcsc_connection.h"
#include "pkcs15_card.h"

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
#include <string>
#include <string_view>
#include <vector>

namespace {

using LibreSCRS::Plugin::CardPlugin;
using LibreSCRS::Plugin::CardPluginService;
using LibreSCRS::Plugin::PinKind;
using LibreSCRS::Plugin::PinState;
using LibreSCRS::SecureChannel::PlainChannel;
using LibreSCRS::SecureChannel::TestSupport::FakePCSCConnection;
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
    std::vector<std::uint16_t> selectableDfs{0x3F00, 0x0DF5};
    /// Empty-VERIFY probe answers: PIN reference → remaining tries
    /// (answered as SW 63 Cx). References absent here answer 6A88.
    std::map<std::uint8_t, int> probeTries;
    /// GET DATA (ODD) DOCP answers: ORF (pinReference & 0x1F) → the raw
    /// DOCP TLV payload, returned with SW 9000. ORFs absent here answer
    /// 6A88 (readCounters sees a non-success SW and returns all-absent).
    std::map<std::uint8_t, std::vector<std::uint8_t>> docpByOrf;
    /// CHANGE REFERENCE DATA (INS 0x24) acceptance: the ONE P1 this double
    /// accepts (returns SW 9000 for); absent (the default) or any other P1
    /// answers 6A86 — the same "independently models acceptance, rejects
    /// wrong P1" anti-tautology technique as Pkcs15ResetRetryCounter's
    /// scripted doubles, applied at the plugin-funnel level.
    std::optional<std::uint8_t> acceptedChangeRefP1;
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

        if (cmd.ins == 0x20 && cmd.data.empty()) { // empty-VERIFY retry-counter probe
            const auto it = probeTries.find(cmd.p2);
            if (it == probeTries.end())
                return {{}, 0x6A, 0x88};
            return {{}, 0x63, static_cast<std::uint8_t>(0xC0 | (it->second & 0x0F))};
        }

        if (cmd.ins == 0x24) { // CHANGE REFERENCE DATA
            if (!acceptedChangeRefP1.has_value() || cmd.p1 != *acceptedChangeRefP1)
                return {{}, 0x6A, 0x86};
            return {{}, 0x90, 0x00};
        }

        if (cmd.ins == 0xCB && cmd.p1 == 0x3F && cmd.p2 == 0xFF) { // GET DATA (ODD) — DOCP
            // Wire shape (apdu.cpp getDataDocp): data = 4D 08 70 06 BF 80 <orf> 02 62 80.
            if (cmd.data.size() < 7)
                return {{}, 0x6A, 0x88};
            const auto orf = cmd.data[6];
            const auto it = docpByOrf.find(orf);
            if (it == docpByOrf.end())
                return {{}, 0x6A, 0x88};
            return {it->second, 0x90, 0x00};
        }

        return {{}, 0x6D, 0x00}; // anything else: instruction not supported
    }
};

bool isEmptyVerifyProbe(const APDUCommand& cmd)
{
    return cmd.ins == 0x20 && cmd.data.empty();
}

bool isRealVerify(const APDUCommand& cmd)
{
    return cmd.ins == 0x20 && !cmd.data.empty();
}

bool isResetRetryCounterCmd(const APDUCommand& cmd)
{
    return cmd.ins == 0x2C; // ISO RESET RETRY COUNTER
}

bool isChangeReferenceDataCmd(const APDUCommand& cmd)
{
    return cmd.ins == 0x24; // ISO CHANGE REFERENCE DATA
}

bool isActivateCmd(const APDUCommand& cmd)
{
    return cmd.ins == 0x44; // ISO ACTIVATE
}

// SELECT BY FID for the AODF (0x4408, per odfPointingAtAodf() below) —
// reaching the wire proves a call actually engaged card.readProfile(),
// distinguishing "the override ran its full evidence-scan/derivation logic
// and correctly found no keyActivatable candidate" from "the call never
// reached the override at all" (the base CardPlugin::activateSigningKey
// default touches the session/channel not at all, so it could never
// produce this SELECT either) — needed because both paths otherwise report
// the SAME PINResultOutcome::Unsupported.
bool isSelectAodfFid(const APDUCommand& cmd)
{
    return cmd.ins == 0xA4 && cmd.p1 == 0x00 && cmd.data.size() == 2 && cmd.data[0] == 0x44 && cmd.data[1] == 0x08;
}

bool logHasProbeFor(const std::vector<APDUCommand>& log, std::uint8_t ref)
{
    return std::any_of(log.begin(), log.end(),
                       [ref](const APDUCommand& c) { return isEmptyVerifyProbe(c) && c.p2 == ref; });
}

// Kind-lookup helper. On a AppletSuiteGen1 (usesPace) card the CAN classifies as
// PinKind::Can on any interface, so Can is unique per AppletSuiteGen1 entry set.
// Callers needing a specific object by label should use findByLabel. On a
// miss, records a non-fatal failure and returns a default-constructed
// sentinel entry rather than dereferencing end().
const LibreSCRS::Plugin::PinStatusEntry& findByKind(const std::vector<LibreSCRS::Plugin::PinStatusEntry>& entries,
                                                    PinKind kind)
{
    static const LibreSCRS::Plugin::PinStatusEntry sentinel{};
    const auto it = std::find_if(entries.begin(), entries.end(), [kind](const auto& e) { return e.kind == kind; });
    EXPECT_NE(it, entries.end()) << "no entry with the requested PinKind";
    return it == entries.end() ? sentinel : *it;
}

const LibreSCRS::Plugin::PinStatusEntry& findByLabel(const std::vector<LibreSCRS::Plugin::PinStatusEntry>& entries,
                                                     std::string_view label)
{
    static const LibreSCRS::Plugin::PinStatusEntry sentinel{};
    const auto it = std::find_if(entries.begin(), entries.end(), [label](const auto& e) { return e.label == label; });
    EXPECT_NE(it, entries.end()) << "no entry with the requested label";
    return it == entries.end() ? sentinel : *it;
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

// Synthetic AODF: one fixed service PIN ("SVC", ref 0x03) marked BOTH
// change-disabled and unblock-disabled — the flag shape a CAN also has,
// but on a plain card with no PACE evidence.
std::vector<std::uint8_t> serviceDisabledPinAodf()
{
    return {0x30, 0x29,                               // SEQUENCE (41)
            0x30, 0x05, 0x0C, 0x03, 0x53, 0x56, 0x43, //   CommonObjectAttributes "SVC"
            0x30, 0x03, 0x04, 0x01, 0x03,             //   CommonAuthObjectAttributes: id 03
            0xA1, 0x1B, 0x30, 0x19,                   //   [1] { PinAttributes
            0x03, 0x02, 0x00, 0x38,                   //     pinFlags: change-disabled,
                                                      //     unblock-disabled, initialized
            0x0A, 0x01, 0x01,                         //     pinType ascii
            0x02, 0x01, 0x04,                         //     minLength 4
            0x02, 0x01, 0x04,                         //     storedLength 4
            0x02, 0x01, 0x08,                         //     maxLength 8
            0x80, 0x01, 0x03,                         //     pinReference 0x03
            0x30, 0x04, 0x04, 0x02, 0x3F, 0x00};      //     path 3F00 }
}

// Synthetic AODF: the plain "PIN" (ref 0x01) followed by a second auth
// object whose CommonObjectAttributes carries NO label (ref 0x05).
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

// Synthetic AODF: ONE SIGN PIN ("Sign PIN", ref 0x92) local + in the
// signature DF (path 3F00/0DF5, matching kAppletSuiteGen1SignatureDf), with
// pinFlags 0x40 (local bit set, initialized bit CLEAR) — a transport-state
// credential, unlike the hardware-captured AppletSuiteGen1 fixture's
// Signature PIN (pinFlags 0x48: local + initialized, i.e. already
// personalized). Paired with the "SSCDv1 PACE MD" token label this
// resolves FamilyId::AppletSuiteGen1 (supportsTransportPin=true), so
// derivePinStatus classifies kind=SignPin, state=Transport,
// activatable=true — the plugin-level activateTransportPin "success" path.
std::vector<std::uint8_t> transportSignPinAodf()
{
    return {0x30, 0x30,                                      // SEQUENCE (48)
            0x30, 0x0A, 0x0C, 0x08, 0x53, 0x69, 0x67, 0x6E,  //   CommonObjectAttributes
            0x20, 0x50, 0x49, 0x4E,                          //     UTF8String "Sign PIN"
            0x30, 0x03, 0x04, 0x01, 0x92,                    //   CommonAuthObjectAttributes: id 92
            0xA1, 0x1D, 0x30, 0x1B,                          //   [1] { PinAttributes
            0x03, 0x02, 0x00, 0x40,                          //     pinFlags 0x40 (local, NOT initialized)
            0x0A, 0x01, 0x01,                                //     pinType ascii
            0x02, 0x01, 0x04,                                //     minLength 4
            0x02, 0x01, 0x04,                                //     storedLength 4
            0x02, 0x01, 0x08,                                //     maxLength 8
            0x80, 0x01, 0x92,                                //     pinReference 0x92
            0x30, 0x06, 0x04, 0x04, 0x3F, 0x00, 0x0D, 0xF5}; //     path 3F00/0DF5 }
}

// ---------------------------------------------------------------------------
// Harness.
// ---------------------------------------------------------------------------

struct FakeCardRig
{
    std::shared_ptr<CardSession> session;
    std::shared_ptr<ScriptedPkcs15Card> card;
};

FakeCardRig makeRig(const char* readerName, std::map<std::uint16_t, std::vector<std::uint8_t>> files,
                    std::map<std::uint8_t, int> probeTries)
{
    FakeCardRig rig;
    rig.session = makeDetachedCardSession(readerName);
    rig.card = std::make_shared<ScriptedPkcs15Card>();
    rig.card->files = std::move(files);
    rig.card->probeTries = std::move(probeTries);

    auto& conn = LibreSCRS::SmartCard::detail::unwrap(*rig.session);
    conn.setTransmitFilter([card = rig.card](const APDUCommand& cmd) { return (*card)(cmd); });

    // Pre-install a PlainChannel bound to the PKCS#15 AID so the plugin's
    // activateChannelFor takes the injected-channel fast path (the
    // detached session cannot run a real SELECT-based activation).
    ChannelInjector::installForTesting(*rig.session, std::make_unique<PlainChannel>(conn, pkcs15Aid()));
    return rig;
}

// AppletSuiteGen1 scripted card: hardware-scanned AODF (kAppletSuiteGen1Aodf20260718) behind
// the hardware-captured EF.TokenInfo label "SSCDv1 PACE MD" (contact scan
// 2026-07-20, production readProfile path) — resolveFamilyId classifies it
// FamilyId::AppletSuiteGen1, opening the probe gate (probeSafe family
// row), so the probe script (User PIN 3, Signature PIN 3, PUK 5) supplies
// the counters. The CAN reference is deliberately absent from the script (a
// non-VERIFY-able object — the real card answers 6A88).
FakeCardRig makeAppletSuiteGen1Rig(const char* readerName)
{
    const auto& aodf = LibreSCRS::test::fixtures::kAppletSuiteGen1Aodf20260718;
    return makeRig(readerName,
                   {{0x5031, odfPointingAtAodf()},
                    {0x5032, tokenInfoWithLabel("SSCDv1 PACE MD")},
                    {0x4408, {aodf.begin(), aodf.end()}}},
                   {{0x86, 3}, {0x92, 3}, {0x93, 5}});
}

// Same AppletSuiteGen1 rig, PLUS a scripted DOCP answer for the PUK (ORF 0x13, ref
// 0x93 & 0x1F) and the User PIN (ORF 0x06, ref 0x86 & 0x1F): readCounters
// now resolves retriesLeft (and, for the PUK, uses/unblocks) from the DOCP
// itself, so the empty-VERIFY fallback probe never reaches those two
// references. The Signature PIN (ORF 0x12) and CAN (ORF 0x02) have no
// DOCP entry and keep going through the empty-VERIFY probe, same as the
// plain AppletSuiteGen1 rig. Kept separate from makeAppletSuiteGen1Rig so the other
// AppletSuiteGen1 tests (which assert the empty-VERIFY probe reaches 0x86/0x93)
// are unaffected.
FakeCardRig makeAppletSuiteGen1RigWithDocp(const char* readerName)
{
    auto rig = makeAppletSuiteGen1Rig(readerName);
    const auto& pukDocp = LibreSCRS::test::fixtures::kAppletSuiteGen1PukDocp;
    const auto& userPinDocp = LibreSCRS::test::fixtures::kAppletSuiteGen1UserPinDocp;
    rig.card->docpByOrf = {{0x13, {pukDocp.begin(), pukDocp.end()}}, {0x06, {userPinDocp.begin(), userPinDocp.end()}}};
    return rig;
}

// Unseen generic PKCS#15 card: one plain PIN, no family row. The probe
// script would answer tries=3 — the gate must prevent it from ever being
// asked.
FakeCardRig makeUnknownRig(const char* readerName)
{
    return makeRig(readerName,
                   {{0x5031, odfPointingAtAodf()}, {0x5032, tokenInfoWithLabel("PKI Token")}, {0x4408, plainPinAodf()}},
                   {{0x01, 3}});
}

// AppletSuiteGen1 card with a single transport-state Signature PIN
// (transportSignPinAodf): same hardware-captured token label as
// makeAppletSuiteGen1Rig (resolves FamilyId::AppletSuiteGen1,
// supportsTransportPin=true), but the AODF itself is synthetic — a
// not-yet-initialized SIGN PIN, unlike the real hardware capture's
// already-personalized one. Used only by activateTransportPin's success
// tests; no probe script needed (activation never reads counters).
FakeCardRig makeAppletSuiteGen1TransportSignRig(const char* readerName)
{
    return makeRig(readerName,
                   {{0x5031, odfPointingAtAodf()},
                    {0x5032, tokenInfoWithLabel("SSCDv1 PACE MD")},
                    {0x4408, transportSignPinAodf()}},
                   {});
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
// AppletSuiteGen1 AODF + the hardware-captured token label → the plugin resolves
// FamilyId::AppletSuiteGen1 and entries combine card-asserted evidence
// (PUK via soPin + the unblock chain, Signature PIN via the family
// signature-DF marker) with the AppletSuiteGen1 family row: change advertised for
// User/Signature PIN, retriesMax from the row, counters from the
// (probe-safe) empty-VERIFY probe. Unblock stays un-advertised — the
// RESET RETRY COUNTER variant is not hardware-verified for this family.
// This rig models a PLAIN (contact) session, so the CAN record classifies
// conservatively (kind=Can requires session PACE evidence; the PACE-gated
// half of that rule is covered at the derivation level — a scripted plain
// card cannot complete a real PACE handshake).
// ---------------------------------------------------------------------------

TEST(Pkcs15PinLifecycle, AppletSuiteGen1AodfProducesClassifiedEntries)
{
    CardPluginService registry{std::filesystem::path(PLUGIN_DIR)};
    auto plugin = loadPkcs15Plugin(registry);
    ASSERT_NE(plugin, nullptr);

    auto rig = makeAppletSuiteGen1Rig("Pkcs15 Lifecycle AppletSuiteGen1 Reader 0");
    const auto entries = plugin->getPINList(*rig.session);
    ASSERT_EQ(entries.size(), 4u);

    // AODF order is preserved: CAN, User PIN, PUK, Signature PIN.
    const auto& can = entries[0];
    const auto& user = entries[1];
    const auto& puk = entries[2];
    const auto& sign = entries[3];

    // CAN record on a PLAIN session: recognised as Can via the family's
    // card-level PACE signal (usesPace) corroborated by the AODF's
    // change-disabled + unblock-disabled shape. The flags ALONE never
    // overclaim — a non-PACE family keeps a disabled service PIN as a PIN.
    // The CAN has no VERIFY-able reference, so its counter stays absent.
    EXPECT_EQ(can.label, "PACE CAN");
    EXPECT_EQ(can.reference, 0x02);
    EXPECT_EQ(can.kind, PinKind::Can);
    EXPECT_FALSE(can.canChange); // change-disabled AODF veto + Can is never changeable
    EXPECT_FALSE(can.unblockable);
    EXPECT_EQ(can.retriesLeft, std::nullopt); // not a VERIFY-able reference
    EXPECT_EQ(can.retriesMax, std::nullopt);  // Can borrows no retry ceiling from the user row
    EXPECT_FALSE(can.blocked);

    // User PIN: global user credential; the AppletSuiteGen1 row advertises change
    // and retriesMax=3, the open probe gate supplies retriesLeft. Unblock is
    // NOT advertised (RRC variant not hardware-verified) even though the
    // AODF chains it to the PUK.
    EXPECT_EQ(user.label, "User PIN");
    EXPECT_EQ(user.reference, 0x86);
    EXPECT_EQ(user.kind, PinKind::UserPin);
    EXPECT_EQ(user.state, PinState::Operational);
    EXPECT_TRUE(user.canChange);
    EXPECT_FALSE(user.unblockable);
    EXPECT_EQ(user.retriesLeft, std::optional<int>{3});
    EXPECT_EQ(user.retriesMax, std::optional<int>{3});
    EXPECT_FALSE(user.blocked);

    // Global PUK: soPin + unblock-disabled unblocking authority — a PUK,
    // NOT a user PIN; never changeable, never itself unblockable. The kind
    // is evidence-driven (soPin + unblock chain); the row supplies
    // retriesMax=5 and the probe answers 5.
    //
    // This rig has NO scripted DOCP (makeAppletSuiteGen1Rig, not *WithDocp): GET
    // DATA (ODD) answers 6A88, so readCounters comes back all-absent and
    // retriesLeft/retriesMax fall all the way back to the empty-VERIFY
    // probe (5) and the AppletSuiteGen1 quirk row (5) respectively — the graceful-
    // degradation path. usesLeft/usesMax/unblocksLeft have no fallback
    // source at all (derivePinStatus never sets them; only the post-
    // derivation DOCP merge in getPINList does) and MUST stay absent —
    // the regression guard against a DOCP-less card spuriously reporting
    // usage/unblock counters it never asserted.
    EXPECT_EQ(puk.label, "Global PUK");
    EXPECT_EQ(puk.reference, 0x93);
    EXPECT_EQ(puk.kind, PinKind::Puk);
    EXPECT_EQ(puk.state, PinState::Operational);
    EXPECT_FALSE(puk.canChange);
    EXPECT_FALSE(puk.unblockable);
    EXPECT_EQ(puk.retriesLeft, std::optional<int>{5}); // VERIFY fallback
    EXPECT_EQ(puk.retriesMax, std::optional<int>{5});  // quirk fallback
    EXPECT_FALSE(puk.usesLeft.has_value());
    EXPECT_FALSE(puk.usesMax.has_value());
    EXPECT_FALSE(puk.unblocksLeft.has_value());

    // Signature PIN: the resolved family activates the signature-DF marker
    // (path 3F00 0DF5), separating it from a user PIN; the row advertises
    // change and retriesMax=3.
    EXPECT_EQ(sign.label, "Signature PIN");
    EXPECT_EQ(sign.reference, 0x92);
    EXPECT_EQ(sign.kind, PinKind::SignPin);
    EXPECT_EQ(sign.state, PinState::Operational);
    EXPECT_TRUE(sign.canChange);
    EXPECT_EQ(sign.retriesLeft, std::optional<int>{3});
    EXPECT_EQ(sign.retriesMax, std::optional<int>{3});

    // Non-consumption: the empty-VERIFY status probe DOES reach the wire
    // (probe-safe family), but no real VERIFY ever leaves getPINList.
    EXPECT_TRUE(logHasProbeFor(rig.card->log, 0x86));
    EXPECT_TRUE(logHasProbeFor(rig.card->log, 0x92));
    EXPECT_TRUE(logHasProbeFor(rig.card->log, 0x93));
    EXPECT_TRUE(std::none_of(rig.card->log.begin(), rig.card->log.end(), isRealVerify));
}

// ---------------------------------------------------------------------------
// A change-disabled + unblock-disabled auth object on a card whose family is
// Unknown (token label resolves to no quirk row) must NOT be promoted to Can —
// the flags shape alone never overclaims. This is the "fixed service PIN on a
// non-PACE card stays a PIN" guard the usesPace/paceGated OR-form must honour.
// ---------------------------------------------------------------------------

TEST(Pkcs15PinLifecycle, DisabledServicePinOnNonPaceCardStaysUserPin)
{
    CardPluginService registry{std::filesystem::path(PLUGIN_DIR)};
    auto plugin = loadPkcs15Plugin(registry);
    ASSERT_NE(plugin, nullptr);

    // "PKI Token" resolves to FamilyId::Unknown (no quirk row -> usesPace
    // unavailable); the plain session means paceGated is false too.
    auto rig = makeRig(
        "Pkcs15 Lifecycle NonPace Reader 0",
        {{0x5031, odfPointingAtAodf()}, {0x5032, tokenInfoWithLabel("PKI Token")}, {0x4408, serviceDisabledPinAodf()}},
        {{0x03, 3}});
    const auto entries = plugin->getPINList(*rig.session);
    ASSERT_EQ(entries.size(), 1u);
    EXPECT_EQ(entries[0].reference, 0x03);
    EXPECT_EQ(entries[0].kind, PinKind::UserPin); // NOT Can
    EXPECT_FALSE(entries[0].canChange);           // change-disabled veto
}

// ---------------------------------------------------------------------------
// Unseen PKCS#15 card → conservative entries: evidence-only kind, no
// counters, no probe, nothing advertised.
// ---------------------------------------------------------------------------

TEST(Pkcs15PinLifecycle, UnknownCardEntriesStayConservative)
{
    CardPluginService registry{std::filesystem::path(PLUGIN_DIR)};
    auto plugin = loadPkcs15Plugin(registry);
    ASSERT_NE(plugin, nullptr);

    auto rig = makeUnknownRig("Pkcs15 Lifecycle Unknown Reader 0");
    const auto entries = plugin->getPINList(*rig.session);
    ASSERT_EQ(entries.size(), 1u);

    const auto& pin = entries[0];
    EXPECT_EQ(pin.label, "PIN");
    EXPECT_EQ(pin.reference, 0x01);
    // Plain initialized PIN with a non-zero reference and no auxiliary
    // flags classifies as a user PIN on card-asserted evidence alone.
    EXPECT_EQ(pin.kind, PinKind::UserPin);
    EXPECT_EQ(pin.state, PinState::Operational);
    EXPECT_FALSE(pin.probeSafe);
    EXPECT_EQ(pin.retriesLeft, std::nullopt);
    EXPECT_EQ(pin.retriesMax, std::nullopt);
    EXPECT_FALSE(pin.unblockable);
    EXPECT_FALSE(pin.blocked);
    // Quirkless families keep the evidence-only change advertisement
    // (non-PUK, non-SO, no change-disabled veto) — the shape this plugin
    // shipped before the derivation engine.
    EXPECT_TRUE(pin.canChange);

    // No family row → the retry-counter probe must never have been sent.
    EXPECT_TRUE(std::none_of(rig.card->log.begin(), rig.card->log.end(), isEmptyVerifyProbe));
    EXPECT_TRUE(std::none_of(rig.card->log.begin(), rig.card->log.end(), isRealVerify));
}

// ---------------------------------------------------------------------------
// The tries-left probe is gated on family probe-safety: a card without a
// resolved family (probeSafe unavailable) sends NO empty-VERIFY APDU and
// retriesLeft stays unset, no matter how willing the card's script is. The
// gate-OPEN half runs against the AppletSuiteGen1 rig, whose captured label resolves
// a probe-safe family row: the counters flow through, and an arbitrary
// unrecognized label on the SAME card shape must still keep the gate shut
// (guards against a regression that re-introduces an unverified matcher).
// ---------------------------------------------------------------------------

TEST(Pkcs15PinLifecycle, TriesLeftProbeGatedByProbeSafe)
{
    CardPluginService registry{std::filesystem::path(PLUGIN_DIR)};
    auto plugin = loadPkcs15Plugin(registry);
    ASSERT_NE(plugin, nullptr);

    {
        // Generic card, no family row: the scripted card WOULD answer the
        // probe with 63 C3, but the gate must keep the probe off the wire.
        auto rig = makeUnknownRig("Pkcs15 Lifecycle Gate Reader 0");
        const auto entries = plugin->getPINList(*rig.session);
        ASSERT_EQ(entries.size(), 1u);
        EXPECT_EQ(entries[0].retriesLeft, std::nullopt);
        EXPECT_TRUE(std::none_of(rig.card->log.begin(), rig.card->log.end(), isEmptyVerifyProbe));
    }
    {
        // AppletSuiteGen1 card, captured label → probe-safe family row → gate OPEN:
        // per-reference probes leave getPINList and the counters land.
        auto rig = makeAppletSuiteGen1Rig("Pkcs15 Lifecycle Gate Reader 1");
        const auto entries = plugin->getPINList(*rig.session);
        ASSERT_EQ(entries.size(), 4u);
        EXPECT_TRUE(logHasProbeFor(rig.card->log, 0x86));
        EXPECT_TRUE(logHasProbeFor(rig.card->log, 0x92));
        EXPECT_TRUE(logHasProbeFor(rig.card->log, 0x93));
        EXPECT_EQ(entries[1].retriesLeft, std::optional<int>{3});
        EXPECT_EQ(entries[2].retriesLeft, std::optional<int>{5});
        EXPECT_EQ(entries[3].retriesLeft, std::optional<int>{3});
        EXPECT_TRUE(std::none_of(rig.card->log.begin(), rig.card->log.end(), isRealVerify));
    }
}

// ---------------------------------------------------------------------------
// A fixed service PIN (change-disabled + unblock-disabled) on a card with
// NO session PACE evidence keeps its PIN classification: the disabled
// flags are only CORROBORATION for the Can kind, never sufficient alone.
// ---------------------------------------------------------------------------

TEST(Pkcs15PinLifecycle, DisabledFlagsAloneDoNotMakeACan)
{
    CardPluginService registry{std::filesystem::path(PLUGIN_DIR)};
    auto plugin = loadPkcs15Plugin(registry);
    ASSERT_NE(plugin, nullptr);

    auto rig = makeRig(
        "Pkcs15 Lifecycle ServicePin Reader 0",
        {{0x5031, odfPointingAtAodf()}, {0x5032, tokenInfoWithLabel("PKI Token")}, {0x4408, serviceDisabledPinAodf()}},
        {});
    const auto entries = plugin->getPINList(*rig.session);
    ASSERT_EQ(entries.size(), 1u);

    const auto& svc = entries[0];
    EXPECT_EQ(svc.label, "SVC");
    EXPECT_EQ(svc.reference, 0x03);
    EXPECT_EQ(svc.kind, PinKind::UserPin);
    EXPECT_FALSE(svc.canChange); // change-disabled AODF veto
    EXPECT_FALSE(svc.unblockable);
}

// ---------------------------------------------------------------------------
// An empty AODF label is advertised as the documented non-aliasing
// "pin_<reference>" selector — never as "" (the changePIN contract
// reserves the empty selector for the legacy default-PIN fallback, so
// advertising "" would alias this record onto a different credential).
// ---------------------------------------------------------------------------

TEST(Pkcs15PinLifecycle, EmptyAodfLabelAdvertisesReferenceSelector)
{
    CardPluginService registry{std::filesystem::path(PLUGIN_DIR)};
    auto plugin = loadPkcs15Plugin(registry);
    ASSERT_NE(plugin, nullptr);

    auto rig = makeRig(
        "Pkcs15 Lifecycle EmptyLabel Reader 0",
        {{0x5031, odfPointingAtAodf()}, {0x5032, tokenInfoWithLabel("PKI Token")}, {0x4408, emptyLabelSecondPinAodf()}},
        {});
    const auto entries = plugin->getPINList(*rig.session);
    ASSERT_EQ(entries.size(), 2u);

    EXPECT_EQ(entries[0].label, "PIN");
    EXPECT_EQ(entries[0].reference, 0x01);
    EXPECT_EQ(entries[1].label, "pin_5");
    EXPECT_EQ(entries[1].reference, 0x05);
}

// ---------------------------------------------------------------------------
// The PUK's full DOCP (uses + unblocks + usesMax, on top of retries) reaches
// getPINList via PKCS15Card::readCounters, and the fallback path (no DOCP
// script entry for a reference) leaves the User PIN's uses/unblocks absent
// — only retriesLeft/retriesMax are ever populated for it (via the
// empty-VERIFY probe / the AppletSuiteGen1 family row), same as before this DOCP
// script existed.
// ---------------------------------------------------------------------------

TEST(Pkcs15PinLifecycle, PukSurfacesUsageAndUnblockCounters)
{
    CardPluginService registry{std::filesystem::path(PLUGIN_DIR)};
    auto plugin = loadPkcs15Plugin(registry);
    ASSERT_NE(plugin, nullptr);

    auto rig = makeAppletSuiteGen1RigWithDocp("Pkcs15 Lifecycle Counters Reader 0");
    const auto entries = plugin->getPINList(*rig.session);
    ASSERT_EQ(entries.size(), 4u);

    const auto& puk = findByKind(entries, PinKind::Puk);
    EXPECT_EQ(puk.retriesLeft, std::optional<int>{5});
    EXPECT_EQ(puk.retriesMax, std::optional<int>{5});
    EXPECT_EQ(puk.usesLeft, std::optional<int>{16});
    EXPECT_EQ(puk.usesMax, std::optional<int>{20});
    EXPECT_EQ(puk.unblocksLeft, std::optional<int>{5});

    const auto& user = findByLabel(entries, "User PIN");
    EXPECT_FALSE(user.usesLeft.has_value());
    EXPECT_FALSE(user.unblocksLeft.has_value());
}

// ---------------------------------------------------------------------------
// pkcs15::PKCS15Card::resetRetryCounter (ISO RESET RETRY
// COUNTER, the RRC verb behind pkcs15-plugin's unblockPIN override), tested
// directly against a minimal scripted connection (same technique as
// LibreSCRS_AetAttestationTests: FakePCSCConnection + a real PlainChannel,
// production selectApplet()/transmit path unmodified) — independent of
// family/quirk resolution, which the plugin-level tests further below cover.
//
// Anti-tautology: the double enforces its OWN, independently chosen "correct"
// P1 for each style (0x01 = ResetOnly, 0x00 = SetsNewPin — the ISO 7816-4
// §7.5.10 conventions the family quirk table's applyIsoExecutionDefaults
// encodes) and rejects anything else with 6A86, exactly like a real card
// refusing an unrecognised P1/P2 combination — so a passing test proves the
// caller-supplied P1 actually reached the wire, not merely that the
// production code and the test read the same constant. The PIN reference
// asserted on the wire is the data-driven value from the PinInfo the test
// builds, never a family default.
// ---------------------------------------------------------------------------

namespace {

pkcs15::PinInfo makeUnblockTargetPinInfo(std::uint8_t pinRef)
{
    pkcs15::PinInfo pin;
    pin.label = "User PIN";
    pin.pinReference = pinRef;
    pin.initialized = true;
    return pin; // path left empty: selectByPath is a no-op, matching these
                // isolated tests' scope (the DF-selection dance is already
                // covered by the shared selectApplet()/selectByPath() paths
                // changePIN/verifyPIN exercise elsewhere).
}

std::vector<std::uint8_t> asBytes(std::string_view s)
{
    return {s.begin(), s.end()};
}

} // namespace

TEST(Pkcs15ResetRetryCounter, ResetOnlyStyleSendsPukOnlyAtTheGivenP1)
{
    constexpr std::uint8_t kResetOnlyP1 = 0x01;
    constexpr std::uint8_t kDataDrivenPinRef = 0x86; // NOT a family default — this object's own reference.

    FakePCSCConnection conn;
    conn.setResponder([&](const APDUCommand& cmd) -> APDUResponse {
        if (cmd.ins == 0xA4 && cmd.p1 == 0x04) // SELECT AID
            return {{}, 0x90, 0x00};
        if (cmd.ins == 0x2C) { // RESET RETRY COUNTER
            if (cmd.p1 != kResetOnlyP1)
                return {{}, 0x6A, 0x86};
            return {{}, 0x90, 0x00};
        }
        return {{}, 0x6D, 0x00};
    });

    PlainChannel channel(conn, AppletAid{});
    pkcs15::PKCS15Card card(channel);
    auto pinInfo = makeUnblockTargetPinInfo(kDataDrivenPinRef);

    auto result = card.resetRetryCounter(pinInfo, "12345678", /*newPin=*/"", kResetOnlyP1);
    EXPECT_TRUE(result.success);
    EXPECT_EQ(result.retriesLeft, -1);
    EXPECT_FALSE(result.blocked);

    const auto& log = conn.history();
    const auto it = std::find_if(log.begin(), log.end(), [](const APDUCommand& c) { return c.ins == 0x2C; });
    ASSERT_NE(it, log.end());
    EXPECT_EQ(it->p1, kResetOnlyP1);
    EXPECT_EQ(it->p2, kDataDrivenPinRef); // data-driven pinRef, not a constant
    EXPECT_EQ(it->data, asBytes("12345678"));
}

TEST(Pkcs15ResetRetryCounter, SetsNewPinStyleSendsPukThenNewPin)
{
    constexpr std::uint8_t kSetsNewPinP1 = 0x00;
    constexpr std::uint8_t kDataDrivenPinRef = 0x92;

    FakePCSCConnection conn;
    conn.setResponder([&](const APDUCommand& cmd) -> APDUResponse {
        if (cmd.ins == 0xA4 && cmd.p1 == 0x04)
            return {{}, 0x90, 0x00};
        if (cmd.ins == 0x2C) {
            if (cmd.p1 != kSetsNewPinP1)
                return {{}, 0x6A, 0x86};
            return {{}, 0x90, 0x00};
        }
        return {{}, 0x6D, 0x00};
    });

    PlainChannel channel(conn, AppletAid{});
    pkcs15::PKCS15Card card(channel);
    auto pinInfo = makeUnblockTargetPinInfo(kDataDrivenPinRef);

    auto result = card.resetRetryCounter(pinInfo, "12345678", "4321", kSetsNewPinP1);
    EXPECT_TRUE(result.success);

    const auto& log = conn.history();
    const auto it = std::find_if(log.begin(), log.end(), [](const APDUCommand& c) { return c.ins == 0x2C; });
    ASSERT_NE(it, log.end());
    EXPECT_EQ(it->p2, kDataDrivenPinRef);
    EXPECT_EQ(it->data, asBytes("123456784321")); // puk || newPin, concatenated raw
}

TEST(Pkcs15ResetRetryCounter, WrongP1IsRejectedAndMapsToGenericFailureNotInvalidPin)
{
    // The double only ever accepts P1==0x01 (ResetOnly); calling with 0x00
    // on purpose proves a form-rejection (6A86) is NOT misread as a wrong-PUK
    // retry count.
    FakePCSCConnection conn;
    conn.setResponder([](const APDUCommand& cmd) -> APDUResponse {
        if (cmd.ins == 0xA4 && cmd.p1 == 0x04)
            return {{}, 0x90, 0x00};
        if (cmd.ins == 0x2C)
            return cmd.p1 == 0x01 ? APDUResponse{{}, 0x90, 0x00} : APDUResponse{{}, 0x6A, 0x86};
        return {{}, 0x6D, 0x00};
    });

    PlainChannel channel(conn, AppletAid{});
    pkcs15::PKCS15Card card(channel);
    auto pinInfo = makeUnblockTargetPinInfo(0x86);

    auto result = card.resetRetryCounter(pinInfo, "12345678", "", /*wrong on purpose=*/0x00);
    EXPECT_FALSE(result.success);
    EXPECT_EQ(result.retriesLeft, -1); // NOT a retry count — 6A86 is a form/parameter error
    EXPECT_FALSE(result.blocked);
}

TEST(Pkcs15ResetRetryCounter, WrongPukSwMapsToInvalidPinShapedResultAttributedToPuk)
{
    FakePCSCConnection conn;
    conn.setResponder([](const APDUCommand& cmd) -> APDUResponse {
        if (cmd.ins == 0xA4 && cmd.p1 == 0x04)
            return {{}, 0x90, 0x00};
        if (cmd.ins == 0x2C)
            return {{}, 0x63, 0xC5}; // wrong PUK, 5 PUK retries left
        return {{}, 0x6D, 0x00};
    });

    PlainChannel channel(conn, AppletAid{});
    pkcs15::PKCS15Card card(channel);
    auto pinInfo = makeUnblockTargetPinInfo(0x86);

    auto result = card.resetRetryCounter(pinInfo, "wrongpuk", "", 0x01);
    EXPECT_FALSE(result.success);
    EXPECT_EQ(result.retriesLeft, 5);
    EXPECT_FALSE(result.blocked);
}

TEST(Pkcs15ResetRetryCounter, PukExhaustedSwMapsToBlocked)
{
    FakePCSCConnection conn;
    conn.setResponder([](const APDUCommand& cmd) -> APDUResponse {
        if (cmd.ins == 0xA4 && cmd.p1 == 0x04)
            return {{}, 0x90, 0x00};
        if (cmd.ins == 0x2C)
            return {{}, 0x69, 0x83};
        return {{}, 0x6D, 0x00};
    });

    PlainChannel channel(conn, AppletAid{});
    pkcs15::PKCS15Card card(channel);
    auto pinInfo = makeUnblockTargetPinInfo(0x86);

    auto result = card.resetRetryCounter(pinInfo, "anything", "", 0x01);
    EXPECT_FALSE(result.success);
    EXPECT_TRUE(result.blocked);
}

TEST(Pkcs15ResetRetryCounter, ReferenceNotFoundSwMapsToGenericFailureNotInvalidPin)
{
    // 6A88 (and by the same code path 6985/6984/6A81/6D00) must never be
    // misread as a wrong-PUK retry signal.
    FakePCSCConnection conn;
    conn.setResponder([](const APDUCommand& cmd) -> APDUResponse {
        if (cmd.ins == 0xA4 && cmd.p1 == 0x04)
            return {{}, 0x90, 0x00};
        if (cmd.ins == 0x2C)
            return {{}, 0x6A, 0x88};
        return {{}, 0x6D, 0x00};
    });

    PlainChannel channel(conn, AppletAid{});
    pkcs15::PKCS15Card card(channel);
    auto pinInfo = makeUnblockTargetPinInfo(0x86);

    auto result = card.resetRetryCounter(pinInfo, "anything", "", 0x01);
    EXPECT_FALSE(result.success);
    EXPECT_EQ(result.retriesLeft, -1);
    EXPECT_FALSE(result.blocked);
}

// ---------------------------------------------------------------------------
// pkcs15::PKCS15Card::changeReferenceData (ISO CHANGE
// REFERENCE DATA, the verb behind pkcs15-plugin's activateTransportPin
// override), tested directly against a minimal scripted connection — same
// technique as the Pkcs15ResetRetryCounter block above, independent of
// family/quirk resolution, which the plugin-level tests further below
// cover.
//
// Anti-tautology: the double enforces its OWN, independently chosen
// "correct" P1 per test (0x00 = one-shot, 0x01 = prior-auth — the ISO
// 7816-4 §7.5.7 conventions the family quirk table's
// applyIsoExecutionDefaults / a future HW-verified row would encode) and
// rejects anything else with 6A86, so a passing test proves the
// caller-supplied P1 actually reached the wire. The PIN reference asserted
// on the wire is the data-driven value from the PinInfo the test builds,
// never a family default.
// ---------------------------------------------------------------------------

TEST(Pkcs15ChangeReferenceDataActivation, OneShotFormSendsTransportThenNewAtTheGivenP1)
{
    constexpr std::uint8_t kOneShotP1 = 0x00;
    constexpr std::uint8_t kDataDrivenPinRef = 0x92; // NOT a family default — this object's own reference.

    FakePCSCConnection conn;
    conn.setResponder([&](const APDUCommand& cmd) -> APDUResponse {
        if (cmd.ins == 0xA4 && cmd.p1 == 0x04) // SELECT AID
            return {{}, 0x90, 0x00};
        if (cmd.ins == 0x24) { // CHANGE REFERENCE DATA
            if (cmd.p1 != kOneShotP1)
                return {{}, 0x6A, 0x86};
            return {{}, 0x90, 0x00};
        }
        return {{}, 0x6D, 0x00};
    });

    PlainChannel channel(conn, AppletAid{});
    pkcs15::PKCS15Card card(channel);
    auto pinInfo = makeUnblockTargetPinInfo(kDataDrivenPinRef);

    auto result = card.changeReferenceData(pinInfo, "transport1", "4321", kOneShotP1);
    EXPECT_TRUE(result.success);
    EXPECT_EQ(result.retriesLeft, -1);
    EXPECT_FALSE(result.blocked);

    const auto& log = conn.history();
    const auto it = std::find_if(log.begin(), log.end(), [](const APDUCommand& c) { return c.ins == 0x24; });
    ASSERT_NE(it, log.end());
    EXPECT_EQ(it->p1, kOneShotP1);
    EXPECT_EQ(it->p2, kDataDrivenPinRef); // data-driven pinRef, not a constant
    EXPECT_EQ(it->data, asBytes("transport14321"));
}

TEST(Pkcs15ChangeReferenceDataActivation, PriorAuthFormSendsNewOnlyAtTheGivenP1)
{
    constexpr std::uint8_t kPriorAuthP1 = 0x01;
    constexpr std::uint8_t kDataDrivenPinRef = 0x92;

    FakePCSCConnection conn;
    conn.setResponder([&](const APDUCommand& cmd) -> APDUResponse {
        if (cmd.ins == 0xA4 && cmd.p1 == 0x04)
            return {{}, 0x90, 0x00};
        if (cmd.ins == 0x24) {
            if (cmd.p1 != kPriorAuthP1)
                return {{}, 0x6A, 0x86};
            return {{}, 0x90, 0x00};
        }
        return {{}, 0x6D, 0x00};
    });

    PlainChannel channel(conn, AppletAid{});
    pkcs15::PKCS15Card card(channel);
    auto pinInfo = makeUnblockTargetPinInfo(kDataDrivenPinRef);

    // oldValue is empty: the prior-auth form's transport value was already
    // consumed by a separate VERIFY (the plugin-level orchestration below),
    // so this call carries new-only data.
    auto result = card.changeReferenceData(pinInfo, /*oldValue=*/"", "4321", kPriorAuthP1);
    EXPECT_TRUE(result.success);

    const auto& log = conn.history();
    const auto it = std::find_if(log.begin(), log.end(), [](const APDUCommand& c) { return c.ins == 0x24; });
    ASSERT_NE(it, log.end());
    EXPECT_EQ(it->p2, kDataDrivenPinRef);
    EXPECT_EQ(it->data, asBytes("4321")); // new-only — old block genuinely absent, not padded
}

TEST(Pkcs15ChangeReferenceDataActivation, WrongP1IsRejectedAndMapsToGenericFailureNotInvalidPin)
{
    // The double only ever accepts P1==0x01; calling with 0x00 on purpose
    // proves a form-rejection (6A86) is NOT misread as a wrong-transport-
    // value retry count.
    FakePCSCConnection conn;
    conn.setResponder([](const APDUCommand& cmd) -> APDUResponse {
        if (cmd.ins == 0xA4 && cmd.p1 == 0x04)
            return {{}, 0x90, 0x00};
        if (cmd.ins == 0x24)
            return cmd.p1 == 0x01 ? APDUResponse{{}, 0x90, 0x00} : APDUResponse{{}, 0x6A, 0x86};
        return {{}, 0x6D, 0x00};
    });

    PlainChannel channel(conn, AppletAid{});
    pkcs15::PKCS15Card card(channel);
    auto pinInfo = makeUnblockTargetPinInfo(0x92);

    auto result = card.changeReferenceData(pinInfo, "transport1", "4321", /*wrong on purpose=*/0x00);
    EXPECT_FALSE(result.success);
    EXPECT_EQ(result.retriesLeft, -1); // NOT a retry count — 6A86 is a form/parameter error
    EXPECT_FALSE(result.blocked);
}

TEST(Pkcs15ChangeReferenceDataActivation, WrongTransportValueSwMapsToInvalidPinShapedResultAttributedToTransport)
{
    FakePCSCConnection conn;
    conn.setResponder([](const APDUCommand& cmd) -> APDUResponse {
        if (cmd.ins == 0xA4 && cmd.p1 == 0x04)
            return {{}, 0x90, 0x00};
        if (cmd.ins == 0x24)
            return {{}, 0x63, 0xC5}; // wrong transport value, 5 retries left
        return {{}, 0x6D, 0x00};
    });

    PlainChannel channel(conn, AppletAid{});
    pkcs15::PKCS15Card card(channel);
    auto pinInfo = makeUnblockTargetPinInfo(0x92);

    auto result = card.changeReferenceData(pinInfo, "wrongtransport", "4321", 0x00);
    EXPECT_FALSE(result.success);
    EXPECT_EQ(result.retriesLeft, 5);
    EXPECT_FALSE(result.blocked);
}

TEST(Pkcs15ChangeReferenceDataActivation, TransportExhaustedSwMapsToBlocked)
{
    FakePCSCConnection conn;
    conn.setResponder([](const APDUCommand& cmd) -> APDUResponse {
        if (cmd.ins == 0xA4 && cmd.p1 == 0x04)
            return {{}, 0x90, 0x00};
        if (cmd.ins == 0x24)
            return {{}, 0x69, 0x83};
        return {{}, 0x6D, 0x00};
    });

    PlainChannel channel(conn, AppletAid{});
    pkcs15::PKCS15Card card(channel);
    auto pinInfo = makeUnblockTargetPinInfo(0x92);

    auto result = card.changeReferenceData(pinInfo, "anything", "4321", 0x00);
    EXPECT_FALSE(result.success);
    EXPECT_TRUE(result.blocked);
}

TEST(Pkcs15ChangeReferenceDataActivation, ReferenceNotFoundSwMapsToGenericFailureNotInvalidPin)
{
    // 6A88 (and by the same code path 6985/6984/6A81/6D00) must never be
    // misread as a wrong-transport-value retry signal.
    FakePCSCConnection conn;
    conn.setResponder([](const APDUCommand& cmd) -> APDUResponse {
        if (cmd.ins == 0xA4 && cmd.p1 == 0x04)
            return {{}, 0x90, 0x00};
        if (cmd.ins == 0x24)
            return {{}, 0x6A, 0x88};
        return {{}, 0x6D, 0x00};
    });

    PlainChannel channel(conn, AppletAid{});
    pkcs15::PKCS15Card card(channel);
    auto pinInfo = makeUnblockTargetPinInfo(0x92);

    auto result = card.changeReferenceData(pinInfo, "anything", "4321", 0x00);
    EXPECT_FALSE(result.success);
    EXPECT_EQ(result.retriesLeft, -1);
    EXPECT_FALSE(result.blocked);
}

// The plugin's activateTransportPin leak guard (P1=0x01 prior-auth form)
// wraps VERIFY-then-CHANGE in a try/catch: an intra-verb transport drop
// between the successful VERIFY and the follow-up CHANGE must trigger a
// best-effort security-state clear rather than leaving a verified secret's
// state dangling on the card. No real family currently sets
// transportChangeP1=0x01 (both AppletSuiteGen1 and AppletSuiteGen2 use the
// ISO-default 0x00 via applyIsoExecutionDefaults — see
// pin_family_quirks.cpp), so that plugin-level orchestration has no
// reachable end-to-end path through the registry funnel today (the same
// documented gap as unblockPIN's RRC variants below: resolveFamilyId /
// findFamilyQuirks are non-parametric static lookups with no production
// injection seam). This test instead proves the two underlying facts the
// guard depends on, directly at the card-verb layer: (1) an intra-verb
// drop surfaces as a propagating exception — never silently misread as a
// wrong-transport-value SW — so the plugin's catch block has something
// real to catch, and (2) a subsequent applet re-select (the exact
// mechanism performSecStateClear's ReselectApplet variant uses) recovers
// once the transport is back. A companion plugin-funnel leak-guard test
// belongs alongside these once a real HW-verified P1=0x01 family exists.
TEST(Pkcs15ChangeReferenceDataActivation, PriorAuthFormIntraVerbDropAfterVerifyPropagatesAndReselectRecovers)
{
    bool dropSelect = false;

    FakePCSCConnection conn;
    conn.setResponder([&](const APDUCommand& cmd) -> APDUResponse {
        if (cmd.ins == 0xA4 && cmd.p1 == 0x04) { // SELECT AID (either P2 form)
            if (dropSelect)
                return {{}, 0x6A, 0x82}; // applet not found — transport dropped
            return {{}, 0x90, 0x00};
        }
        if (cmd.ins == 0x20 && !cmd.data.empty()) // VERIFY (the transport value)
            return {{}, 0x90, 0x00};
        if (cmd.ins == 0x24) // CHANGE REFERENCE DATA
            return {{}, 0x90, 0x00};
        return {{}, 0x6D, 0x00};
    });

    PlainChannel channel(conn, AppletAid{});
    pkcs15::PKCS15Card card(channel);
    auto pinInfo = makeUnblockTargetPinInfo(0x92);

    auto verifyResult = card.verifyPIN(pinInfo, "transport1");
    ASSERT_TRUE(verifyResult.success);

    dropSelect = true; // simulate the intra-verb transport drop
    EXPECT_THROW(card.changeReferenceData(pinInfo, "", "4321", 0x01), std::runtime_error);

    dropSelect = false; // transport is back
    EXPECT_TRUE(card.selectApplet());
}

// ---------------------------------------------------------------------------
// pkcs15::PKCS15Card::activate (ISO ACTIVATE, the verb
// behind pkcs15-plugin's activateSigningKey override), tested directly
// against a minimal scripted connection — same technique as the
// Pkcs15ResetRetryCounter / Pkcs15ChangeReferenceDataActivation blocks
// above, independent of family/quirk resolution.
//
// Anti-tautology: the double enforces its OWN, independently chosen
// "correct" P1/P2 (the ISO 7816-9 ACTIVATE convention the family quirk
// table's applyIsoExecutionDefaults encodes: `keyActivate = {0x44, 0x00,
// 0x00}`) and rejects anything else with 6A86, so a passing test proves
// the caller-supplied P1/P2 actually reached the wire.
//
// Coverage note (front-loaded — read before the plugin-funnel section
// further below): per derivePinStatus's own doc comment
// (pin_lifecycle_derivation.cpp), PinStatusEntry::keyActivatable /
// keyActivationPending keep their conservative FALSE default for EVERY
// family today — there is no FamilyQuirks/PinEvidence field at all whose
// value could flip them (unlike unblockPIN's rrcVariantKnown, which a
// future hardware campaign COULD flip). So pkcs15-plugin's
// activateSigningKey override has NO reachable success path through the
// real registry funnel for any family, including AppletSuiteGen1 — the
// plugin-funnel tests below only ever observe the Unsupported gate. The
// tests in THIS block instead prove the two facts that override's body
// composes, unbranched, into its result: PKCS15Card::activate's own SW
// mapping (9000 / 6985-idempotent / other-failure) and — reusing
// verifyPIN, already exercised via changePIN/unblockPIN elsewhere — the
// VERIFY-side 63Cx-to-retry-shaped-failure mapping
// LibreSCRS::Plugin::classifyPinOutcome then turns into InvalidPin.
// ---------------------------------------------------------------------------

TEST(Pkcs15KeyActivation, OkSwActivatesAtTheGivenP1P2)
{
    constexpr std::uint8_t kP1 = 0x00; // AppletSuiteGen1's keyActivate.p1 (the family table's ISO default).
    constexpr std::uint8_t kP2 = 0x00; // ditto keyActivate.p2 — caller-supplied, never a PKCS15Card constant.
    constexpr std::uint8_t kDataDrivenPinRef = 0x92; // the guarding SIGN PIN's own reference (path navigation only).

    FakePCSCConnection conn;
    conn.setResponder([&](const APDUCommand& cmd) -> APDUResponse {
        if (cmd.ins == 0xA4 && cmd.p1 == 0x04) // SELECT AID
            return {{}, 0x90, 0x00};
        if (cmd.ins == 0x44) { // ACTIVATE
            if (cmd.p1 != kP1 || cmd.p2 != kP2)
                return {{}, 0x6A, 0x86};
            return {{}, 0x90, 0x00};
        }
        return {{}, 0x6D, 0x00};
    });

    PlainChannel channel(conn, AppletAid{});
    pkcs15::PKCS15Card card(channel);
    auto pinInfo = makeUnblockTargetPinInfo(kDataDrivenPinRef);

    auto result = card.activate(pinInfo, kP1, kP2);
    EXPECT_TRUE(result.success);
    EXPECT_EQ(result.retriesLeft, -1);
    EXPECT_FALSE(result.blocked);

    const auto& log = conn.history();
    const auto it = std::find_if(log.begin(), log.end(), [](const APDUCommand& c) { return c.ins == 0x44; });
    ASSERT_NE(it, log.end());
    EXPECT_EQ(it->p1, kP1);
    EXPECT_EQ(it->p2, kP2);
}

TEST(Pkcs15KeyActivation, AlreadyActiveSwIsIdempotentSuccess)
{
    // ISO ACTIVATE on an already-operational key answers 6985 (conditions
    // of use not satisfied) — the "reachable/retry case" pins:
    // a client retry (or a card that was already activated by a previous
    // attempt) must be treated as success, not failure, so it never
    // surfaces a spurious KeyActivationFailed for a key that is, in fact,
    // already active.
    FakePCSCConnection conn;
    conn.setResponder([](const APDUCommand& cmd) -> APDUResponse {
        if (cmd.ins == 0xA4 && cmd.p1 == 0x04)
            return {{}, 0x90, 0x00};
        if (cmd.ins == 0x44)
            return {{}, 0x69, 0x85};
        return {{}, 0x6D, 0x00};
    });

    PlainChannel channel(conn, AppletAid{});
    pkcs15::PKCS15Card card(channel);
    auto pinInfo = makeUnblockTargetPinInfo(0x92);

    auto result = card.activate(pinInfo, 0x00, 0x00);
    EXPECT_TRUE(result.success);
    EXPECT_EQ(result.retriesLeft, -1);
    EXPECT_FALSE(result.blocked);
}

TEST(Pkcs15KeyActivation, WrongP1P2IsRejectedAndMapsToFailureNotSuccess)
{
    // The double only ever accepts P1==0x00/P2==0x00; calling with
    // different values on purpose proves a form-rejection (6A86) reaches
    // `success=false`, not a silently-accepted activation.
    FakePCSCConnection conn;
    conn.setResponder([](const APDUCommand& cmd) -> APDUResponse {
        if (cmd.ins == 0xA4 && cmd.p1 == 0x04)
            return {{}, 0x90, 0x00};
        if (cmd.ins == 0x44)
            return (cmd.p1 == 0x00 && cmd.p2 == 0x00) ? APDUResponse{{}, 0x90, 0x00} : APDUResponse{{}, 0x6A, 0x86};
        return {{}, 0x6D, 0x00};
    });

    PlainChannel channel(conn, AppletAid{});
    pkcs15::PKCS15Card card(channel);
    auto pinInfo = makeUnblockTargetPinInfo(0x92);

    auto result = card.activate(pinInfo, /*wrong on purpose=*/0x01, 0x02);
    EXPECT_FALSE(result.success);
    EXPECT_EQ(result.retriesLeft, -1);
    EXPECT_FALSE(result.blocked);
}

TEST(Pkcs15KeyActivation, ReferenceNotFoundSwMapsToFailure)
{
    // 6A88 (and by the same code path 6A81/6D00/anything else non-9000,
    // non-6985) is a genuine ACTIVATE failure — VERIFY succeeded but the
    // key ACTIVATE step failed (KeyActivationFailed, at the plugin layer).
    FakePCSCConnection conn;
    conn.setResponder([](const APDUCommand& cmd) -> APDUResponse {
        if (cmd.ins == 0xA4 && cmd.p1 == 0x04)
            return {{}, 0x90, 0x00};
        if (cmd.ins == 0x44)
            return {{}, 0x6A, 0x88};
        return {{}, 0x6D, 0x00};
    });

    PlainChannel channel(conn, AppletAid{});
    pkcs15::PKCS15Card card(channel);
    auto pinInfo = makeUnblockTargetPinInfo(0x92);

    auto result = card.activate(pinInfo, 0x00, 0x00);
    EXPECT_FALSE(result.success);
}

TEST(Pkcs15KeyActivation, VerifySignPinWrongValueMapsToRetryShapedFailure)
{
    // Proves the VERIFY-side fact activateSigningKey's classification
    // depends on: PKCS15Card::verifyPIN maps 63Cx to a retry-shaped
    // failure (success=false, retriesLeft=N), which
    // LibreSCRS::Plugin::classifyPinOutcome (reused verbatim, unchanged,
    // by every sibling override) turns into InvalidPin, attributed to the
    // SIGN PIN.
    FakePCSCConnection conn;
    conn.setResponder([](const APDUCommand& cmd) -> APDUResponse {
        if (cmd.ins == 0xA4 && cmd.p1 == 0x04)
            return {{}, 0x90, 0x00};
        if (cmd.ins == 0x20 && !cmd.data.empty())
            return {{}, 0x63, 0xC5};
        return {{}, 0x6D, 0x00};
    });

    PlainChannel channel(conn, AppletAid{});
    pkcs15::PKCS15Card card(channel);
    auto pinInfo = makeUnblockTargetPinInfo(0x92);

    auto result = card.verifyPIN(pinInfo, "wrongpin");
    EXPECT_FALSE(result.success);
    EXPECT_EQ(result.retriesLeft, 5);
    EXPECT_FALSE(result.blocked);
}

TEST(Pkcs15KeyActivation, IntraVerbDropAfterVerifyPropagatesAndReselectRecovers)
{
    // The plugin's activateSigningKey leak guard wraps VERIFY-then-ACTIVATE
    // in a try/catch: an intra-verb transport drop between the successful
    // VERIFY and the follow-up ACTIVATE must trigger a best-effort
    // security-state clear rather than leaving a verified SIGN PIN's state
    // dangling on the card. Same technique as
    // Pkcs15ChangeReferenceDataActivation's
    // PriorAuthFormIntraVerbDropAfterVerifyPropagatesAndReselectRecovers:
    // (1) the drop surfaces as a propagating exception — never silently
    // misread as an ACTIVATE-rejected SW — so the plugin's catch block has
    // something real to catch, and (2) a subsequent applet re-select (the
    // exact mechanism performSecStateClear's ReselectApplet variant uses)
    // recovers once the transport is back.
    bool dropSelect = false;

    FakePCSCConnection conn;
    conn.setResponder([&](const APDUCommand& cmd) -> APDUResponse {
        if (cmd.ins == 0xA4 && cmd.p1 == 0x04) {
            if (dropSelect)
                return {{}, 0x6A, 0x82}; // applet not found — transport dropped
            return {{}, 0x90, 0x00};
        }
        if (cmd.ins == 0x20 && !cmd.data.empty()) // VERIFY (the SIGN PIN)
            return {{}, 0x90, 0x00};
        if (cmd.ins == 0x44) // ACTIVATE
            return {{}, 0x90, 0x00};
        return {{}, 0x6D, 0x00};
    });

    PlainChannel channel(conn, AppletAid{});
    pkcs15::PKCS15Card card(channel);
    auto pinInfo = makeUnblockTargetPinInfo(0x92);

    auto verifyResult = card.verifyPIN(pinInfo, "signpin1");
    ASSERT_TRUE(verifyResult.success);

    dropSelect = true; // simulate the intra-verb transport drop
    EXPECT_THROW(card.activate(pinInfo, 0x00, 0x00), std::runtime_error);

    dropSelect = false; // transport is back
    EXPECT_TRUE(card.selectApplet());
}

// ---------------------------------------------------------------------------
// pkcs15-plugin's unblockPIN override, driven end-to-end (plugin .so via the
// registry) against the SAME AppletSuiteGen1 / unknown-family fixtures as
// getPINList above.
//
// Credential resolution mirrors changePIN's hard-fail contract exactly. The
// family-gated fallback is the observable, HONEST current-state behaviour:
// the real AppletSuiteGen1 quirk row deliberately withholds a
// hardware-verified RRC variant (pin_family_quirks.cpp — rrcVariantKnown
// stays false for UserPin/SignPin pending a hardware campaign, even though
// The family quirk table already seeds the ISO-default P1 bytes and the RESET RETRY
// COUNTER builder), so unblockPIN correctly reports Unsupported for it
// today. Critically, NO RESET RETRY COUNTER APDU reaches the wire in that
// case — proving the style resolution (derivePinStatus, the SAME function
// getPINList's advertisement uses) is genuinely data-driven rather than an
// unconditional attempt: an accidental hardcode (e.g. "always try P1=0x00")
// would send the APDU regardless of rrcVariantKnown and would be caught by
// the isResetRetryCounterCmd assertions below. Once a future hardware
// campaign flips that row's rrcVariantKnown/unblockStyle for a kind, this
// same code path starts succeeding — no unblockPIN change required — and a
// companion "success" fixture test belongs alongside these at that time.
// ---------------------------------------------------------------------------

TEST(Pkcs15PinLifecycle, UnblockPinNonEmptySelectorMissIsHardFailure)
{
    CardPluginService registry{std::filesystem::path(PLUGIN_DIR)};
    auto plugin = loadPkcs15Plugin(registry);
    ASSERT_NE(plugin, nullptr);

    auto rig = makeAppletSuiteGen1Rig("Pkcs15 Unblock SelectorMiss Reader 0");
    LibreSCRS::Secure::String puk{std::string_view{"12345678"}};
    LibreSCRS::Secure::String newPin{std::string_view{"4321"}};
    const auto result = plugin->unblockPIN(*rig.session, "Not A Real Label", puk, newPin);
    EXPECT_EQ(result.outcome, LibreSCRS::Plugin::PINResultOutcome::PluginError);
    EXPECT_TRUE(std::none_of(rig.card->log.begin(), rig.card->log.end(), isResetRetryCounterCmd));
}

TEST(Pkcs15PinLifecycle, UnblockPinAppletSuiteGen1FallsBackToUnsupportedUntilHwVerified)
{
    CardPluginService registry{std::filesystem::path(PLUGIN_DIR)};
    auto plugin = loadPkcs15Plugin(registry);
    ASSERT_NE(plugin, nullptr);

    auto rig = makeAppletSuiteGen1Rig("Pkcs15 Unblock AppletSuiteGen1 Reader 0");
    LibreSCRS::Secure::String puk{std::string_view{"12345678"}};
    LibreSCRS::Secure::String newPin{std::string_view{"4321"}};
    const auto result = plugin->unblockPIN(*rig.session, "User PIN", puk, newPin);
    EXPECT_EQ(result.outcome, LibreSCRS::Plugin::PINResultOutcome::Unsupported);
    // No RRC attempt, and no consumption of the read surface either.
    EXPECT_TRUE(std::none_of(rig.card->log.begin(), rig.card->log.end(), isResetRetryCounterCmd));
    EXPECT_TRUE(std::none_of(rig.card->log.begin(), rig.card->log.end(), isRealVerify));
}

TEST(Pkcs15PinLifecycle, UnblockPinUnknownFamilyFallsBackToUnsupported)
{
    CardPluginService registry{std::filesystem::path(PLUGIN_DIR)};
    auto plugin = loadPkcs15Plugin(registry);
    ASSERT_NE(plugin, nullptr);

    auto rig = makeUnknownRig("Pkcs15 Unblock Unknown Reader 0");
    LibreSCRS::Secure::String puk{std::string_view{"12345678"}};
    LibreSCRS::Secure::String newPin{std::string_view{"4321"}};
    const auto result = plugin->unblockPIN(*rig.session, "PIN", puk, newPin);
    EXPECT_EQ(result.outcome, LibreSCRS::Plugin::PINResultOutcome::Unsupported);
    EXPECT_TRUE(std::none_of(rig.card->log.begin(), rig.card->log.end(), isResetRetryCounterCmd));
}

// ---------------------------------------------------------------------------
// pkcs15-plugin's activateTransportPin override, driven
// end-to-end (plugin .so via the registry) against the SAME
// AppletSuiteGen1 / unknown-family fixtures as getPINList/unblockPIN
// above, plus the synthetic transportSignPinAodf() rig for the one
// reachable success form.
//
// Credential resolution hard-fails on ANY findPinByLabel miss — including
// the EMPTY selector, unlike changePIN/unblockPIN's legacy default-PIN
// fallback (see the override's doc comment in pkcs15_card_plugin.cpp for
// why: findUserPin() requires pin.initialized, which a transport-state
// SIGN PIN by definition is not).
//
// The non-activatable fallback is the anti-hardcode proof: the REAL
// hardware-captured AppletSuiteGen1 Signature PIN (already personalized,
// pinFlags 0x48) resolves state=Operational, not Transport, so
// activateTransportPin correctly reports Unsupported for it even though
// the family's supportsTransportPin is true — proving the gate reads
// live evidence rather than merely the family flag. Critically, NO CHANGE
// REFERENCE DATA APDU reaches the wire in that case.
//
// The one-shot (P1=0x00) success path IS reachable today (unlike
// unblockPIN's RRC forms): AppletSuiteGen1's row already carries
// transportChangeP1=0x00 (the family table's ISO default), so a genuinely
// transport-state SIGN PIN (transportSignPinAodf) drives a real CHANGE
// REFERENCE DATA through the plugin. The P1=0x01 prior-auth form's
// VERIFY-then-CHANGE orchestration and its intra-verb-drop leak guard have
// no such reachable path (no real family sets transportChangeP1=0x01) —
// see the Pkcs15ChangeReferenceDataActivation card-verb-layer tests above
// for that coverage.
// ---------------------------------------------------------------------------

TEST(Pkcs15PinLifecycle, ActivateTransportPinNonEmptySelectorMissIsHardFailure)
{
    CardPluginService registry{std::filesystem::path(PLUGIN_DIR)};
    auto plugin = loadPkcs15Plugin(registry);
    ASSERT_NE(plugin, nullptr);

    auto rig = makeAppletSuiteGen1Rig("Pkcs15 Activate SelectorMiss Reader 0");
    LibreSCRS::Secure::String transport{std::string_view{"87654321"}};
    LibreSCRS::Secure::String newPin{std::string_view{"4321"}};
    const auto result = plugin->activateTransportPin(*rig.session, "Not A Real Label", transport, newPin);
    EXPECT_EQ(result.outcome, LibreSCRS::Plugin::PINResultOutcome::PluginError);
    EXPECT_TRUE(std::none_of(rig.card->log.begin(), rig.card->log.end(), isChangeReferenceDataCmd));
}

TEST(Pkcs15PinLifecycle, ActivateTransportPinEmptySelectorIsAlsoHardFailure)
{
    // Unlike changePIN/unblockPIN, there is no "empty selector -> default
    // PIN" fallback for activation (findUserPin() requires initialized,
    // which a transport-state SIGN PIN never is) — an empty selector is
    // therefore ALSO a hard-fail here, not merely the non-empty-miss case.
    CardPluginService registry{std::filesystem::path(PLUGIN_DIR)};
    auto plugin = loadPkcs15Plugin(registry);
    ASSERT_NE(plugin, nullptr);

    auto rig = makeAppletSuiteGen1TransportSignRig("Pkcs15 Activate EmptySelector Reader 0");
    LibreSCRS::Secure::String transport{std::string_view{"87654321"}};
    LibreSCRS::Secure::String newPin{std::string_view{"4321"}};
    const auto result = plugin->activateTransportPin(*rig.session, "", transport, newPin);
    EXPECT_EQ(result.outcome, LibreSCRS::Plugin::PINResultOutcome::PluginError);
    EXPECT_TRUE(std::none_of(rig.card->log.begin(), rig.card->log.end(), isChangeReferenceDataCmd));
}

TEST(Pkcs15PinLifecycle, ActivateTransportPinAlreadyOperationalSignPinFallsBackToUnsupported)
{
    CardPluginService registry{std::filesystem::path(PLUGIN_DIR)};
    auto plugin = loadPkcs15Plugin(registry);
    ASSERT_NE(plugin, nullptr);

    // The real hardware-captured AppletSuiteGen1 Signature PIN is already
    // personalized (pinFlags 0x48: local + initialized) -> state=Operational,
    // not Transport, even though the family DOES support transport PINs in
    // general. The gate must read the credential's OWN evidence, never just
    // the family flag.
    auto rig = makeAppletSuiteGen1Rig("Pkcs15 Activate AlreadyOperational Reader 0");
    LibreSCRS::Secure::String transport{std::string_view{"87654321"}};
    LibreSCRS::Secure::String newPin{std::string_view{"4321"}};
    const auto result = plugin->activateTransportPin(*rig.session, "Signature PIN", transport, newPin);
    EXPECT_EQ(result.outcome, LibreSCRS::Plugin::PINResultOutcome::Unsupported);
    EXPECT_TRUE(std::none_of(rig.card->log.begin(), rig.card->log.end(), isChangeReferenceDataCmd));
    EXPECT_TRUE(std::none_of(rig.card->log.begin(), rig.card->log.end(), isRealVerify));
}

TEST(Pkcs15PinLifecycle, ActivateTransportPinUnknownFamilyFallsBackToUnsupported)
{
    CardPluginService registry{std::filesystem::path(PLUGIN_DIR)};
    auto plugin = loadPkcs15Plugin(registry);
    ASSERT_NE(plugin, nullptr);

    auto rig = makeUnknownRig("Pkcs15 Activate Unknown Reader 0");
    LibreSCRS::Secure::String transport{std::string_view{"87654321"}};
    LibreSCRS::Secure::String newPin{std::string_view{"4321"}};
    const auto result = plugin->activateTransportPin(*rig.session, "PIN", transport, newPin);
    EXPECT_EQ(result.outcome, LibreSCRS::Plugin::PINResultOutcome::Unsupported);
    EXPECT_TRUE(std::none_of(rig.card->log.begin(), rig.card->log.end(), isChangeReferenceDataCmd));
}

TEST(Pkcs15PinLifecycle, ActivateTransportPinOneShotFormSucceedsAndSendsTransportThenNew)
{
    CardPluginService registry{std::filesystem::path(PLUGIN_DIR)};
    auto plugin = loadPkcs15Plugin(registry);
    ASSERT_NE(plugin, nullptr);

    auto rig = makeAppletSuiteGen1TransportSignRig("Pkcs15 Activate OneShot Reader 0");
    rig.card->acceptedChangeRefP1 = 0x00; // AppletSuiteGen1's transportChangeP1 (the family table's ISO default)

    // transportSignPinAodf's storedLength is 4 (minLength=4/storedLength=4/
    // maxLength=8): both values are exactly 4 chars so encodePIN neither
    // truncates nor pads either side, keeping the on-wire data assertion
    // below a direct, unambiguous concatenation.
    LibreSCRS::Secure::String transport{std::string_view{"8765"}};
    LibreSCRS::Secure::String newPin{std::string_view{"4321"}};
    const auto result = plugin->activateTransportPin(*rig.session, "Sign PIN", transport, newPin);
    EXPECT_EQ(result.outcome, LibreSCRS::Plugin::PINResultOutcome::Ok);

    const auto& log = rig.card->log;
    const auto it = std::find_if(log.begin(), log.end(), isChangeReferenceDataCmd);
    ASSERT_NE(it, log.end());
    EXPECT_EQ(it->p1, 0x00);
    EXPECT_EQ(it->p2, 0x92); // data-driven signPinRef from the AODF, not a constant
    const std::vector<std::uint8_t> expectedData = {'8', '7', '6', '5', '4', '3', '2', '1'};
    EXPECT_EQ(it->data, expectedData); // transport || new, concatenated raw
    // One-shot form: no separate VERIFY precedes the CHANGE.
    EXPECT_TRUE(std::none_of(log.begin(), log.end(), isRealVerify));
    // Exactly one CHANGE REFERENCE DATA reached the wire.
    EXPECT_EQ(std::count_if(log.begin(), log.end(), isChangeReferenceDataCmd), 1);
}

// ---------------------------------------------------------------------------
// pkcs15-plugin's activateSigningKey override, driven
// end-to-end (plugin .so via the registry) against the SAME
// AppletSuiteGen1 / unknown-family fixtures as getPINList/unblockPIN/
// activateTransportPin above.
//
// Unlike unblockPIN and activateTransportPin, this override's base virtual
// signature carries NO pin-label selector (CardPlugin.h ~737): there is no
// "selector miss" case to test here — the credential is resolved entirely
// from the derived evidence set (PinStatusEntry::keyActivatable), never a
// caller-supplied label.
//
// Both tests below observe the SAME outcome (Unsupported, zero ACTIVATE
// APDUs) for a different reason each: the first because the family is
// unrecognized at all; the second — the anti-hardcode proof — because the
// AppletSuiteGen1 family row already carries ISO-default `keyActivate`
// bytes (still [HW-VERIFY]) yet still correctly reports
// Unsupported, since no credential's derived record ever asserts
// keyActivatable today (see the Pkcs15KeyActivation block's coverage note
// above, and unblockPIN's identically-shaped documented gap). A "success"
// fixture test belongs alongside these once a future increment teaches
// derivePinStatus to assert keyActivatable from real key/certificate
// evidence — no activateSigningKey change required at that point, exactly
// as unblockPIN's own gap note promises for rrcVariantKnown.
// ---------------------------------------------------------------------------

TEST(Pkcs15PinLifecycle, ActivateSigningKeyUnknownFamilyFallsBackToUnsupported)
{
    CardPluginService registry{std::filesystem::path(PLUGIN_DIR)};
    auto plugin = loadPkcs15Plugin(registry);
    ASSERT_NE(plugin, nullptr);

    auto rig = makeUnknownRig("Pkcs15 ActivateKey Unknown Reader 0");
    LibreSCRS::Secure::String signPin{std::string_view{"1234"}};
    const auto result = plugin->activateSigningKey(*rig.session, signPin);
    EXPECT_EQ(result.outcome, LibreSCRS::Plugin::PINResultOutcome::Unsupported);
    // The AODF SELECT DOES reach the wire (readProfile runs first, to
    // resolve the family) — proving the call reached the override's own
    // body rather than the inherited base default (which touches the
    // session/channel not at all); the family then resolves to Unknown, so
    // no quirk row exists and the override exits before any VERIFY/ACTIVATE.
    EXPECT_TRUE(std::any_of(rig.card->log.begin(), rig.card->log.end(), isSelectAodfFid));
    EXPECT_TRUE(std::none_of(rig.card->log.begin(), rig.card->log.end(), isActivateCmd));
    EXPECT_TRUE(std::none_of(rig.card->log.begin(), rig.card->log.end(), isRealVerify));
}

TEST(Pkcs15PinLifecycle, ActivateSigningKeyAppletSuiteGen1FallsBackToUnsupportedUntilKeyEvidenceExists)
{
    CardPluginService registry{std::filesystem::path(PLUGIN_DIR)};
    auto plugin = loadPkcs15Plugin(registry);
    ASSERT_NE(plugin, nullptr);

    // The AppletSuiteGen1 rig (hardware-captured AODF): the family row DOES
    // carry the ISO-default keyActivate bytes (still [HW-VERIFY]), but no AODF
    // object's derived record is ever keyActivatable (derivePinStatus keeps
    // it conservatively false for every family today) — proving the gate
    // reads live derived evidence, never just "this family supports key
    // activation in general".
    auto rig = makeAppletSuiteGen1Rig("Pkcs15 ActivateKey AppletSuiteGen1 Reader 0");
    LibreSCRS::Secure::String signPin{std::string_view{"1234"}};
    const auto result = plugin->activateSigningKey(*rig.session, signPin);
    EXPECT_EQ(result.outcome, LibreSCRS::Plugin::PINResultOutcome::Unsupported);
    // The profile IS read and the family IS resolved + quirk-matched (this
    // rig's label positively resolves AppletSuiteGen1, unlike the unknown-
    // family test above) — proving the override engaged the full
    // evidence-scan/derivation path and STILL correctly found no
    // keyActivatable credential, rather than short-circuiting on a missing
    // quirk row. No ACTIVATE attempt, and no VERIFY consumption either.
    EXPECT_TRUE(std::any_of(rig.card->log.begin(), rig.card->log.end(), isSelectAodfFid));
    EXPECT_TRUE(std::none_of(rig.card->log.begin(), rig.card->log.end(), isActivateCmd));
    EXPECT_TRUE(std::none_of(rig.card->log.begin(), rig.card->log.end(), isRealVerify));
}
