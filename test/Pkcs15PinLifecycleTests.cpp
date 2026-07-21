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

#include "fixtures/veridos_suite1_aodf_20260718.h"
#include "fixtures/veridos_suite1_docp_20260721.h"

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

bool logHasProbeFor(const std::vector<APDUCommand>& log, std::uint8_t ref)
{
    return std::any_of(log.begin(), log.end(),
                       [ref](const APDUCommand& c) { return isEmptyVerifyProbe(c) && c.p2 == ref; });
}

// Kind-lookup helper. NOTE: on a plain (non-PACE) session the CAN entry
// also classifies as PinKind::UserPin (see the CAN commentary above), so
// this is only unambiguous for kinds unique per entry set (e.g. Puk,
// SignPin). Callers needing the "User PIN" object specifically (as
// distinct from a degraded CAN) should use findByLabel instead. On a
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

// Suite-1 scripted card: hardware-scanned AODF (kSuite1Aodf20260718) behind
// the hardware-captured EF.TokenInfo label "SSCDv1 PACE MD" (contact scan
// 2026-07-20, production readProfile path) — resolveFamilyId classifies it
// FamilyId::VeridosAppletSuite1, opening the probe gate (probeSafe family
// row), so the probe script (User PIN 3, Signature PIN 3, PUK 5) supplies
// the counters. The CAN reference is deliberately absent from the script (a
// non-VERIFY-able object — the real card answers 6A88).
FakeCardRig makeSuite1Rig(const char* readerName)
{
    const auto& aodf = LibreSCRS::test::fixtures::kSuite1Aodf20260718;
    return makeRig(readerName,
                   {{0x5031, odfPointingAtAodf()},
                    {0x5032, tokenInfoWithLabel("SSCDv1 PACE MD")},
                    {0x4408, {aodf.begin(), aodf.end()}}},
                   {{0x86, 3}, {0x92, 3}, {0x93, 5}});
}

// Same suite-1 rig, PLUS a scripted DOCP answer for the PUK (ORF 0x13, ref
// 0x93 & 0x1F) and the User PIN (ORF 0x06, ref 0x86 & 0x1F): readCounters
// now resolves retriesLeft (and, for the PUK, uses/unblocks) from the DOCP
// itself, so the empty-VERIFY fallback probe never reaches those two
// references. The Signature PIN (ORF 0x12) and CAN (ORF 0x02) have no
// DOCP entry and keep going through the empty-VERIFY probe, same as the
// plain suite-1 rig. Kept separate from makeSuite1Rig so the other
// suite-1 tests (which assert the empty-VERIFY probe reaches 0x86/0x93)
// are unaffected.
FakeCardRig makeSuite1RigWithDocp(const char* readerName)
{
    auto rig = makeSuite1Rig(readerName);
    const auto& pukDocp = LibreSCRS::test::fixtures::kSuite1PukDocp;
    const auto& userPinDocp = LibreSCRS::test::fixtures::kSuite1UserPinDocp;
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
// Suite-1 AODF + the hardware-captured token label → the plugin resolves
// FamilyId::VeridosAppletSuite1 and entries combine card-asserted evidence
// (PUK via soPin + the unblock chain, Signature PIN via the family
// signature-DF marker) with the suite-1 family row: change advertised for
// User/Signature PIN, retriesMax from the row, counters from the
// (probe-safe) empty-VERIFY probe. Unblock stays un-advertised — the
// RESET RETRY COUNTER variant is not hardware-verified for this family.
// This rig models a PLAIN (contact) session, so the CAN record classifies
// conservatively (kind=Can requires session PACE evidence; the PACE-gated
// half of that rule is covered at the derivation level — a scripted plain
// card cannot complete a real PACE handshake).
// ---------------------------------------------------------------------------

TEST(Pkcs15PinLifecycle, Suite1AodfProducesClassifiedEntries)
{
    CardPluginService registry{std::filesystem::path(PLUGIN_DIR)};
    auto plugin = loadPkcs15Plugin(registry);
    ASSERT_NE(plugin, nullptr);

    auto rig = makeSuite1Rig("Pkcs15 Lifecycle Suite1 Reader 0");
    const auto entries = plugin->getPINList(*rig.session);
    ASSERT_EQ(entries.size(), 4u);

    // AODF order is preserved: CAN, User PIN, PUK, Signature PIN.
    const auto& can = entries[0];
    const auto& user = entries[1];
    const auto& puk = entries[2];
    const auto& sign = entries[3];

    // CAN record on a PLAIN session: the Can kind requires session-level
    // PACE evidence (the plain probe answered 6982, or PACE was already
    // established) corroborated by the AODF's disabled-flags shape — the
    // flags ALONE must not overclaim a PACE pseudo-credential. Without
    // that evidence the record degrades to an (unchangeable) user
    // credential; the probe finds no VERIFY-able reference, so its
    // counter stays absent.
    EXPECT_EQ(can.label, "PACE CAN");
    EXPECT_EQ(can.reference, 0x02);
    EXPECT_EQ(can.kind, PinKind::UserPin);
    EXPECT_FALSE(can.canChange); // change-disabled AODF veto
    EXPECT_FALSE(can.unblockable);
    EXPECT_EQ(can.retriesLeft, std::nullopt); // not a VERIFY-able reference
    EXPECT_FALSE(can.blocked);

    // User PIN: global user credential; the suite-1 row advertises change
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
    // This rig has NO scripted DOCP (makeSuite1Rig, not *WithDocp): GET
    // DATA (ODD) answers 6A88, so readCounters comes back all-absent and
    // retriesLeft/retriesMax fall all the way back to the empty-VERIFY
    // probe (5) and the suite-1 quirk row (5) respectively — the graceful-
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
// gate-OPEN half runs against the suite-1 rig, whose captured label resolves
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
        // Suite-1 card, captured label → probe-safe family row → gate OPEN:
        // per-reference probes leave getPINList and the counters land.
        auto rig = makeSuite1Rig("Pkcs15 Lifecycle Gate Reader 1");
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
// empty-VERIFY probe / the suite-1 family row), same as before this DOCP
// script existed.
// ---------------------------------------------------------------------------

TEST(Pkcs15PinLifecycle, PukSurfacesUsageAndUnblockCounters)
{
    CardPluginService registry{std::filesystem::path(PLUGIN_DIR)};
    auto plugin = loadPkcs15Plugin(registry);
    ASSERT_NE(plugin, nullptr);

    auto rig = makeSuite1RigWithDocp("Pkcs15 Lifecycle Counters Reader 0");
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
