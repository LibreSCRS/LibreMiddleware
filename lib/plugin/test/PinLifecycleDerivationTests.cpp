// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "pin_lifecycle_derivation.h"
#include "pin_family_quirks.h"

#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <vector>

using namespace LibreSCRS::Plugin;
using namespace LibreSCRS::Plugin::Internal;

namespace {

// AppletSuiteGen1 card AODF facts (hardware-scanned 2026-07-18).
PinEvidence appletSuiteGen1UserPin()
{
    PinEvidence e;
    e.label = "User PIN";
    e.reference = 0x86;
    e.ownId = {0x06};
    e.initialized = true;
    // Protected/unblocked by the PUK object (full authId bytes).
    e.authIdChainTarget = std::vector<std::uint8_t>{0x03};
    return e;
}
PinEvidence appletSuiteGen1Puk()
{
    PinEvidence e;
    e.label = "Global PUK";
    e.reference = 0x93;
    e.ownId = {0x03}; // chain target of the User PIN
    e.soPinFlag = true;
    e.unblockDisabledFlag = true;
    e.unblockingPinFlag = true;
    e.initialized = true;
    return e;
}
PinEvidence appletSuiteGen1SignPin()
{
    PinEvidence e;
    e.label = "Signature PIN";
    e.reference = 0x92;
    e.localScope = true;
    e.inQscdDf = true;
    e.initialized = true;
    return e;
}
PinEvidence appletSuiteGen1Can()
{
    PinEvidence e;
    e.label = "PACE CAN";
    e.reference = 0x02;
    e.changeDisabledFlag = true;
    e.unblockDisabledFlag = true;
    e.paceEvidence = true;
    return e;
}
std::vector<PinEvidence> appletSuiteGen1All()
{
    return {appletSuiteGen1UserPin(), appletSuiteGen1Puk(), appletSuiteGen1SignPin(), appletSuiteGen1Can()};
}

} // namespace

TEST(PinLifecycleDerivation, AppletSuiteGen1KindClassification)
{
    const auto all = appletSuiteGen1All();
    const auto* q = findFamilyQuirks(FamilyId::AppletSuiteGen1);
    EXPECT_EQ(derivePinStatus(appletSuiteGen1UserPin(), all, q).kind, PinKind::UserPin);
    EXPECT_EQ(derivePinStatus(appletSuiteGen1Puk(), all, q).kind, PinKind::Puk);
    EXPECT_EQ(derivePinStatus(appletSuiteGen1SignPin(), all, q).kind, PinKind::SignPin);
    EXPECT_EQ(derivePinStatus(appletSuiteGen1Can(), all, q).kind, PinKind::Can);
}

TEST(PinLifecycleDerivation, SoPinAloneIsNotAPuk)
{
    // An SO PIN that is not an unblocker and no chain target stays Unknown.
    PinEvidence e;
    e.label = "SO PIN";
    e.reference = 0x01;
    e.soPinFlag = true;
    EXPECT_EQ(derivePinStatus(e, {e}, nullptr).kind, PinKind::Unknown);
}

TEST(PinLifecycleDerivation, BareLowReferenceIsNotACan)
{
    PinEvidence e;
    e.label = "CHV1";
    e.reference = 0x02; // low ref, but no PACE evidence
    EXPECT_NE(derivePinStatus(e, {e}, nullptr).kind, PinKind::Can);
}

TEST(PinLifecycleDerivation, PaceEvidenceDoesNotOverrideAPukOrSoPin)
{
    // The CAN rule must not capture a PUK/SO-PIN that happens to carry the
    // change+unblock-disabled shape — a real PUK can be a fixed, non-changeable,
    // non-unblockable value. An unblocking authority stays Puk...
    PinEvidence puk = appletSuiteGen1Puk();
    puk.changeDisabledFlag = true; // now BOTH disabled flags present
    puk.paceEvidence = true;       // as the plugin would set on a usesPace family
    EXPECT_EQ(derivePinStatus(puk, {puk}, nullptr).kind, PinKind::Puk)
        << "an unblocking object with the PACE shape must stay Puk, not Can";

    // ...and a soPin-only object is never a CAN either (stays Unknown, the
    // conservative soPin-only default).
    PinEvidence so;
    so.label = "SO PIN";
    so.reference = 0x01;
    so.soPinFlag = true;
    so.changeDisabledFlag = true;
    so.unblockDisabledFlag = true;
    so.paceEvidence = true;
    EXPECT_NE(derivePinStatus(so, {so}, nullptr).kind, PinKind::Can);
}

TEST(PinLifecycleDerivation, UnblockableRequiresChainKnownVariantAndPresentablePuk)
{
    auto all = appletSuiteGen1All();
    // The real table deliberately advertises no verified unblock command
    // form yet, so build a synthetic family row that does — the quirks
    // aggregate is test-constructible for exactly this.
    FamilyQuirks synthetic;
    synthetic.id = FamilyId::AppletSuiteGen1;
    auto& userKind = synthetic.kinds[static_cast<std::size_t>(PinKind::UserPin)];
    userKind.rrcVariantKnown = true;
    userKind.unblockStyle = UnblockStyle::UnblockAndChange;
    const auto* q = &synthetic;

    auto user = derivePinStatus(appletSuiteGen1UserPin(), all, q);
    EXPECT_TRUE(user.unblockable);
    EXPECT_EQ(user.recovery, PinRecovery::HolderViaPuk);

    // Same card, but the PUK itself is blocked → degrade.
    all[1].blocked = true;
    auto degraded = derivePinStatus(appletSuiteGen1UserPin(), all, q);
    EXPECT_FALSE(degraded.unblockable);
    EXPECT_NE(degraded.recovery, PinRecovery::HolderViaPuk);
}

TEST(PinLifecycleDerivation, TwoUnblockerProfileResolvesTheAddressedPuk)
{
    // Two PINs, each chained to its OWN unblocker (multi-byte AODF ids):
    // the PUK-presentability rule must evaluate the PUK the chain names,
    // never merely the first unblocker in enumeration order.
    PinEvidence pinA;
    pinA.label = "PIN A";
    pinA.reference = 0x01;
    pinA.ownId = {0x40, 0x01};
    pinA.authIdChainTarget = std::vector<std::uint8_t>{0x40, 0x11};

    PinEvidence pukA;
    pukA.label = "PUK A";
    pukA.reference = 0x11;
    pukA.ownId = {0x40, 0x11};
    pukA.unblockingPinFlag = true;

    PinEvidence pinB;
    pinB.label = "PIN B";
    pinB.reference = 0x02;
    pinB.ownId = {0x40, 0x02};
    pinB.authIdChainTarget = std::vector<std::uint8_t>{0x40, 0x12};

    PinEvidence pukB;
    pukB.label = "PUK B";
    pukB.reference = 0x12;
    pukB.ownId = {0x40, 0x12};
    pukB.unblockingPinFlag = true;
    pukB.blocked = true; // NOT presentable

    const std::vector<PinEvidence> all{pinA, pukA, pinB, pukB};

    FamilyQuirks synthetic;
    synthetic.id = FamilyId::Piv;
    auto& userKind = synthetic.kinds[static_cast<std::size_t>(PinKind::UserPin)];
    userKind.rrcVariantKnown = true;
    userKind.unblockStyle = UnblockStyle::SetsNewPin;

    // PIN A's own PUK is presentable → unblock advertised.
    const auto a = derivePinStatus(pinA, all, &synthetic);
    EXPECT_TRUE(a.unblockable);
    EXPECT_EQ(a.recovery, PinRecovery::HolderViaPuk);

    // PIN B's own PUK is blocked → degrade, even though ANOTHER
    // unblocker (PUK A) is still presentable.
    const auto b = derivePinStatus(pinB, all, &synthetic);
    EXPECT_FALSE(b.unblockable);
    EXPECT_NE(b.recovery, PinRecovery::HolderViaPuk);
}

TEST(PinLifecycleDerivation, ChainTargetAbsentFromEvidenceIsNotUnblockable)
{
    // A chain naming an id that no evidence entry carries must never
    // resolve to some other unblocker.
    PinEvidence pin;
    pin.label = "PIN";
    pin.reference = 0x01;
    pin.ownId = {0x01};
    pin.authIdChainTarget = std::vector<std::uint8_t>{0x99};

    PinEvidence stranger;
    stranger.label = "PUK";
    stranger.reference = 0x11;
    stranger.ownId = {0x03};
    stranger.unblockingPinFlag = true;

    FamilyQuirks synthetic;
    synthetic.id = FamilyId::Piv;
    synthetic.kinds[static_cast<std::size_t>(PinKind::UserPin)].rrcVariantKnown = true;

    const auto s = derivePinStatus(pin, {pin, stranger}, &synthetic);
    EXPECT_FALSE(s.unblockable);
    EXPECT_NE(s.recovery, PinRecovery::HolderViaPuk);
}

TEST(PinLifecycleDerivation, UnblockDisabledFlagVetoes)
{
    auto all = appletSuiteGen1All();
    auto user = appletSuiteGen1UserPin();
    user.unblockDisabledFlag = true;
    EXPECT_FALSE(derivePinStatus(user, all, findFamilyQuirks(FamilyId::AppletSuiteGen1)).unblockable);
}

TEST(PinLifecycleDerivation, NoQuirksMeansNoUnblockAdvertised)
{
    // Chain evidence present but family unknown (no RRC variant known):
    // never advertise what we cannot execute.
    const auto all = appletSuiteGen1All();
    auto user = derivePinStatus(appletSuiteGen1UserPin(), all, nullptr);
    EXPECT_FALSE(user.unblockable);
    EXPECT_EQ(user.recovery, PinRecovery::Unknown);
}

TEST(PinLifecycleDerivation, StatePrecedenceBlockedOverTransport)
{
    PinEvidence e = appletSuiteGen1SignPin();
    e.initialized = false; // transport-born
    e.blocked = true;      // and exhausted
    const auto* q = findFamilyQuirks(FamilyId::AppletSuiteGen1);
    auto s = derivePinStatus(e, appletSuiteGen1All(), q);
    EXPECT_EQ(s.state, PinState::Blocked);
    EXPECT_FALSE(s.activatable); // not while blocked
}

// Plan D Task 11 (post-unblock classification, spec §5.1): the derivation
// needs no new code for this — it already classifies purely from the
// `initialized` evidence bit (plus the family's supportsTransportPin +
// SignPin kind), and that bit is exactly what a fresh getPINList / AODF
// re-read reports after an unblock completes. An unblock that only resets
// the retry counter (resetOnly / UnblockAndChange-without-a-new-value)
// leaves the transport value in place -> the card still reports
// initialized=false next read -> Transport, activatable=true (still needs
// activateTransportPin). An unblock that also sets a new value (setsNewPin /
// UnblockAndChange-with-a-new-value) personalizes the credential -> the card
// reports initialized=true -> Operational, activatable=false. No unblockPIN
// return path needs to special-case this: the NEXT getPINList call re-derives
// it from card evidence alone.
TEST(PinLifecycleDerivation, PostUnblockTransportVsOperationalClassification)
{
    const auto* q = findFamilyQuirks(FamilyId::AppletSuiteGen1); // supportsTransportPin=true
    ASSERT_NE(q, nullptr);

    // resetOnly-shaped unblock: counter reset only, value still transport.
    PinEvidence stillTransport = appletSuiteGen1SignPin();
    stillTransport.initialized = false;
    stillTransport.blocked = false;
    const auto transportEntry = derivePinStatus(stillTransport, appletSuiteGen1All(), q);
    EXPECT_EQ(transportEntry.state, PinState::Transport);
    EXPECT_TRUE(transportEntry.activatable);

    // setsNewPin-shaped unblock: a new value was set, credential personalized.
    PinEvidence nowOperational = appletSuiteGen1SignPin();
    nowOperational.initialized = true;
    nowOperational.blocked = false;
    const auto operationalEntry = derivePinStatus(nowOperational, appletSuiteGen1All(), q);
    EXPECT_EQ(operationalEntry.state, PinState::Operational);
    EXPECT_FALSE(operationalEntry.activatable);
}

TEST(PinLifecycleDerivation, NeedsChangeSignalPropagatesAndBlockedWins)
{
    const auto all = appletSuiteGen1All();
    const auto* q = findFamilyQuirks(FamilyId::AppletSuiteGen1);

    auto user = appletSuiteGen1UserPin();
    user.needsChangeSignal = true;
    EXPECT_EQ(derivePinStatus(user, all, q).state, PinState::NeedsChange);

    // Precedence: Blocked > NeedsChange.
    user.blocked = true;
    EXPECT_EQ(derivePinStatus(user, all, q).state, PinState::Blocked);
}

TEST(PinLifecycleDerivation, ConservativeDefaultsForUnseenCard)
{
    PinEvidence e;
    e.label = "PIN";
    auto s = derivePinStatus(e, {e}, nullptr);
    EXPECT_EQ(s.kind, PinKind::Unknown);
    EXPECT_EQ(s.recovery, PinRecovery::Unknown);
    EXPECT_FALSE(s.probeSafe);
    EXPECT_EQ(s.unblockStyle, UnblockStyle::Unknown);
}

TEST(PinLifecycleDerivation, QuirklessFamilyKeepsEvidenceOnlyChangeAdvertisement)
{
    // Families without a quirk row keep the evidence-only change
    // advertisement every plugin shipped before the derivation engine:
    // any non-PUK, non-SO credential without the change-disabled veto.
    PinEvidence user;
    user.label = "PIN1";
    user.reference = 0x01;
    EXPECT_TRUE(derivePinStatus(user, {user}, nullptr).canChange);

    PinEvidence vetoed = user;
    vetoed.changeDisabledFlag = true;
    EXPECT_FALSE(derivePinStatus(vetoed, {vetoed}, nullptr).canChange);

    PinEvidence puk = user;
    puk.unblockingPinFlag = true;
    EXPECT_FALSE(derivePinStatus(puk, {puk}, nullptr).canChange);

    PinEvidence so = user;
    so.soPinFlag = true;
    EXPECT_FALSE(derivePinStatus(so, {so}, nullptr).canChange);
}

TEST(PinLifecycleDerivation, NeedsChangeImpliesChangeOffered)
{
    // A driver-reported must-change state is the card DEMANDING a change:
    // the action must be offered whether family knowledge is absent
    // (quirkless) or the row does not vouch for change on this kind —
    // only the card's own change-disabled veto withholds it.
    PinEvidence e;
    e.label = "PIN1";
    e.reference = 0x01;
    e.needsChangeSignal = true;

    const auto quirkless = derivePinStatus(e, {e}, nullptr);
    EXPECT_EQ(quirkless.state, PinState::NeedsChange);
    EXPECT_TRUE(quirkless.canChange);

    FamilyQuirks row; // row with no change knowledge for any kind
    row.id = FamilyId::CurrentLkCardEdge;
    const auto withRow = derivePinStatus(e, {e}, &row);
    EXPECT_EQ(withRow.state, PinState::NeedsChange);
    EXPECT_TRUE(withRow.canChange);

    e.changeDisabledFlag = true; // card veto wins
    EXPECT_FALSE(derivePinStatus(e, {e}, nullptr).canChange);
}

TEST(PinLifecycleDerivation, QuirkRowStillGovernsChangeWhenPresent)
{
    // A present family row keeps precedence over the quirkless fallback:
    // no change advertised for a kind the row does not vouch for (absent
    // a driver-reported must-change demand).
    PinEvidence e;
    e.label = "PIN1";
    e.reference = 0x01;
    FamilyQuirks row;
    row.id = FamilyId::CurrentLkCardEdge; // synthetic: no UserPin change knowledge
    EXPECT_FALSE(derivePinStatus(e, {e}, &row).canChange);
}

TEST(PinLifecycleDerivation, FamilyKeyActivationGuidanceIsForwarded)
{
    // Issuer-tool-only families carry a key-activation guidance text in
    // their row; the derivation forwards it (display-only). Pending /
    // holder-activatable stay conservatively off: asserting a
    // deactivated signing key requires key or certificate state evidence
    // no plugin reads yet.
    const auto* q = findFamilyQuirks(FamilyId::AetPosta);
    ASSERT_NE(q, nullptr);
    ASSERT_TRUE(q->keyActivationGuidance.has_value());

    PinEvidence user;
    user.label = "PIN";
    user.reference = 0x03;
    const auto s = derivePinStatus(user, {user}, q);
    ASSERT_TRUE(s.keyActivationGuidance.has_value());
    EXPECT_EQ(s.keyActivationGuidance->key, q->keyActivationGuidance->key);
    EXPECT_FALSE(s.keyActivationPending);
    EXPECT_FALSE(s.keyActivatable);
}

TEST(PinLifecycleDerivation, KeyActivationGuidanceNotOnPukOrCan)
{
    // The guidance concerns the signing key a PIN guards; PUK and CAN
    // records never own a signing key, so they must not carry it.
    const auto* q = findFamilyQuirks(FamilyId::AetPosta);
    ASSERT_NE(q, nullptr);

    PinEvidence puk;
    puk.label = "PUK";
    puk.reference = 0x04;
    puk.unblockingPinFlag = true;
    EXPECT_FALSE(derivePinStatus(puk, {puk}, q).keyActivationGuidance.has_value());

    PinEvidence can;
    can.label = "CAN";
    can.reference = 0x02;
    can.changeDisabledFlag = true;
    can.unblockDisabledFlag = true;
    can.paceEvidence = true;
    EXPECT_FALSE(derivePinStatus(can, {can}, q).keyActivationGuidance.has_value());
}

// ---------------------------------------------------------------------------
// Task 11 review fix: resolveUnblockApdu — the RESET RETRY COUNTER P1 +
// on-wire data-shape decision extracted from pkcs15-plugin's unblockPIN
// override. Mirrors the classifyPinOutcome extraction precedent
// (<LibreSCRS/Plugin/PinOutcome.h>): a pure free function living beside the
// derivation engine, unit-tested directly rather than through the plugin
// funnel — the plugin-funnel route is NOT achievable here because
// resolveFamilyId/findFamilyQuirks are non-parametric static lookups (no
// production injection seam). A synthetic quirk row exercises
// rrcVariantKnown=true + each UnblockStyle WITHOUT touching the real
// AppletSuiteGen1 row (which deliberately withholds rrcVariantKnown pending
// hardware verification) and without flipping any [HW-VERIFY] flag on it.
// ---------------------------------------------------------------------------

namespace {

FamilyQuirks syntheticUnblockQuirks(UnblockStyle style, std::uint8_t p1)
{
    FamilyQuirks q;
    q.id = FamilyId::AppletSuiteGen1; // arbitrary — resolveUnblockApdu reads only rrcP1[]
    auto& user = q.kinds[static_cast<std::size_t>(PinKind::UserPin)];
    user.rrcVariantKnown = true; // mirrors the shape of a real unblockable case
    user.unblockStyle = style;
    q.rrcP1[static_cast<std::size_t>(style)] = p1;
    return q;
}

} // namespace

TEST(ResolveUnblockApdu, ResetOnlyIsPukOnlyAtTheRowsP1)
{
    const auto quirks = syntheticUnblockQuirks(UnblockStyle::ResetOnly, 0x01);
    const auto apdu = resolveUnblockApdu(UnblockStyle::ResetOnly, quirks, "12345678", "4321");
    EXPECT_EQ(apdu.p1, quirks.rrcP1[static_cast<std::size_t>(UnblockStyle::ResetOnly)]);
    EXPECT_EQ(apdu.puk, "12345678");
    EXPECT_TRUE(apdu.newPin.empty()) << "ResetOnly never sends a new PIN, even when the caller supplied one";
}

TEST(ResolveUnblockApdu, SetsNewPinIsPukPlusNewPinAtTheRowsP1)
{
    const auto quirks = syntheticUnblockQuirks(UnblockStyle::SetsNewPin, 0x02);
    const auto apdu = resolveUnblockApdu(UnblockStyle::SetsNewPin, quirks, "12345678", "4321");
    EXPECT_EQ(apdu.p1, quirks.rrcP1[static_cast<std::size_t>(UnblockStyle::SetsNewPin)]);
    EXPECT_EQ(apdu.puk, "12345678");
    EXPECT_EQ(apdu.newPin, "4321");
}

TEST(ResolveUnblockApdu, UnblockAndChangeSendsNewPinOnlyWhenCallerSuppliesOne)
{
    const auto quirks = syntheticUnblockQuirks(UnblockStyle::UnblockAndChange, 0x03);

    const auto withNewPin = resolveUnblockApdu(UnblockStyle::UnblockAndChange, quirks, "12345678", "4321");
    EXPECT_EQ(withNewPin.p1, quirks.rrcP1[static_cast<std::size_t>(UnblockStyle::UnblockAndChange)]);
    EXPECT_EQ(withNewPin.puk, "12345678");
    EXPECT_EQ(withNewPin.newPin, "4321");

    const auto resetOnlyChoice = resolveUnblockApdu(UnblockStyle::UnblockAndChange, quirks, "12345678", "");
    EXPECT_EQ(resetOnlyChoice.p1, quirks.rrcP1[static_cast<std::size_t>(UnblockStyle::UnblockAndChange)]);
    EXPECT_EQ(resetOnlyChoice.puk, "12345678");
    EXPECT_TRUE(resetOnlyChoice.newPin.empty()) << "holder chose reset-only: no new PIN supplied";
}

// ---------------------------------------------------------------------------
// Plan D Task 12 — resolveTransportChangeApdu: the CHANGE REFERENCE DATA P1
// + on-wire data-shape decision extracted from pkcs15-plugin's
// activateTransportPin override, up front this time (following the
// resolveUnblockApdu precedent immediately above rather than needing a
// review round to arrive at it). Pure function over its arguments — no
// FamilyQuirks lookup involved beyond the raw P1 byte the caller passes in,
// so these tests exercise arbitrary P1 values directly, exactly like
// resolveUnblockApdu's tests exercise arbitrary rrcP1 rows via a synthetic
// quirk row.
// ---------------------------------------------------------------------------

TEST(ResolveTransportChangeApdu, OneShotFormAtP1ZeroSendsTransportThenNew)
{
    const auto apdu = resolveTransportChangeApdu(0x00, "transport1", "4321");
    EXPECT_EQ(apdu.p1, 0x00);
    EXPECT_EQ(apdu.oldData, "transport1");
    EXPECT_EQ(apdu.newData, "4321");
}

TEST(ResolveTransportChangeApdu, PriorAuthFormAtP1OneSendsNewOnly)
{
    const auto apdu = resolveTransportChangeApdu(0x01, "transport1", "4321");
    EXPECT_EQ(apdu.p1, 0x01);
    EXPECT_TRUE(apdu.oldData.empty()) << "prior-auth form: old-data block omitted, not padded";
    EXPECT_EQ(apdu.newData, "4321");
}

TEST(ResolveTransportChangeApdu, AnyOtherP1ConservativelyBehavesAsOneShot)
{
    // Only 0x01 is the special prior-auth form; any other family-supplied
    // byte (including values ISO doesn't define) conservatively takes the
    // "send everything" one-shot shape rather than silently dropping data.
    const auto apdu = resolveTransportChangeApdu(0x02, "transport1", "4321");
    EXPECT_EQ(apdu.p1, 0x02);
    EXPECT_EQ(apdu.oldData, "transport1");
    EXPECT_EQ(apdu.newData, "4321");
}
