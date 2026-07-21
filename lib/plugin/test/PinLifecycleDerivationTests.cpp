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

// Suite-1 card AODF facts (hardware-scanned 2026-07-18).
PinEvidence suite1UserPin()
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
PinEvidence suite1Puk()
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
PinEvidence suite1SignPin()
{
    PinEvidence e;
    e.label = "Signature PIN";
    e.reference = 0x92;
    e.localScope = true;
    e.inQscdDf = true;
    e.initialized = true;
    return e;
}
PinEvidence suite1Can()
{
    PinEvidence e;
    e.label = "PACE CAN";
    e.reference = 0x02;
    e.changeDisabledFlag = true;
    e.unblockDisabledFlag = true;
    e.paceEvidence = true;
    return e;
}
std::vector<PinEvidence> suite1All()
{
    return {suite1UserPin(), suite1Puk(), suite1SignPin(), suite1Can()};
}

} // namespace

TEST(PinLifecycleDerivation, Suite1KindClassification)
{
    const auto all = suite1All();
    const auto* q = findFamilyQuirks(FamilyId::VeridosAppletSuite1);
    EXPECT_EQ(derivePinStatus(suite1UserPin(), all, q).kind, PinKind::UserPin);
    EXPECT_EQ(derivePinStatus(suite1Puk(), all, q).kind, PinKind::Puk);
    EXPECT_EQ(derivePinStatus(suite1SignPin(), all, q).kind, PinKind::SignPin);
    EXPECT_EQ(derivePinStatus(suite1Can(), all, q).kind, PinKind::Can);
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

TEST(PinLifecycleDerivation, UnblockableRequiresChainKnownVariantAndPresentablePuk)
{
    auto all = suite1All();
    // The real table deliberately advertises no verified unblock command
    // form yet, so build a synthetic family row that does — the quirks
    // aggregate is test-constructible for exactly this.
    FamilyQuirks synthetic;
    synthetic.id = FamilyId::VeridosAppletSuite1;
    auto& userKind = synthetic.kinds[static_cast<std::size_t>(PinKind::UserPin)];
    userKind.rrcVariantKnown = true;
    userKind.unblockStyle = UnblockStyle::UnblockAndChange;
    const auto* q = &synthetic;

    auto user = derivePinStatus(suite1UserPin(), all, q);
    EXPECT_TRUE(user.unblockable);
    EXPECT_EQ(user.recovery, PinRecovery::HolderViaPuk);

    // Same card, but the PUK itself is blocked → degrade.
    all[1].blocked = true;
    auto degraded = derivePinStatus(suite1UserPin(), all, q);
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
    auto all = suite1All();
    auto user = suite1UserPin();
    user.unblockDisabledFlag = true;
    EXPECT_FALSE(derivePinStatus(user, all, findFamilyQuirks(FamilyId::VeridosAppletSuite1)).unblockable);
}

TEST(PinLifecycleDerivation, NoQuirksMeansNoUnblockAdvertised)
{
    // Chain evidence present but family unknown (no RRC variant known):
    // never advertise what we cannot execute.
    const auto all = suite1All();
    auto user = derivePinStatus(suite1UserPin(), all, nullptr);
    EXPECT_FALSE(user.unblockable);
    EXPECT_EQ(user.recovery, PinRecovery::Unknown);
}

TEST(PinLifecycleDerivation, StatePrecedenceBlockedOverTransport)
{
    PinEvidence e = suite1SignPin();
    e.initialized = false; // transport-born
    e.blocked = true;      // and exhausted
    const auto* q = findFamilyQuirks(FamilyId::VeridosAppletSuite1);
    auto s = derivePinStatus(e, suite1All(), q);
    EXPECT_EQ(s.state, PinState::Blocked);
    EXPECT_FALSE(s.activatable); // not while blocked
}

TEST(PinLifecycleDerivation, NeedsChangeSignalPropagatesAndBlockedWins)
{
    const auto all = suite1All();
    const auto* q = findFamilyQuirks(FamilyId::VeridosAppletSuite1);

    auto user = suite1UserPin();
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
