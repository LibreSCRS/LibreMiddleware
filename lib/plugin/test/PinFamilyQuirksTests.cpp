// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "pin_family_quirks.h"

#include <LibreSCRS/Plugin/PinStatusEntry.h>

#include <gtest/gtest.h>

using LibreSCRS::Plugin::PinKind;
using LibreSCRS::Plugin::PinRecovery;
using LibreSCRS::Plugin::UnblockStyle;
using LibreSCRS::Plugin::Internal::FamilyId;
using LibreSCRS::Plugin::Internal::FamilyQuirks;
using LibreSCRS::Plugin::Internal::findFamilyQuirks;

TEST(PinFamilyQuirks, CurrentLkBlockedIsIssuerProcess)
{
    const auto* q = findFamilyQuirks(FamilyId::CurrentLkCardEdge);
    ASSERT_NE(q, nullptr);
    EXPECT_EQ(q->blockedRecovery(PinKind::UserPin), PinRecovery::IssuerProcess);
    EXPECT_TRUE(q->blockedGuidance(PinKind::UserPin).has_value());
}

TEST(PinFamilyQuirks, PivPukExhaustionIsTerminal)
{
    const auto* q = findFamilyQuirks(FamilyId::Piv);
    ASSERT_NE(q, nullptr);
    EXPECT_EQ(q->blockedRecovery(PinKind::Puk), PinRecovery::None);
    EXPECT_EQ(q->unblockStyle(PinKind::UserPin), UnblockStyle::SetsNewPin);
}

TEST(PinFamilyQuirks, UnknownFamilyHasNoRow)
{
    EXPECT_EQ(findFamilyQuirks(FamilyId::Unknown), nullptr);
}

TEST(PinFamilyQuirks, NoFamilyAdvertisesUnverifiedRrc)
{
    for (auto id :
         {FamilyId::CurrentLkCardEdge, FamilyId::AppletSuiteGen1, FamilyId::AppletSuiteGen2, FamilyId::AetPosta}) {
        const auto* q = findFamilyQuirks(id);
        ASSERT_NE(q, nullptr);
        EXPECT_FALSE(q->rrcVariantKnown(PinKind::UserPin));
        EXPECT_FALSE(q->rrcVariantKnown(PinKind::SignPin));
    }
}

TEST(PinFamilyQuirks, SecondSuiteStaysProbeUnsafeUntilVerified)
{
    // Every command-form fact for the second applet-suite generation —
    // including counter-probe safety — is unverified until the dedicated
    // driver track lands. An unverified probe could consume retry/usage
    // budget, so the gate must stay shut.
    const auto* q = findFamilyQuirks(FamilyId::AppletSuiteGen2);
    ASSERT_NE(q, nullptr);
    EXPECT_FALSE(q->probeSafe);
}

TEST(PinFamilyQuirks, IssuerToolFamilyCarriesKeyActivationGuidance)
{
    // The issuer-tool-only family row carries the display-only guidance
    // the derivation forwards; counter safety stays unverified.
    const auto* q = findFamilyQuirks(FamilyId::AetPosta);
    ASSERT_NE(q, nullptr);
    EXPECT_TRUE(q->keyActivationGuidance.has_value());
    EXPECT_FALSE(q->probeSafe);
}

TEST(PinFamilyQuirks, PaceFamiliesFlagUsesPace)
{
    // The CAN classifier needs an interface-independent "this card uses PACE"
    // signal so a CAN is recognised on the contact interface too. It is set
    // only for the PACE-capable applet suites; every other family (and the
    // no-row Unknown) must leave it false so a fixed service PIN on a
    // non-PACE card is never promoted to a CAN.
    const auto* s1 = findFamilyQuirks(FamilyId::AppletSuiteGen1);
    const auto* s2 = findFamilyQuirks(FamilyId::AppletSuiteGen2);
    ASSERT_NE(s1, nullptr);
    ASSERT_NE(s2, nullptr);
    EXPECT_TRUE(s1->usesPace);
    EXPECT_TRUE(s2->usesPace);

    for (auto id : {FamilyId::CurrentLkCardEdge, FamilyId::Piv, FamilyId::AetPosta}) {
        const auto* q = findFamilyQuirks(id);
        ASSERT_NE(q, nullptr);
        EXPECT_FALSE(q->usesPace) << "non-PACE family must not set usesPace";
    }
}

TEST(PinFamilyQuirks, AppletSuiteGenerationsCarryIsoExecutionDefaults)
{
    // Both applet-suite generations share the same ISO command-form
    // defaults for the card verbs the credential-lifecycle derivation will
    // eventually issue (RESET RETRY COUNTER / CHANGE REFERENCE DATA /
    // ACTIVATE). These are [HW-VERIFY] placeholders, not confirmed
    // per-family behaviour; a later hardware campaign may flip them.
    for (auto id : {FamilyId::AppletSuiteGen1, FamilyId::AppletSuiteGen2}) {
        const auto* q = findFamilyQuirks(id);
        ASSERT_NE(q, nullptr);

        EXPECT_EQ(q->rrcP1[static_cast<std::size_t>(UnblockStyle::Unknown)], 0x00);
        EXPECT_EQ(q->rrcP1[static_cast<std::size_t>(UnblockStyle::ResetOnly)], 0x01);
        EXPECT_EQ(q->rrcP1[static_cast<std::size_t>(UnblockStyle::SetsNewPin)], 0x00);
        EXPECT_EQ(q->rrcP1[static_cast<std::size_t>(UnblockStyle::UnblockAndChange)], 0x00);

        EXPECT_EQ(q->transportChangeP1, 0x00);

        EXPECT_EQ(q->keyActivate.ins, 0x44);
        EXPECT_EQ(q->keyActivate.p1, 0x00);
        EXPECT_EQ(q->keyActivate.p2, 0x00);

        EXPECT_EQ(q->secStateClear, FamilyQuirks::SecStateClear::ReselectApplet);
    }
}
