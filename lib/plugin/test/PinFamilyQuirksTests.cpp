// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "pin_family_quirks.h"

#include <LibreSCRS/Plugin/PinStatusEntry.h>

#include <gtest/gtest.h>

using LibreSCRS::Plugin::PinKind;
using LibreSCRS::Plugin::PinRecovery;
using LibreSCRS::Plugin::UnblockStyle;
using LibreSCRS::Plugin::Internal::FamilyId;
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
    for (auto id : {FamilyId::CurrentLkCardEdge, FamilyId::VeridosAppletSuite1, FamilyId::VeridosAppletSuite2,
                    FamilyId::AetPosta}) {
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
    const auto* q = findFamilyQuirks(FamilyId::VeridosAppletSuite2);
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
