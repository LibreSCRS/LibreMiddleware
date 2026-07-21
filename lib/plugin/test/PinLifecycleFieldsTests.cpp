// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <LibreSCRS/Plugin/PinStatusEntry.h>
#include <LibreSCRS/Plugin/PluginTypes.h>

#include <gtest/gtest.h>

using namespace LibreSCRS::Plugin;

TEST(PinLifecycleFields, DefaultsAreConservative)
{
    PinStatusEntry e;
    EXPECT_EQ(e.kind, PinKind::Unknown);
    EXPECT_EQ(e.state, PinState::Unknown);
    EXPECT_FALSE(e.retriesMax.has_value());
    EXPECT_FALSE(e.usesLeft.has_value());
    EXPECT_FALSE(e.unblocksLeft.has_value());
    EXPECT_EQ(e.unblockStyle, UnblockStyle::Unknown);
    EXPECT_FALSE(e.activatable);
    EXPECT_FALSE(e.keyActivationPending);
    EXPECT_FALSE(e.keyActivatable);
    EXPECT_EQ(e.recovery, PinRecovery::Unknown);
    EXPECT_FALSE(e.probeSafe);
    EXPECT_FALSE(e.keyActivationGuidance.has_value());
}

TEST(PinLifecycleFields, EqualityCoversNewFields)
{
    PinStatusEntry a;
    PinStatusEntry b;
    EXPECT_EQ(a, b);
    b.kind = PinKind::Puk;
    EXPECT_NE(a, b);
    b = a;
    b.usesLeft = 20;
    EXPECT_NE(a, b);
}

TEST(PinLifecycleFields, EnumFirstValueIsUnknown)
{
    // Conservative-default convention: value 0 == Unknown for every
    // lifecycle enum, so a zero-initialized record never overclaims.
    EXPECT_EQ(static_cast<int>(PinKind::Unknown), 0);
    EXPECT_EQ(static_cast<int>(PinState::Unknown), 0);
    EXPECT_EQ(static_cast<int>(UnblockStyle::Unknown), 0);
    EXPECT_EQ(static_cast<int>(PinRecovery::Unknown), 0);
}

TEST(PinLifecycleFields, KeyActivationFailedIsAppendedAfterUnsupported)
{
    EXPECT_GT(static_cast<int>(LibreSCRS::Plugin::PINResultOutcome::KeyActivationFailed),
              static_cast<int>(LibreSCRS::Plugin::PINResultOutcome::Unsupported));
}
