// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include <LibreSCRS/Plugin/PluginTypes.h>
#include <gtest/gtest.h>

using namespace LibreSCRS::Plugin;

TEST(DecipherTypes, OkPredicateMatchesOutcome)
{
    DecipherResult r;
    EXPECT_FALSE(r.ok()); // default Unspecified
    r.outcome = DecipherResultOutcome::Ok;
    EXPECT_TRUE(r.ok());
    r.outcome = DecipherResultOutcome::PluginError;
    EXPECT_FALSE(r.ok());
}

TEST(DecipherTypes, RsaPkcs1V15IsTheOnlyMechanismThisRelease)
{
    // No card this release advertises OAEP, so the enum carries only the
    // PKCS#1 v1.5 mechanism; OAEP is reserved for a card that advertises it.
    EXPECT_EQ(static_cast<int>(DecipherMechanism::RSA_PKCS1_V15), 0);
}
