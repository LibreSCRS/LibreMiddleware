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

// A plugin built against an older header must never receive a value it knew
// under another meaning: RSA_PKCS1_V15 keeps 0, and ECDH_RAW follows it.
TEST(DecipherTypes, MechanismsAreAppendOnly)
{
    EXPECT_EQ(static_cast<int>(DecipherMechanism::RSA_PKCS1_V15), 0);
    EXPECT_EQ(static_cast<int>(DecipherMechanism::ECDH_RAW), 1);
}

// A host advertises key agreement from this flag, so a plugin that says
// nothing must not read as offering it.
TEST(DecipherTypes, CanDeriveIsOffUntilAPluginSetsIt)
{
    CertificateData cd{};
    EXPECT_FALSE(cd.canDerive);
}
