// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

// Narrowed BAC-fallback policy for shouldTryFallback: the fallback fires ONLY
// on the structural PaceUnsupported verdict, never on any other non-stop
// error. Falling back to BAC on an arbitrary non-stop failure is a silent
// protocol-downgrade surface — a document that genuinely advertises PACE (its
// EF.CardAccess is present) must not be quietly answered with the weaker,
// key-derived-from-the-printed-secret BAC channel just because a transient or
// wrong-secret error occurred. The one legitimate reason to downgrade is a
// document that structurally lacks PACE, which the walk reports as
// PaceUnsupported.
//
// These cases live in the top-level test/ tree so they run under the
// CI-literal `ctest --test-dir build/test` gate. (The sibling coverage in
// lib/plugin/test/ActivationProfileTests.cpp registers at the build ROOT,
// outside that gate.)

#include <LibreSCRS/Plugin/ActivationProfile.h>
#include <LibreSCRS/SecureChannel/ChannelErrors.h>

#include <gtest/gtest.h>

using LibreSCRS::Plugin::ActivationProfile;
using LibreSCRS::Plugin::shouldTryFallback;
using LibreSCRS::SecureChannel::ChannelActivationError;

namespace {

// A profile that permits the BAC fallback. shouldTryFallback only consults
// allowBacFallback and the error, so no aid / primary need be populated.
ActivationProfile fallbackAllowed()
{
    ActivationProfile p;
    p.allowBacFallback = true;
    return p;
}

} // namespace

TEST(ActivationFallbackPolicy, FallbackFiresOnlyOnPaceUnsupported)
{
    const ActivationProfile p = fallbackAllowed();

    // The one structural "this document has no PACE" verdict is the ONLY
    // error that may downgrade to BAC.
    EXPECT_TRUE(shouldTryFallback(p, ChannelActivationError::PaceUnsupported));

    // Every other non-stop error keeps the walk on the credential the caller
    // asked for; falling back here would be a silent protocol downgrade.
    EXPECT_FALSE(shouldTryFallback(p, ChannelActivationError::PaceWrongSecret));
    EXPECT_FALSE(shouldTryFallback(p, ChannelActivationError::PaceProtocolFailure));
    EXPECT_FALSE(shouldTryFallback(p, ChannelActivationError::SelectAppletFailed));
    EXPECT_FALSE(shouldTryFallback(p, ChannelActivationError::Internal));
    EXPECT_FALSE(shouldTryFallback(p, ChannelActivationError::CredentialsRequired));

    // Security-critical: a DETECTED downgrade must NEVER be answered by
    // falling back to the very protocol the attacker forced.
    EXPECT_FALSE(shouldTryFallback(p, ChannelActivationError::PaceDowngradeDetected));
}

TEST(ActivationFallbackPolicy, FallbackNeverFiresWhenDisallowed)
{
    ActivationProfile p = fallbackAllowed();
    p.allowBacFallback = false;

    for (const auto e : {ChannelActivationError::None, ChannelActivationError::SelectAppletFailed,
                         ChannelActivationError::PaceWrongSecret, ChannelActivationError::PacePinBlocked,
                         ChannelActivationError::PaceProtocolFailure, ChannelActivationError::PaceUnsupported,
                         ChannelActivationError::UserCancelled, ChannelActivationError::Cancelled,
                         ChannelActivationError::CardRemoved, ChannelActivationError::ReaderError,
                         ChannelActivationError::CredentialsRequired, ChannelActivationError::Internal,
                         ChannelActivationError::ReentrantAccess, ChannelActivationError::PaceDowngradeDetected}) {
        EXPECT_FALSE(shouldTryFallback(p, e));
    }
}

TEST(ActivationFallbackPolicy, StopErrorsNeverFallBack)
{
    const ActivationProfile p = fallbackAllowed(); // allowBacFallback == true

    // Stop errors abort the walk unconditionally, even with the flag set.
    EXPECT_FALSE(shouldTryFallback(p, ChannelActivationError::Cancelled));
    EXPECT_FALSE(shouldTryFallback(p, ChannelActivationError::UserCancelled));
    EXPECT_FALSE(shouldTryFallback(p, ChannelActivationError::CardRemoved));
}
