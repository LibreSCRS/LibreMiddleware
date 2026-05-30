// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include <LibreSCRS/Plugin/ActivationProfile.h>
#include <LibreSCRS/Auth/PaceSecretKind.h>
#include <gtest/gtest.h>

#include <array>
#include <cstdint>

using LibreSCRS::Auth::PaceSecretKind;
using LibreSCRS::Plugin::ActivationProfile;
using LibreSCRS::SmartCard::AppletAid;
using LibreSCRS::SmartCard::PaceRequest;
using LibreSCRS::SmartCard::SmProtocolRequest;

TEST(ActivationProfileTest, PlainRequiresNoActivation)
{
    auto p = ActivationProfile::plain();
    EXPECT_FALSE(p.requiresActivation());
    EXPECT_FALSE(p.aid.has_value());
    EXPECT_FALSE(p.allowBacFallback);
}

TEST(ActivationProfileTest, PaceCanProfileRequiresActivation)
{
    ActivationProfile p;
    p.aid = AppletAid::fromBytes(std::array<std::uint8_t, 1>{0xA0});
    p.primary = SmProtocolRequest{PaceRequest{PaceSecretKind::Can}};
    EXPECT_TRUE(p.requiresActivation());
    EXPECT_FALSE(p.allowBacFallback);
}

#include <LibreSCRS/SecureChannel/ChannelErrors.h>
using LibreSCRS::Plugin::isStopError;
using LibreSCRS::Plugin::shouldTryFallback;
using LibreSCRS::SecureChannel::ChannelActivationError;

TEST(StopErrorTest, StopSetIsExactlyCancelUserCancelCardRemoved)
{
    EXPECT_TRUE(isStopError(ChannelActivationError::Cancelled));
    EXPECT_TRUE(isStopError(ChannelActivationError::UserCancelled));
    EXPECT_TRUE(isStopError(ChannelActivationError::CardRemoved));
    EXPECT_FALSE(isStopError(ChannelActivationError::PaceWrongSecret));
    EXPECT_FALSE(isStopError(ChannelActivationError::CredentialsRequired));
    EXPECT_FALSE(isStopError(ChannelActivationError::SelectAppletFailed));
    EXPECT_FALSE(isStopError(ChannelActivationError::Internal));
}

TEST(ShouldTryFallbackTest, OnlyWhenAllowedAndNotStop)
{
    ActivationProfile withFallback;
    withFallback.aid = AppletAid::fromBytes(std::array<std::uint8_t, 1>{0xA0});
    withFallback.allowBacFallback = true;
    ActivationProfile noFallback = withFallback;
    noFallback.allowBacFallback = false;

    EXPECT_TRUE(shouldTryFallback(withFallback, ChannelActivationError::PaceWrongSecret));
    EXPECT_TRUE(shouldTryFallback(withFallback, ChannelActivationError::CredentialsRequired));
    EXPECT_FALSE(shouldTryFallback(withFallback, ChannelActivationError::UserCancelled));
    EXPECT_FALSE(shouldTryFallback(noFallback, ChannelActivationError::PaceWrongSecret));
}
