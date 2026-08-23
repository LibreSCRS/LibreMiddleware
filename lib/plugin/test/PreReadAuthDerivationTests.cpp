// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

/// @file
/// @brief Unit tests for @ref LibreSCRS::Plugin::CardPlugin::preReadAuth's
///        derivation from the plugin-published @ref
///        LibreSCRS::Plugin::ActivationProfile.
///
/// @c preReadAuth is no longer an independently-stored value: the base class
/// derives the pre-read unlock method from the profile a plugin returns from
/// @ref LibreSCRS::Plugin::CardPlugin::activationProfile. A plain profile (no
/// activation) yields @c None; a PACE-CAN profile yields @c Can; any other
/// activating profile yields @c Mrz. This test pins those mappings via a
/// minimal concrete plugin that overrides only the pure virtuals plus
/// @c activationProfile.
///
/// @c makeDetachedCardSession is the LM-internal test factory pulled in via the
/// internal-build-guarded injection header; the @c LIBRESCRS_INTERNAL_BUILD
/// define and the @c LibreSCRS_SmartCard_TestHelpers archive (which provides
/// the factory definition) are wired in the matching CMakeLists.

#include <LibreSCRS/Auth/AuthRequirement.h>
#include <LibreSCRS/Auth/PaceSecretKind.h>
#include <LibreSCRS/Plugin/ActivationProfile.h>
#include <LibreSCRS/Plugin/CardPlugin.h>
#include <LibreSCRS/SmartCard/CardSession.h>
#include <LibreSCRS/SmartCard/detail/CardSessionInjection.h>

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <utility>

namespace {

/// @brief Minimal concrete @ref LibreSCRS::Plugin::CardPlugin that returns a
///        fixed @ref LibreSCRS::Plugin::ActivationProfile so the base-class
///        @c preReadAuth derivation can be observed in isolation.
class FakeProfilePlugin final : public LibreSCRS::Plugin::CardPlugin
{
public:
    explicit FakeProfilePlugin(LibreSCRS::Plugin::ActivationProfile profile) : m_profile(std::move(profile))
    {
        setIdentity("fake", "Fake", 0);
    }

    LibreSCRS::Plugin::CardCapabilities capabilities() const override
    {
        return {};
    }

    std::span<const LibreSCRS::Plugin::Atr> supportedAtrs() const noexcept override
    {
        return {};
    }

protected:
    LibreSCRS::Plugin::ActivationProfile
    activationProfile(LibreSCRS::SmartCard::CardSession& /*session*/) const override
    {
        return m_profile;
    }

    LibreSCRS::Plugin::ReadResult doReadCard(LibreSCRS::SmartCard::CardSession& /*session*/,
                                             GroupCallback /*onGroup*/) const override
    {
        return LibreSCRS::Plugin::ReadResult::ok({});
    }

private:
    LibreSCRS::Plugin::ActivationProfile m_profile;
};

} // namespace

TEST(PreReadAuthDerivationTest, PlainProfileYieldsNone)
{
    FakeProfilePlugin plugin{LibreSCRS::Plugin::ActivationProfile::plain()};
    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("test-reader");
    ASSERT_NE(session, nullptr);
    EXPECT_EQ(plugin.preReadAuth(*session), LibreSCRS::Auth::PreReadAuthMethod::None);
}

TEST(PreReadAuthDerivationTest, CanProfileYieldsCan)
{
    LibreSCRS::Plugin::ActivationProfile profile;
    profile.aid = LibreSCRS::SmartCard::AppletAid::fromBytes(std::array<std::uint8_t, 1>{0xA0});
    profile.primary = LibreSCRS::SmartCard::SmProtocolRequest{
        LibreSCRS::SmartCard::PaceRequest{LibreSCRS::Auth::PaceSecretKind::Can}};

    FakeProfilePlugin plugin{std::move(profile)};
    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("test-reader");
    ASSERT_NE(session, nullptr);
    EXPECT_EQ(plugin.preReadAuth(*session), LibreSCRS::Auth::PreReadAuthMethod::Can);
}

TEST(PreReadAuthDerivationTest, PaceMrzProfileYieldsMrz)
{
    LibreSCRS::Plugin::ActivationProfile profile;
    profile.aid = LibreSCRS::SmartCard::AppletAid::fromBytes(std::array<std::uint8_t, 1>{0xA0});
    profile.primary = LibreSCRS::SmartCard::SmProtocolRequest{
        LibreSCRS::SmartCard::PaceRequest{LibreSCRS::Auth::PaceSecretKind::Mrz}};

    FakeProfilePlugin plugin{std::move(profile)};
    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("test-reader");
    ASSERT_NE(session, nullptr);
    EXPECT_EQ(plugin.preReadAuth(*session), LibreSCRS::Auth::PreReadAuthMethod::Mrz);
}

TEST(PreReadAuthDerivationTest, BacProfileYieldsMrz)
{
    LibreSCRS::Plugin::ActivationProfile profile;
    profile.aid = LibreSCRS::SmartCard::AppletAid::fromBytes(std::array<std::uint8_t, 1>{0xA0});
    profile.primary = LibreSCRS::SmartCard::SmProtocolRequest{LibreSCRS::SmartCard::BacRequest{}};

    FakeProfilePlugin plugin{std::move(profile)};
    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("test-reader");
    ASSERT_NE(session, nullptr);
    EXPECT_EQ(plugin.preReadAuth(*session), LibreSCRS::Auth::PreReadAuthMethod::Mrz);
}

TEST(PreReadAuthDerivationTest, ChipAuthProfileYieldsNone)
{
    // A ChipAuthRequest profile reuses an already-proven live tunnel; there is
    // no user secret to collect, so the truthful pre-read answer is None —
    // falling through to the Mrz default would promise a prompt that never
    // comes.
    LibreSCRS::Plugin::ActivationProfile profile;
    profile.aid = LibreSCRS::SmartCard::AppletAid::fromBytes(std::array<std::uint8_t, 1>{0xA0});
    profile.primary = LibreSCRS::SmartCard::SmProtocolRequest{LibreSCRS::SmartCard::ChipAuthRequest{}};

    FakeProfilePlugin plugin{std::move(profile)};
    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("test-reader");
    ASSERT_NE(session, nullptr);
    EXPECT_EQ(plugin.preReadAuth(*session), LibreSCRS::Auth::PreReadAuthMethod::None);
}
