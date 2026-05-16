// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

/// @file
/// @brief Tests for AuthRequirement::forPaceSecret factory and its PACE
///        accessors. Verifies field shape per secret kind and that the
///        EstablishPaceChannel purpose round-trips.

#include <LibreSCRS/Auth/AuthRequirement.h>
#include <LibreSCRS/Auth/PaceSecretKind.h>
#include <LibreSCRS/LocalizedText.h>
#include <LibreSCRS/SmartCard/AppletAid.h>

#include <gtest/gtest.h>

using LibreSCRS::LocalizedText;
using LibreSCRS::Auth::AuthRequirement;
using LibreSCRS::Auth::PaceSecretKind;
using LibreSCRS::Auth::Purpose;
using LibreSCRS::SmartCard::AppletAid;

namespace {

AppletAid makeNamEmrtdAid()
{
    return AppletAid{0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01};
}

LocalizedText emptyReason()
{
    return LocalizedText{};
}

} // namespace

TEST(AuthRequirementPaceTests, PurposeIsEstablishPaceChannel)
{
    auto req = AuthRequirement::forPaceSecret(makeNamEmrtdAid(), PaceSecretKind::Can, std::nullopt, emptyReason());
    EXPECT_EQ(req.purpose(), Purpose::EstablishPaceChannel);
}

TEST(AuthRequirementPaceTests, PaceKindAndAppletPopulated)
{
    auto aid = makeNamEmrtdAid();
    auto req = AuthRequirement::forPaceSecret(aid, PaceSecretKind::Can, std::nullopt, emptyReason());
    ASSERT_TRUE(req.paceKind().has_value());
    EXPECT_EQ(*req.paceKind(), PaceSecretKind::Can);
    ASSERT_TRUE(req.paceApplet().has_value());
    EXPECT_EQ(*req.paceApplet(), aid);
}

TEST(AuthRequirementPaceTests, CanFieldShape)
{
    auto req = AuthRequirement::forPaceSecret(makeNamEmrtdAid(), PaceSecretKind::Can, std::nullopt, emptyReason());
    auto fields = req.fields();
    ASSERT_EQ(fields.size(), 1u);
    EXPECT_EQ(fields[0].id, "can");
    EXPECT_FALSE(fields[0].secret);
    ASSERT_TRUE(fields[0].minLength.has_value());
    EXPECT_EQ(*fields[0].minLength, 6u);
    ASSERT_TRUE(fields[0].maxLength.has_value());
    EXPECT_EQ(*fields[0].maxLength, 6u);
}

TEST(AuthRequirementPaceTests, MrzFieldShape)
{
    auto req = AuthRequirement::forPaceSecret(makeNamEmrtdAid(), PaceSecretKind::Mrz, std::nullopt, emptyReason());
    auto fields = req.fields();
    ASSERT_EQ(fields.size(), 1u);
    EXPECT_EQ(fields[0].id, "mrz");
    EXPECT_FALSE(fields[0].secret);
}

TEST(AuthRequirementPaceTests, PinFieldIsSecret)
{
    auto req =
        AuthRequirement::forPaceSecret(makeNamEmrtdAid(), PaceSecretKind::Pin, std::optional<int>{3}, emptyReason());
    auto fields = req.fields();
    ASSERT_EQ(fields.size(), 1u);
    EXPECT_EQ(fields[0].id, "pin");
    EXPECT_TRUE(fields[0].secret);
    ASSERT_TRUE(req.retriesLeft().has_value());
    EXPECT_EQ(*req.retriesLeft(), 3);
}

TEST(AuthRequirementPaceTests, ReasonForUserStoredAsMessage)
{
    LocalizedText reason;
    reason.defaultText = "Insert the CAN printed on the back of your ID card";
    auto req = AuthRequirement::forPaceSecret(makeNamEmrtdAid(), PaceSecretKind::Can, std::nullopt, std::move(reason));
    ASSERT_TRUE(req.message().has_value());
    EXPECT_EQ(req.message()->defaultText, "Insert the CAN printed on the back of your ID card");
}

TEST(AuthRequirementPaceTests, OtherFactoriesLeavePaceFieldsEmpty)
{
    auto req = AuthRequirement::forSigning(std::string{"PIN1"}, 3);
    EXPECT_FALSE(req.paceKind().has_value());
    EXPECT_FALSE(req.paceApplet().has_value());
}
