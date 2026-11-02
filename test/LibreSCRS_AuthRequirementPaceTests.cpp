// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

/// @file
/// @brief Tests for AuthRequirement::forPaceSecret factory and its PACE
///        accessors. Verifies field shape per secret kind and that the
///        EstablishPaceChannel purpose round-trips.

#include <LibreSCRS/Auth/AuthRequirement.h>
#include <LibreSCRS/Auth/PaceSecretKind.h>
#include <LibreSCRS/LocalizedText.h>

#include <gtest/gtest.h>

using LibreSCRS::LocalizedText;
using LibreSCRS::Auth::AuthRequirement;
using LibreSCRS::Auth::PaceSecretKind;
using LibreSCRS::Auth::Purpose;

namespace {

LocalizedText emptyReason()
{
    return LocalizedText{};
}

} // namespace

TEST(AuthRequirementPaceTests, PurposeIsEstablishPaceChannel)
{
    auto req = AuthRequirement::forPaceSecret(PaceSecretKind::Can, emptyReason());
    EXPECT_EQ(req.purpose(), Purpose::EstablishPaceChannel);
}

TEST(AuthRequirementPaceTests, PaceKindPopulated)
{
    auto req = AuthRequirement::forPaceSecret(PaceSecretKind::Can, emptyReason());
    ASSERT_TRUE(req.paceKind().has_value());
    EXPECT_EQ(*req.paceKind(), PaceSecretKind::Can);
}

TEST(AuthRequirementPaceTests, CanFieldShape)
{
    auto req = AuthRequirement::forPaceSecret(PaceSecretKind::Can, emptyReason());
    auto fields = req.fields();
    ASSERT_EQ(fields.size(), 1u);
    ASSERT_TRUE(fields[0].minLength.has_value());
    EXPECT_EQ(*fields[0].minLength, 6u);
    ASSERT_TRUE(fields[0].maxLength.has_value());
    EXPECT_EQ(*fields[0].maxLength, 6u);
}

TEST(AuthRequirementPaceTests, MrzFieldIsUnbounded)
{
    auto req = AuthRequirement::forPaceSecret(PaceSecretKind::Mrz, emptyReason());
    auto fields = req.fields();
    ASSERT_EQ(fields.size(), 1u);
    EXPECT_FALSE(fields[0].minLength.has_value());
    EXPECT_FALSE(fields[0].maxLength.has_value());
}

TEST(AuthRequirementPaceTests, PinFieldBounds)
{
    auto req = AuthRequirement::forPaceSecret(PaceSecretKind::Pin, emptyReason());
    auto fields = req.fields();
    ASSERT_EQ(fields.size(), 1u);
    ASSERT_TRUE(fields[0].minLength.has_value());
    EXPECT_EQ(*fields[0].minLength, 4u);
    ASSERT_TRUE(fields[0].maxLength.has_value());
    EXPECT_EQ(*fields[0].maxLength, 12u);
}

TEST(AuthRequirementPaceTests, ReasonForUserStoredAsMessage)
{
    LocalizedText reason;
    reason.defaultText = "Insert the CAN printed on the back of your ID card";
    auto req = AuthRequirement::forPaceSecret(PaceSecretKind::Can, std::move(reason));
    ASSERT_TRUE(req.message().has_value());
    EXPECT_EQ(req.message()->defaultText, "Insert the CAN printed on the back of your ID card");
}

TEST(AuthRequirementPaceTests, OtherFactoriesLeavePaceFieldsEmpty)
{
    auto req = AuthRequirement::forSigning();
    EXPECT_FALSE(req.paceKind().has_value());
}
