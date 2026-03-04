// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright hirashix0@proton.me

#include <gtest/gtest.h>
#include "healthcard/healthtypes.h"

// Type-level sanity tests — no card required

TEST(HealthDocumentData, DefaultConstruct)
{
    healthcard::HealthDocumentData d;
    EXPECT_TRUE(d.insurerName.empty());
    EXPECT_TRUE(d.personalNumber.empty());
    EXPECT_FALSE(d.permanentlyValid);
    EXPECT_FALSE(d.carrierFamilyMember);
}

TEST(HealthDocumentData, FieldAssignment)
{
    healthcard::HealthDocumentData d;
    d.insurerName     = "РЗЗО";
    d.cardId          = "1234567890";
    d.dateOfBirth     = "01.01.1990";
    d.permanentlyValid = true;
    d.carrierFamilyMember = true;

    EXPECT_EQ(d.insurerName, "РЗЗО");
    EXPECT_EQ(d.cardId, "1234567890");
    EXPECT_EQ(d.dateOfBirth, "01.01.1990");
    EXPECT_TRUE(d.permanentlyValid);
    EXPECT_TRUE(d.carrierFamilyMember);
}
