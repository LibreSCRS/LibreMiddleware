// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright hirashix0@proton.me

#include <gtest/gtest.h>
#include <vehiclecard/vehicletypes.h>

using namespace vehiclecard;

TEST(VehicleTypesTest, DefaultConstruction) {
    VehicleDocumentData vd;
    EXPECT_TRUE(vd.registrationNumber.empty());
    EXPECT_TRUE(vd.vehicleIdNumber.empty());
    EXPECT_TRUE(vd.vehicleMake.empty());
    EXPECT_TRUE(vd.vehicleType.empty());
    EXPECT_TRUE(vd.commercialDescription.empty());
    EXPECT_TRUE(vd.vehicleCategory.empty());
    EXPECT_TRUE(vd.colourOfVehicle.empty());
    EXPECT_TRUE(vd.yearOfProduction.empty());
    EXPECT_TRUE(vd.engineIdNumber.empty());
    EXPECT_TRUE(vd.ownersSurnameOrBusinessName.empty());
    EXPECT_TRUE(vd.serialNumber.empty());
}

TEST(VehicleTypesTest, FieldAssignment) {
    VehicleDocumentData vd;
    vd.registrationNumber = "BG-123-AB";
    vd.vehicleMake = "Zastava";
    vd.vehicleType = "Yugo 45";
    vd.yearOfProduction = "1985";
    vd.colourOfVehicle = "Crvena";

    EXPECT_EQ(vd.registrationNumber, "BG-123-AB");
    EXPECT_EQ(vd.vehicleMake, "Zastava");
    EXPECT_EQ(vd.vehicleType, "Yugo 45");
    EXPECT_EQ(vd.yearOfProduction, "1985");
    EXPECT_EQ(vd.colourOfVehicle, "Crvena");
}

TEST(VehicleTypesTest, OwnerFields) {
    VehicleDocumentData vd;
    vd.ownersSurnameOrBusinessName = "Jovanović";
    vd.ownerName = "Milan";
    vd.ownerAddress = "Knez Mihailova 1, Beograd";
    vd.ownersPersonalNo = "0101985710123";

    EXPECT_EQ(vd.ownersSurnameOrBusinessName, "Jovanović");
    EXPECT_EQ(vd.ownerName, "Milan");
    EXPECT_EQ(vd.ownerAddress, "Knez Mihailova 1, Beograd");
    EXPECT_EQ(vd.ownersPersonalNo, "0101985710123");
}

TEST(VehicleTypesTest, MassFields) {
    VehicleDocumentData vd;
    vd.vehicleMass = "850";
    vd.maximumPermissibleLadenMass = "1250";
    vd.vehicleLoad = "400";

    EXPECT_EQ(vd.vehicleMass, "850");
    EXPECT_EQ(vd.maximumPermissibleLadenMass, "1250");
    EXPECT_EQ(vd.vehicleLoad, "400");
}
