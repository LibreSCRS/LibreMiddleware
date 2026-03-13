// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright hirashix0@proton.me

#ifndef VEHICLECARD_VEHICLETYPES_H
#define VEHICLECARD_VEHICLETYPES_H

#include <string>

namespace vehiclecard {

struct VehicleDocumentData
{
    // Registration
    std::string registrationNumber;
    std::string dateOfFirstRegistration;

    // Vehicle
    std::string vehicleIdNumber;
    std::string vehicleMake;
    std::string vehicleType;
    std::string commercialDescription;
    std::string vehicleCategory;
    std::string colourOfVehicle;
    std::string yearOfProduction;

    // Engine
    std::string engineIdNumber;
    std::string engineCapacity;
    std::string maximumNetPower;
    std::string typeOfFuel;

    // Mass
    std::string vehicleMass;
    std::string maximumPermissibleLadenMass;
    std::string vehicleLoad;
    std::string powerWeightRatio;
    std::string numberOfAxles;

    // Capacity
    std::string numberOfSeats;
    std::string numberOfStandingPlaces;

    // Document
    std::string expiryDate;
    std::string issuingDate;
    std::string typeApprovalNumber;
    std::string stateIssuing;
    std::string competentAuthority;
    std::string authorityIssuing;
    std::string unambiguousNumber;
    std::string serialNumber;

    // Owner
    std::string ownersSurnameOrBusinessName;
    std::string ownerName;
    std::string ownerAddress;
    std::string ownersPersonalNo;

    // User
    std::string usersSurnameOrBusinessName;
    std::string usersName;
    std::string usersAddress;
    std::string usersPersonalNo;
};

} // namespace vehiclecard

#endif // VEHICLECARD_VEHICLETYPES_H
