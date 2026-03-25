// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace euvrc {

// EU VRC data per Commission Directive 2003/127/EC
struct EuVrcData
{
    // Metadata
    std::string memberState;         // tag 9F33
    std::string version;             // tag 80
    std::string documentNumber;      // tag 9F38
    std::string competentAuthority;  // tag 9F35
    std::string issuingAuthority;    // tag 9F36
    std::string previousDocument;    // tag 9F34

    // EU mandatory (tag 71)
    std::string registrationNumber;  // A: 81
    std::string firstRegistration;   // B: 82
    std::string holderName;          // C.1.1: 83
    std::string holderOtherNames;    // C.1.2: 84
    std::string holderAddress;       // C.1.3: 85
    std::string ownershipStatus;     // C.4: 86
    std::string vehicleMake;         // D.1: 87
    std::string vehicleType;         // D.2: 88
    std::string commercialDesc;      // D.3: 89
    std::string vin;                 // E: 8A
    std::string maxLadenMass;        // F.1: 8B
    std::string vehicleMass;         // G: 8C
    std::string expiryDate;          // H: 8D
    std::string registrationDate;    // I: 8E
    std::string typeApproval;        // K: 8F
    std::string engineCapacity;      // P.1: 90
    std::string maxNetPower;         // P.2: 91
    std::string fuelType;            // P.3: 92
    std::string powerWeightRatio;    // Q: 93
    std::string numberOfSeats;       // S.1: 94
    std::string standingPlaces;      // S.2: 95

    // EU optional (tag 72)
    std::string maxLadenMassService; // F.2: 96
    std::string maxLadenMassWhole;   // F.3: 97
    std::string vehicleCategory;     // J: 98
    std::string numberOfAxles;       // L: 99
    std::string wheelbase;           // M: 9A
    std::string brakedTrailerMass;   // O.1: 9B
    std::string unbrakedTrailerMass; // O.2: 9C
    std::string ratedEngineSpeed;    // P.4: 9D
    std::string engineIdNumber;      // P.5: 9E
    std::string colour;              // R: 9F24
    std::string maxSpeed;            // T: 9F25
    std::string stationarySoundLevel;// U.1: 9F26
    std::string engineSpeedRef;      // U.2: 9F27
    std::string driveBySound;        // U.3: 9F28
    std::string fuelConsumption;     // V.7: 9F2F
    std::string co2;                 // V.7: 9F30
    std::string envCategory;         // V.9: 9F31
    std::string fuelTankCapacity;    // W: 9F32

    // Owner/User (nested containers)
    std::string owner2Name;          // C.2: A7/83
    std::string userName;            // C.3: A9/83
    std::string userOtherNames;      // C.3: A9/84
    std::string userAddress;         // C.3: A9/85

    // National extensions — generic {tag, value} pairs for tags beyond EU range
    std::vector<std::pair<uint32_t, std::string>> nationalTags;

    // Signatures & certificates (binary, not verified)
    std::vector<uint8_t> signatureA;  // E001
    std::vector<uint8_t> signatureB;  // E011
    std::vector<uint8_t> certA;       // C001
    std::vector<uint8_t> certB;       // C011
    // National extension binary files (E021/C021 etc.)
    std::vector<std::pair<uint16_t, std::vector<uint8_t>>> additionalSignatures;
    std::vector<std::pair<uint16_t, std::vector<uint8_t>>> additionalCerts;
};

} // namespace euvrc
