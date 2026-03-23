// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright hirashix0@proton.me

#pragma once

#include <string>

namespace healthcard {

struct HealthDocumentData
{
    // Document file
    std::string insurerName;
    std::string insurerId;
    std::string cardId;
    std::string dateOfIssue;  // DD.MM.YYYY
    std::string dateOfExpiry; // DD.MM.YYYY
    std::string printLanguage;

    // Fixed personal
    std::string insurantNumber; // LBO
    std::string familyName;     // Cyrillic
    std::string familyNameLatin;
    std::string givenName; // Cyrillic
    std::string givenNameLatin;
    std::string dateOfBirth; // DD.MM.YYYY

    // Variable personal
    std::string validUntil; // DD.MM.YYYY
    bool permanentlyValid = false;

    // Variable admin
    std::string parentName;
    std::string parentNameLatin;
    std::string gender;         // "Мушко" / "Женско"
    std::string personalNumber; // JMBG
    std::string street;
    std::string municipality;
    std::string place;
    std::string addressNumber;
    std::string apartment;
    std::string insuranceBasisRzzo;
    std::string insuranceDescription;
    std::string carrierRelationship;
    bool carrierFamilyMember = false;
    std::string carrierIdNumber;
    std::string carrierInsurantNumber;
    std::string carrierFamilyName;
    std::string carrierFamilyNameLatin;
    std::string carrierGivenName;
    std::string carrierGivenNameLatin;
    std::string insuranceStartDate; // DD.MM.YYYY
    std::string country;
    std::string taxpayerName;
    std::string taxpayerResidence;
    std::string taxpayerIdNumber;
    std::string taxpayerActivityCode;
};

} // namespace healthcard
