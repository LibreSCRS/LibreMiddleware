// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright hirashix0@proton.me

#ifndef EIDCARD_EIDTYPES_H
#define EIDCARD_EIDTYPES_H

#include <cstdint>
#include <string>
#include <vector>

namespace eidcard {

enum class CardType : int { Unknown = 0, Apollo2008 = 1, Gemalto2014 = 2, ForeignerIF2020 = 3 };

struct DocumentData
{
    std::string docRegNo;
    std::string documentType;
    std::string documentSerialNumber;
    std::string issuingDate;
    std::string expiryDate;
    std::string issuingAuthority;
    std::string chipSerialNumber;
};

struct FixedPersonalData
{
    std::string personalNumber;
    std::string surname;
    std::string givenName;
    std::string parentGivenName;
    std::string sex;
    std::string placeOfBirth;
    std::string communityOfBirth;
    std::string stateOfBirth;
    std::string dateOfBirth;
    std::string nationalityFull;
    std::string statusOfForeigner;
};

struct VariablePersonalData
{
    std::string state;
    std::string community;
    std::string place;
    std::string street;
    std::string houseNumber;
    std::string houseLetter;
    std::string entrance;
    std::string floor;
    std::string apartmentNumber;
    std::string addressDate;
    std::string addressLabel;
};

using PhotoData = std::vector<uint8_t>;

enum class VerificationResult {
    Unknown, // verification could not be performed
    Valid,   // signature verified successfully
    Invalid  // signature verification failed
};

} // namespace eidcard

#endif // EIDCARD_EIDTYPES_H
