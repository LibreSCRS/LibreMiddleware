// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace LibreSCRS::RsEId::Core {

/// @brief Outcome of a card-data trust decision.
///
/// Three states rather than two: a signer outside our domain is not evidence of
/// tampering, so it must not be reported the same way a broken signature is.
enum class VerificationResult : std::uint8_t {
    Unknown, ///< verification could not be performed, or the signer is not ours
    Valid,   ///< signature verified and the signer is attributable
    Invalid  ///< signature or chain verification failed
};

// --- Serbian national data, as the card carries it ---

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

using PhotoData = std::vector<std::uint8_t>;

} // namespace LibreSCRS::RsEId::Core
