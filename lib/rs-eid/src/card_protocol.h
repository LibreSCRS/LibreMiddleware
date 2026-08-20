// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

#include <rs_tags.h>

#include <cstdint>
#include <vector>

namespace eidcard::protocol {

// Application Identifiers (AIDs) for Serbian eID cards
// SERID - Citizen eID application
inline const std::vector<uint8_t> AID_SERID = {0xF3, 0x81, 0x00, 0x00, 0x02, 0x53, 0x45, 0x52, 0x49, 0x44, 0x01};

// SERIF - eID for foreigners application (primary AID, IF2020 cards)
inline const std::vector<uint8_t> AID_SERIF = {0xF3, 0x81, 0x00, 0x00, 0x02, 0x53, 0x45, 0x52, 0x49, 0x46, 0x01};

// SERRP - eID for foreigners application (alternate AID, same card family as SERIF)
// Note: despite the "RP" suffix this is NOT a residence permit; it is another
// variant of the Serbian identity card for foreigners ("Lična karta za strance").
inline const std::vector<uint8_t> AID_SERRP = {0xF3, 0x81, 0x00, 0x00, 0x02, 0x53, 0x45, 0x52, 0x52, 0x50, 0x01};

// File IDs (2 bytes each) - Data files
constexpr uint8_t FILE_DOCUMENT_DATA_H = 0x0F;
constexpr uint8_t FILE_DOCUMENT_DATA_L = 0x02;
constexpr uint8_t FILE_PERSONAL_DATA_H = 0x0F;
constexpr uint8_t FILE_PERSONAL_DATA_L = 0x03;
constexpr uint8_t FILE_VARIABLE_DATA_H = 0x0F;
constexpr uint8_t FILE_VARIABLE_DATA_L = 0x04;
constexpr uint8_t FILE_PORTRAIT_H = 0x0F;
constexpr uint8_t FILE_PORTRAIT_L = 0x06;

// File IDs - Apollo 2008 certificate and signature files
constexpr uint8_t FILE_USER_CERT1_H = 0x0F; // User Certificate 1
constexpr uint8_t FILE_USER_CERT1_L = 0x08;
constexpr uint8_t FILE_CERT_VX_H = 0x0F; // Signing cert for variable data (MOI_CERTo1)
constexpr uint8_t FILE_CERT_VX_L = 0x13;
constexpr uint8_t FILE_SIGN_VX_H = 0x0F; // Variable data signature (MOI_SIGN_VX)
constexpr uint8_t FILE_SIGN_VX_L = 0x14;
constexpr uint8_t FILE_CERT_FX_H = 0x0F; // Signing cert for fixed data (MOI_CERTm1)
constexpr uint8_t FILE_CERT_FX_L = 0x15;
constexpr uint8_t FILE_SIGN_FX_H = 0x0F; // Fixed data signature (MOI_SIGN_FX)
constexpr uint8_t FILE_SIGN_FX_L = 0x16;

// File IDs - Gemalto 2014 / IF2020 SOD (Security Object Document) files
constexpr uint8_t FILE_SOD_FX_H = 0x0F; // SOD for fixed data (PKCS#7 SignedData)
constexpr uint8_t FILE_SOD_FX_L = 0x1C;
constexpr uint8_t FILE_SOD_VX_H = 0x0F; // SOD for variable data (PKCS#7 SignedData)
constexpr uint8_t FILE_SOD_VX_L = 0x1D;

// Field tags live in the core, which both the CardEdge readers and the annex
// reader share. These aliases keep existing call sites spelled as they were.
inline constexpr uint16_t TAG_DOC_REG_NO = LibreSCRS::RsEId::Core::tags::kDocRegNo;
inline constexpr uint16_t TAG_DOCUMENT_TYPE = LibreSCRS::RsEId::Core::tags::kDocumentType;
inline constexpr uint16_t TAG_DOCUMENT_SERIAL_NO = LibreSCRS::RsEId::Core::tags::kDocumentSerialNo;
inline constexpr uint16_t TAG_ISSUING_DATE = LibreSCRS::RsEId::Core::tags::kIssuingDate;
inline constexpr uint16_t TAG_EXPIRY_DATE = LibreSCRS::RsEId::Core::tags::kExpiryDate;
inline constexpr uint16_t TAG_ISSUING_AUTHORITY = LibreSCRS::RsEId::Core::tags::kIssuingAuthority;
inline constexpr uint16_t TAG_CHIP_SERIAL_NUMBER = LibreSCRS::RsEId::Core::tags::kChipSerialNumber;
inline constexpr uint16_t TAG_PERSONAL_NUMBER = LibreSCRS::RsEId::Core::tags::kPersonalNumber;
inline constexpr uint16_t TAG_SURNAME = LibreSCRS::RsEId::Core::tags::kSurname;
inline constexpr uint16_t TAG_GIVEN_NAME = LibreSCRS::RsEId::Core::tags::kGivenName;
inline constexpr uint16_t TAG_PARENT_GIVEN_NAME = LibreSCRS::RsEId::Core::tags::kParentGivenName;
inline constexpr uint16_t TAG_SEX = LibreSCRS::RsEId::Core::tags::kSex;
inline constexpr uint16_t TAG_PLACE_OF_BIRTH = LibreSCRS::RsEId::Core::tags::kPlaceOfBirth;
inline constexpr uint16_t TAG_COMMUNITY_OF_BIRTH = LibreSCRS::RsEId::Core::tags::kCommunityOfBirth;
inline constexpr uint16_t TAG_STATE_OF_BIRTH = LibreSCRS::RsEId::Core::tags::kStateOfBirth;
inline constexpr uint16_t TAG_DATE_OF_BIRTH = LibreSCRS::RsEId::Core::tags::kDateOfBirth;
inline constexpr uint16_t TAG_NATIONALITY_FULL = LibreSCRS::RsEId::Core::tags::kNationalityFull;
inline constexpr uint16_t TAG_STATUS_OF_FOREIGNER = LibreSCRS::RsEId::Core::tags::kStatusOfForeigner;
inline constexpr uint16_t TAG_STATE = LibreSCRS::RsEId::Core::tags::kState;
inline constexpr uint16_t TAG_COMMUNITY = LibreSCRS::RsEId::Core::tags::kCommunity;
inline constexpr uint16_t TAG_PLACE = LibreSCRS::RsEId::Core::tags::kPlace;
inline constexpr uint16_t TAG_STREET = LibreSCRS::RsEId::Core::tags::kStreet;
inline constexpr uint16_t TAG_HOUSE_NUMBER = LibreSCRS::RsEId::Core::tags::kHouseNumber;
inline constexpr uint16_t TAG_HOUSE_LETTER = LibreSCRS::RsEId::Core::tags::kHouseLetter;
inline constexpr uint16_t TAG_ENTRANCE = LibreSCRS::RsEId::Core::tags::kEntrance;
inline constexpr uint16_t TAG_FLOOR = LibreSCRS::RsEId::Core::tags::kFloor;
inline constexpr uint16_t TAG_APARTMENT_NUMBER = LibreSCRS::RsEId::Core::tags::kApartmentNumber;
inline constexpr uint16_t TAG_ADDRESS_DATE = LibreSCRS::RsEId::Core::tags::kAddressDate;
inline constexpr uint16_t TAG_ADDRESS_LABEL = LibreSCRS::RsEId::Core::tags::kAddressLabel;

// ATR patterns for card type detection
// Gemalto (2014+) cards have ATR starting with 3B FF 94 00 00
// Apollo (pre-2014) cards have ATR starting with 3B B9 18 00
inline bool isGemaltoATR(const std::vector<uint8_t>& atr)
{
    return atr.size() >= 5 && atr[0] == 0x3B && atr[1] == 0xFF && atr[2] == 0x94;
}

inline bool isApolloATR(const std::vector<uint8_t>& atr)
{
    return atr.size() >= 4 && atr[0] == 0x3B && atr[1] == 0xB9 && atr[2] == 0x18;
}

// Read chunk size for eID data files (SELECT by path, plain READ BINARY).
constexpr uint8_t READ_CHUNK_SIZE = 0xFF; // 255 bytes per READ BINARY

} // namespace eidcard::protocol
