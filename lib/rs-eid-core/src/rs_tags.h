// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

#include <cstdint>

/// @brief Vocabulary of the Serbian national data format.
///
/// Shared by the CardEdge generations and by the annex dedicated file that the
/// current generation carries alongside its eMRTD application.
namespace LibreSCRS::RsEId::Core::tags {

// --- Annex manifest (file 0x0F1B) ---
inline constexpr std::uint16_t kAnnexManifestVersion = 1537;
inline constexpr std::uint16_t kAnnexManifestVariant = 1538;
/// File ids the annex carries, little-endian pairs. Never lists the manifest.
inline constexpr std::uint16_t kAnnexManifestFileList = 1539;

// --- Annex file ids ---
inline constexpr std::uint16_t kFidDocumentData = 0x0F02;
inline constexpr std::uint16_t kFidPersonalData = 0x0F03;
inline constexpr std::uint16_t kFidVariableData = 0x0F04;
inline constexpr std::uint16_t kFidAnnexDf = 0x0FF3;
inline constexpr std::uint16_t kFidManifest = 0x0F1B;
inline constexpr std::uint16_t kFidSodFixed = 0x0F1C;
inline constexpr std::uint16_t kFidSodVariable = 0x0F1D;
inline constexpr std::uint16_t kFidIdHash = 0x0FA1;
inline constexpr std::uint16_t kFidPhoto = 0x0F06;
inline constexpr std::uint16_t kFidPublicKey = 0x0D10;
inline constexpr std::uint16_t kFidCertDigests = 0x0F12;
inline constexpr std::uint16_t kFidIssuerHash = 0x0FA2;

// --- Official ID (SEREL) file ids; same numbers as other types, other meaning ---
inline constexpr std::uint16_t kFidElManifest = 0x0D00;
inline constexpr std::uint16_t kFidElDocument = 0x0D01;
inline constexpr std::uint16_t kFidElPersonal = 0x0D02;
inline constexpr std::uint16_t kFidElService = 0x0D03;
inline constexpr std::uint16_t kFidElSealed = 0x0D04;
inline constexpr std::uint16_t kFidElPhoto = 0x0D05;
inline constexpr std::uint16_t kFidElDigest = 0x0D07;
inline constexpr std::uint16_t kFidElSodFixed = 0x0D08;
inline constexpr std::uint16_t kFidElSodService = 0x0D09;
inline constexpr std::uint16_t kFidElSodSealed = 0x0D0A;

// --- Serbian national data fields, shared by CardEdge and the annex ---
inline constexpr std::uint16_t kDocRegNo = 1546;
inline constexpr std::uint16_t kDocumentType = 1547;
inline constexpr std::uint16_t kDocumentSerialNo = 1548;
inline constexpr std::uint16_t kIssuingDate = 1549;
inline constexpr std::uint16_t kExpiryDate = 1550;
inline constexpr std::uint16_t kIssuingAuthority = 1551;
inline constexpr std::uint16_t kPersonalNumber = 1558;
inline constexpr std::uint16_t kSurname = 1559;
inline constexpr std::uint16_t kGivenName = 1560;
inline constexpr std::uint16_t kParentGivenName = 1561;
inline constexpr std::uint16_t kSex = 1562;
inline constexpr std::uint16_t kPlaceOfBirth = 1563;
inline constexpr std::uint16_t kCommunityOfBirth = 1564;
inline constexpr std::uint16_t kStateOfBirth = 1565;
inline constexpr std::uint16_t kStateOfBirthCode = 1567;
inline constexpr std::uint16_t kDateOfBirth = 1566;
inline constexpr std::uint16_t kNationalityFull = 1583;
inline constexpr std::uint16_t kStatusOfForeigner = 1582;
inline constexpr std::uint16_t kState = 1568;
inline constexpr std::uint16_t kCommunity = 1569;
inline constexpr std::uint16_t kPlace = 1570;
inline constexpr std::uint16_t kStreet = 1571;
inline constexpr std::uint16_t kHouseNumber = 1572;
inline constexpr std::uint16_t kHouseLetter = 1573;
inline constexpr std::uint16_t kEntrance = 1574;
inline constexpr std::uint16_t kFloor = 1575;
inline constexpr std::uint16_t kApartmentNumber = 1578;
inline constexpr std::uint16_t kAddressDate = 1580;
inline constexpr std::uint16_t kAddressLabel = 1581;
inline constexpr std::uint16_t kCardNumber = 1681;
inline constexpr std::uint16_t kDocumentName = 1682;
inline constexpr std::uint16_t kPurposeOfStay = 1683;
inline constexpr std::uint16_t kNote = 1684;

// --- Official ID (SEREL): the numbers coincide with the fields above, the
// meaning does not, so a profile binds them per file, never globally. ---
namespace el {
inline constexpr std::uint16_t kIssuingAuthority = 1553;
inline constexpr std::uint16_t kIssuingDate = 1554;
inline constexpr std::uint16_t kDocRegNo = 1556;
inline constexpr std::uint16_t kGivenName = 1568;
inline constexpr std::uint16_t kSurname = 1569;
inline constexpr std::uint16_t kDateOfBirth = 1570;
inline constexpr std::uint16_t kPersonalNumber = 1571;
inline constexpr std::uint16_t kBloodGroup = 1572;
inline constexpr std::uint16_t kSex = 1573;
inline constexpr std::uint16_t kStatus = 1574;
inline constexpr std::uint16_t kBadgeNumber = 1575;
inline constexpr std::uint16_t kRank = 1576;
inline constexpr std::uint16_t kOrganisationalUnit = 1600;
inline constexpr std::uint16_t kPosition = 1601;
inline constexpr std::uint16_t kServiceAddress = 1602;
} // namespace el

} // namespace LibreSCRS::RsEId::Core::tags
