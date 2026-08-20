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

// --- Serbian national data fields, shared by CardEdge and the annex ---
inline constexpr std::uint16_t kDocRegNo = 1546;
inline constexpr std::uint16_t kDocumentType = 1547;
inline constexpr std::uint16_t kDocumentSerialNo = 1548;
inline constexpr std::uint16_t kIssuingDate = 1549;
inline constexpr std::uint16_t kExpiryDate = 1550;
inline constexpr std::uint16_t kIssuingAuthority = 1551;
inline constexpr std::uint16_t kChipSerialNumber = 1689;
inline constexpr std::uint16_t kPersonalNumber = 1558;
inline constexpr std::uint16_t kSurname = 1559;
inline constexpr std::uint16_t kGivenName = 1560;
inline constexpr std::uint16_t kParentGivenName = 1561;
inline constexpr std::uint16_t kSex = 1562;
inline constexpr std::uint16_t kPlaceOfBirth = 1563;
inline constexpr std::uint16_t kCommunityOfBirth = 1564;
inline constexpr std::uint16_t kStateOfBirth = 1565;
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

} // namespace LibreSCRS::RsEId::Core::tags
