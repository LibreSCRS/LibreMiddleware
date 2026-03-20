// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

#include <emrtd/emrtd_types.h>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace emrtd {

struct ParsedMRZ
{
    std::string documentCode;
    std::string issuingState;
    std::string surname;
    std::string givenNames;
    std::string documentNumber;
    std::string nationality;
    std::string dateOfBirth;
    std::string sex;
    std::string dateOfExpiry;
    std::string optionalData;
    std::string rawMRZ;
};

struct BiometricImage
{
    std::string mimeType;
    std::vector<uint8_t> imageData;
};

struct AdditionalPersonalData
{
    std::string fullName;
    std::string otherNames;
    std::string personalNumber;
    std::string placeOfBirth;
    std::string address;
    std::string telephone;
    std::string profession;
    std::string title;
    std::string custodyInfo;
};

struct AdditionalDocumentData
{
    std::string issuingAuthority;
    std::string dateOfIssue;
    std::string endorsements;
    std::string taxExitRequirements;
};

struct DataGroups
{
    std::optional<ParsedMRZ> dg1;
    std::optional<BiometricImage> dg2;
    std::optional<BiometricImage> dg7;
    std::optional<AdditionalPersonalData> dg11;
    std::optional<AdditionalDocumentData> dg12;
    std::optional<std::vector<uint8_t>> dg13;
    std::map<int, std::vector<uint8_t>> raw;
};

DataGroups parseDataGroups(const std::map<int, std::vector<uint8_t>>& rawDGs);
ParsedMRZ parseMRZ(const std::string& mrz);

} // namespace emrtd
