// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace piv {

struct CCCInfo
{
    std::vector<uint8_t> cardIdentifier;      // Tag F0
    std::vector<uint8_t> capabilityContainer; // Tag F1
    std::vector<uint8_t> capabilityVersion;   // Tag F2
    std::vector<uint8_t> capabilityGrammar;   // Tag F3
};

struct CHUIDInfo
{
    std::vector<uint8_t> fascn;               // Tag 30 — FASC-N
    std::vector<uint8_t> guid;                // Tag 34 — GUID (16 bytes)
    std::string expirationDate;               // Tag 35 — YYYYMMDD
    std::vector<uint8_t> issuerAsymSignature; // Tag 3E
};

struct DiscoveryInfo
{
    std::vector<uint8_t> pivAID; // Tag 4F
    uint16_t pinUsagePolicy = 0; // Tag 5F2F — 2 bytes
};

struct PrintedInfo
{
    std::string name;                     // Tag 01
    std::string employeeAffiliation;      // Tag 02
    std::string expirationDate;           // Tag 04
    std::string agencyCardSerialNumber;   // Tag 05
    std::string issuerIdentification;     // Tag 06
    std::string organizationAffiliation1; // Tag 07
    std::string organizationAffiliation2; // Tag 08
};

struct KeyHistoryInfo
{
    uint8_t keysWithOnCardCerts = 0;  // Tag C1
    uint8_t keysWithOffCardCerts = 0; // Tag C2
    std::string offCardCertURL;       // Tag F3
};

struct PIVCertificate
{
    std::string slotName;           // "PIV Authentication", etc.
    uint8_t keyReference = 0;       // 9A, 9C, 9D, 9E, 82-95
    std::vector<uint8_t> certBytes; // Tag 70 — X.509 DER
    uint8_t certInfo = 0;           // Tag 71 — bit 0: gzip compressed
};

struct PINInfo
{
    std::string label;        // "PIV Application PIN", "Global PIN"
    uint8_t keyReference = 0; // 0x80, 0x00
};

struct PIVData
{
    CCCInfo ccc;
    CHUIDInfo chuid;
    DiscoveryInfo discovery;
    std::optional<PrintedInfo> printedInfo;
    std::optional<KeyHistoryInfo> keyHistory;
    std::vector<PIVCertificate> certificates;
};

} // namespace piv
