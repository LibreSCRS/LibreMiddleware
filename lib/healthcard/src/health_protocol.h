// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright hirashix0@proton.me

#ifndef HEALTHCARD_HEALTH_PROTOCOL_H
#define HEALTHCARD_HEALTH_PROTOCOL_H

#include <cstdint>
#include <vector>

namespace healthcard::protocol {

// Known ATRs for Serbian health insurance cards
inline const std::vector<uint8_t> MEDICAL_ATR_1 = {
    0x3B, 0xF4, 0x13, 0x00, 0x00, 0x81, 0x31, 0xFE,
    0x45, 0x52, 0x46, 0x5A, 0x4F, 0xED
};
inline const std::vector<uint8_t> MEDICAL_ATR_2 = {
    0x3B, 0x9E, 0x97, 0x80, 0x31, 0xFE, 0x45, 0x53,
    0x43, 0x45, 0x20, 0x38, 0x2E, 0x30, 0x2D, 0x43,
    0x31, 0x56, 0x30, 0x0D, 0x0A, 0x6E
};

// AID — SERVSZK Serbian health insurance application
inline const std::vector<uint8_t> AID_SERVSZK = {
    0xF3, 0x81, 0x00, 0x00, 0x02, 0x53, 0x45, 0x52,
    0x56, 0x53, 0x5A, 0x4B, 0x01
};

// File IDs (SELECT FILE by ID)
inline const std::vector<uint8_t> FILE_DOCUMENT           = {0x0D, 0x01};
inline const std::vector<uint8_t> FILE_FIXED_PERSONAL     = {0x0D, 0x02};
inline const std::vector<uint8_t> FILE_VARIABLE_PERSONAL  = {0x0D, 0x03};
inline const std::vector<uint8_t> FILE_VARIABLE_ADMIN     = {0x0D, 0x04};

// File header: 4 bytes; content length at bytes [2:3] as LE uint16
constexpr uint8_t FILE_HEADER_SIZE = 4;
constexpr uint8_t READ_CHUNK_SIZE  = 0xFF;

// TLV tags — document file (0D 01)
constexpr uint16_t TAG_INSURER_NAME     = 1553;
constexpr uint16_t TAG_INSURER_ID       = 1554;
constexpr uint16_t TAG_CARD_ID          = 1555;
constexpr uint16_t TAG_DATE_OF_ISSUE    = 1557;
constexpr uint16_t TAG_DATE_OF_EXPIRY   = 1558;
constexpr uint16_t TAG_PRINT_LANGUAGE   = 1560;

// TLV tags — fixed personal file (0D 02)
constexpr uint16_t TAG_INSURANT_NUMBER  = 1569;
constexpr uint16_t TAG_FAMILY_NAME      = 1570;
constexpr uint16_t TAG_FAMILY_NAME_LAT  = 1571;
constexpr uint16_t TAG_GIVEN_NAME       = 1572;
constexpr uint16_t TAG_GIVEN_NAME_LAT   = 1573;
constexpr uint16_t TAG_DATE_OF_BIRTH    = 1574;

// TLV tags — variable personal file (0D 03)
constexpr uint16_t TAG_VALID_UNTIL      = 1586;
constexpr uint16_t TAG_PERMANENTLY_VALID = 1587;

// TLV tags — variable administrative file (0D 04)
constexpr uint16_t TAG_PARENT_NAME           = 1601;
constexpr uint16_t TAG_PARENT_NAME_LAT       = 1602;
constexpr uint16_t TAG_GENDER                = 1603;
constexpr uint16_t TAG_PERSONAL_NUMBER       = 1604;
constexpr uint16_t TAG_STREET                = 1605;
constexpr uint16_t TAG_MUNICIPALITY          = 1607;
constexpr uint16_t TAG_PLACE                 = 1608;
constexpr uint16_t TAG_ADDRESS_NUMBER        = 1610;
constexpr uint16_t TAG_APARTMENT             = 1612;
constexpr uint16_t TAG_INSURANCE_BASIS       = 1614;
constexpr uint16_t TAG_INSURANCE_DESC        = 1615;
constexpr uint16_t TAG_CARRIER_RELATION      = 1616;
constexpr uint16_t TAG_CARRIER_FAMILY_MEMBER = 1617;
constexpr uint16_t TAG_CARRIER_ID_NO         = 1618;
constexpr uint16_t TAG_CARRIER_INSURANT_NO   = 1619;
constexpr uint16_t TAG_CARRIER_FAMILY_NAME   = 1620;
constexpr uint16_t TAG_CARRIER_FAMILY_NAME_LAT = 1621;
constexpr uint16_t TAG_CARRIER_GIVEN_NAME    = 1622;
constexpr uint16_t TAG_CARRIER_GIVEN_NAME_LAT = 1623;
constexpr uint16_t TAG_INSURANCE_START       = 1624;
constexpr uint16_t TAG_COUNTRY               = 1626;
constexpr uint16_t TAG_TAXPAYER_NAME         = 1630;
constexpr uint16_t TAG_TAXPAYER_RES          = 1631;
constexpr uint16_t TAG_TAXPAYER_ID_1         = 1632;
constexpr uint16_t TAG_TAXPAYER_ID_2         = 1633;
constexpr uint16_t TAG_TAXPAYER_ACTIV        = 1634;

} // namespace healthcard::protocol

#endif // HEALTHCARD_HEALTH_PROTOCOL_H
