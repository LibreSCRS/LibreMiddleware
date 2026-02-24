// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright hirashix0@proton.me

#ifndef EIDCARD_CARD_PROTOCOL_H
#define EIDCARD_CARD_PROTOCOL_H

#include <cstdint>
#include <vector>

namespace eidcard::protocol {

// Application Identifiers (AIDs) for Serbian eID cards
// SERID - Main eID application (citizen ID)
inline const std::vector<uint8_t> AID_SERID = {
    0xF3, 0x81, 0x00, 0x00, 0x02, 0x53, 0x45, 0x52, 0x49, 0x44, 0x01
};

// SERIF - Foreigner ID application
inline const std::vector<uint8_t> AID_SERIF = {
    0xF3, 0x81, 0x00, 0x00, 0x02, 0x53, 0x45, 0x52, 0x49, 0x46, 0x01
};

// SERRP - Residence Permit application
inline const std::vector<uint8_t> AID_SERRP = {
    0xF3, 0x81, 0x00, 0x00, 0x02, 0x53, 0x45, 0x52, 0x52, 0x50, 0x01
};

// CardEdge PKI applet (PKCS#15) — holds end-entity certificates and keys
inline const std::vector<uint8_t> AID_PKCS15 = {
    0xA0, 0x00, 0x00, 0x00, 0x63, 0x50, 0x4B, 0x43, 0x53, 0x2D, 0x31, 0x35
};

// File IDs (2 bytes each) - Data files
constexpr uint8_t FILE_DOCUMENT_DATA_H  = 0x0F;
constexpr uint8_t FILE_DOCUMENT_DATA_L  = 0x02;
constexpr uint8_t FILE_PERSONAL_DATA_H  = 0x0F;
constexpr uint8_t FILE_PERSONAL_DATA_L  = 0x03;
constexpr uint8_t FILE_VARIABLE_DATA_H  = 0x0F;
constexpr uint8_t FILE_VARIABLE_DATA_L  = 0x04;
constexpr uint8_t FILE_PORTRAIT_H       = 0x0F;
constexpr uint8_t FILE_PORTRAIT_L       = 0x06;

// File IDs - Apollo 2008 certificate and signature files
constexpr uint8_t FILE_USER_CERT1_H      = 0x0F;  // User Certificate 1
constexpr uint8_t FILE_USER_CERT1_L      = 0x08;
constexpr uint8_t FILE_USER_CERT2_H      = 0x0F;  // User Certificate 2
constexpr uint8_t FILE_USER_CERT2_L      = 0x10;
constexpr uint8_t FILE_INTERMEDIATE_CA_H = 0x0F;  // MOI Intermediate CA Certificate
constexpr uint8_t FILE_INTERMEDIATE_CA_L = 0x11;
constexpr uint8_t FILE_CERT_VX_H         = 0x0F;  // Signing cert for variable data (MOI_CERTo1)
constexpr uint8_t FILE_CERT_VX_L         = 0x13;
constexpr uint8_t FILE_SIGN_VX_H         = 0x0F;  // Variable data signature (MOI_SIGN_VX)
constexpr uint8_t FILE_SIGN_VX_L         = 0x14;
constexpr uint8_t FILE_CERT_FX_H         = 0x0F;  // Signing cert for fixed data (MOI_CERTm1)
constexpr uint8_t FILE_CERT_FX_L         = 0x15;
constexpr uint8_t FILE_SIGN_FX_H         = 0x0F;  // Fixed data signature (MOI_SIGN_FX)
constexpr uint8_t FILE_SIGN_FX_L         = 0x16;

// File IDs - Gemalto 2014 / IF2020 SOD (Security Object Document) files
constexpr uint8_t FILE_SOD_FX_H          = 0x0F;  // SOD for fixed data (PKCS#7 SignedData)
constexpr uint8_t FILE_SOD_FX_L          = 0x1C;
constexpr uint8_t FILE_SOD_VX_H          = 0x0F;  // SOD for variable data (PKCS#7 SignedData)
constexpr uint8_t FILE_SOD_VX_L          = 0x1D;

// TLV Tags for Document Data
constexpr uint16_t TAG_DOC_REG_NO           = 1546;
constexpr uint16_t TAG_DOCUMENT_TYPE        = 1547;
constexpr uint16_t TAG_DOCUMENT_SERIAL_NO   = 1548;
constexpr uint16_t TAG_ISSUING_DATE         = 1549;
constexpr uint16_t TAG_EXPIRY_DATE          = 1550;
constexpr uint16_t TAG_ISSUING_AUTHORITY    = 1551;
constexpr uint16_t TAG_CHIP_SERIAL_NUMBER   = 1689;

// TLV Tags for Fixed Personal Data
constexpr uint16_t TAG_PERSONAL_NUMBER      = 1558;
constexpr uint16_t TAG_SURNAME              = 1559;
constexpr uint16_t TAG_GIVEN_NAME           = 1560;
constexpr uint16_t TAG_PARENT_GIVEN_NAME    = 1561;
constexpr uint16_t TAG_SEX                  = 1562;
constexpr uint16_t TAG_PLACE_OF_BIRTH       = 1563;
constexpr uint16_t TAG_COMMUNITY_OF_BIRTH   = 1564;
constexpr uint16_t TAG_STATE_OF_BIRTH       = 1565;
constexpr uint16_t TAG_DATE_OF_BIRTH        = 1566;
constexpr uint16_t TAG_NATIONALITY_FULL     = 1583;
constexpr uint16_t TAG_STATUS_OF_FOREIGNER  = 1582;

// TLV Tags for Variable Personal Data
constexpr uint16_t TAG_STATE                = 1568;
constexpr uint16_t TAG_COMMUNITY            = 1569;
constexpr uint16_t TAG_PLACE                = 1570;
constexpr uint16_t TAG_STREET               = 1571;
constexpr uint16_t TAG_HOUSE_NUMBER         = 1572;
constexpr uint16_t TAG_HOUSE_LETTER         = 1573;
constexpr uint16_t TAG_ENTRANCE             = 1574;
constexpr uint16_t TAG_FLOOR                = 1575;
constexpr uint16_t TAG_APARTMENT_NUMBER     = 1578;
constexpr uint16_t TAG_ADDRESS_DATE         = 1580;
constexpr uint16_t TAG_ADDRESS_LABEL        = 1581;

// TLV Tags for Portrait
constexpr uint16_t TAG_PORTRAIT             = 1584;

// ATR patterns for card type detection
// Gemalto (2014+) cards have ATR starting with 3B FF 94 00 00
// Apollo (pre-2014) cards have ATR starting with 3B B9 18 00
inline bool isGemaltoATR(const std::vector<uint8_t>& atr)
{
    return atr.size() >= 5 &&
           atr[0] == 0x3B &&
           atr[1] == 0xFF &&
           atr[2] == 0x94;
}

inline bool isApolloATR(const std::vector<uint8_t>& atr)
{
    return atr.size() >= 4 &&
           atr[0] == 0x3B &&
           atr[1] == 0xB9 &&
           atr[2] == 0x18;
}

// PIN reference for the PKI (CardEdge/PKCS#15) applet
// nstpkcs11 CE_PIN_ID(RoleUser) = 0x80 | (1-1) = 0x80
constexpr uint8_t PKI_PIN_REFERENCE = 0x80;

// Maximum PIN length — PINs are null-padded (0x00) to this length
constexpr uint8_t PIN_MAX_LENGTH = 8;

// Read chunk size
constexpr uint8_t READ_CHUNK_SIZE = 0xFF;  // 255 bytes per READ BINARY

} // namespace eidcard::protocol

#endif // EIDCARD_CARD_PROTOCOL_H
