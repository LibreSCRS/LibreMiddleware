// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright hirashix0@proton.me

#ifndef EIDCARD_CARD_PROTOCOL_H
#define EIDCARD_CARD_PROTOCOL_H

#include <cstdint>
#include <vector>

namespace eidcard::protocol {

// Application Identifiers (AIDs) for Serbian eID cards
// SERID - Citizen eID application
inline const std::vector<uint8_t> AID_SERID = {
    0xF3, 0x81, 0x00, 0x00, 0x02, 0x53, 0x45, 0x52, 0x49, 0x44, 0x01
};

// SERIF - eID for foreigners application (primary AID, IF2020 cards)
inline const std::vector<uint8_t> AID_SERIF = {
    0xF3, 0x81, 0x00, 0x00, 0x02, 0x53, 0x45, 0x52, 0x49, 0x46, 0x01
};

// SERRP - eID for foreigners application (alternate AID, same card family as SERIF)
// Note: despite the "RP" suffix this is NOT a residence permit; it is another
// variant of the Serbian identity card for foreigners ("Lična karta za strance").
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

// PIN reference byte for the PKI applet user slot (role=User, slot index 0).
constexpr uint8_t PKI_PIN_REFERENCE = 0x80;

// Maximum PIN length — PINs are null-padded (0x00) to this length.
constexpr uint8_t PIN_MAX_LENGTH = 8;

// Maximum PIN retry count for Serbian eID (Gemalto/IF2020).
// A successful verification resets the counter to this value.
constexpr uint8_t PIN_MAX_RETRIES = 3;

// Read chunk size for eID data files (SELECT by path, plain READ BINARY).
constexpr uint8_t READ_CHUNK_SIZE = 0xFF;  // 255 bytes per READ BINARY

// -----------------------------------------------------------------------
// PKI (PKCS#15 CardEdge) applet constants
// -----------------------------------------------------------------------

// Root directory FID inside the PKI applet filesystem.
constexpr uint16_t PKI_ROOT_DIR_FID = 0x7000;

// Maximum bytes per READ BINARY on the PKI applet (CardEdge internal buffer).
constexpr uint8_t PKI_READ_CHUNK = 0x80;  // 128 bytes

// MSE SET algorithm reference byte for RSA-2048.
// The card applies PKCS#1 v1.5 padding when the input is shorter than the modulus.
// Note: RSA-PSS (full 256-byte input) is NOT supported by the CardEdge PSO.
constexpr uint8_t MSE_ALG_RSA2048 = 0x02;

// CardEdge directory file layout (root dir FID 0x7000, mscp subdir).
// Header (10 bytes): LeftFiles(1) LeftDirs(1) NextFileFID(2 LE) NextDirFID(2 LE)
//                    EntriesCount(2 LE) WriteACL(2 LE)
// Entry  (12 bytes): Name(8) FID(2 LE) IsDir(1) pad(1)
constexpr size_t CE_DIR_HEADER_SIZE = 10;
constexpr size_t CE_DIR_ENTRY_SIZE  = 12;

// PKCS#15 container map (cmapfile) record layout — 86 bytes per entry.
// Based on Windows CNG cardmod.h CONTAINER_MAP_RECORD:
//   WCHAR wszGuid[40]  = 80 bytes (UTF-16LE, null-padded)
//   BYTE  bFlags       =  1 byte  (bit 0 = valid, bit 1 = default container)
//   BYTE  bReserved    =  1 byte
//   WORD  wSigKeySizeBits     = 2 bytes LE (0 if no signature key)
//   WORD  wKeyExchangeKeySizeBits = 2 bytes LE (0 if no key-exchange key)
constexpr size_t  CMAP_RECORD_SIZE      = 86;
constexpr size_t  CMAP_FLAGS_OFFSET     = 80;
constexpr size_t  CMAP_SIG_SIZE_OFFSET  = 82;  // signature key size in bits (LE)
constexpr size_t  CMAP_KX_SIZE_OFFSET   = 84;  // key-exchange key size in bits (LE)
constexpr uint8_t CMAP_VALID_CONTAINER  = 0x01;

// Private key FID derivation (CardEdge GET_KEY_FID formula):
//   FID = CE_KEYS_BASE_FID
//       | ((containerIndex << 4) & 0x0FF0)
//       | ((keyPairId      << 2) & 0x000C)
//       | CE_KEY_KIND_PRIVATE
constexpr uint16_t CE_KEYS_BASE_FID    = 0x6000;
constexpr uint16_t CE_KEY_KIND_PRIVATE = 1;
constexpr uint16_t AT_KEYEXCHANGE      = 1;  // key-exchange (encryption) key pair
constexpr uint16_t AT_SIGNATURE        = 2;  // digital-signature key pair

inline uint16_t privateKeyFID(uint8_t containerIndex, uint16_t keyPairId)
{
    return static_cast<uint16_t>(
        CE_KEYS_BASE_FID
        | ((static_cast<uint16_t>(containerIndex) << 4) & 0x0FF0u)
        | ((keyPairId << 2) & 0x000Cu)
        | CE_KEY_KIND_PRIVATE);
}

} // namespace eidcard::protocol

#endif // EIDCARD_CARD_PROTOCOL_H
