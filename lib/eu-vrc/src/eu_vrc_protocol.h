// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

namespace euvrc::protocol {

// EU standard VRC AID (Commission Directive 2003/127/EC)
// RID: European Commission, PIX: "EVR-01"
inline const std::vector<uint8_t> EU_VRC_AID = {
    0xA0, 0x00, 0x00, 0x04, 0x56, 0x45, 0x56, 0x52, 0x2D, 0x30, 0x31};

// Serbian AID sequences (NXP eVL platform)

// Sequence 1 (pre-2015)
inline const std::vector<uint8_t> SEQ1_CMD1 = {0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00};
inline const std::vector<uint8_t> SEQ1_CMD2 = {0xA0, 0x00, 0x00, 0x00, 0x77, 0x01, 0x08, 0x00,
                                               0x07, 0x00, 0x00, 0xFE, 0x00, 0x00, 0x01, 0x00};
inline const std::vector<uint8_t> SEQ1_CMD3 = {0xA0, 0x00, 0x00, 0x00, 0x77, 0x01, 0x08, 0x00,
                                               0x07, 0x00, 0x00, 0xFE, 0x00, 0x00, 0xAD, 0xF2};

// Sequence 2 (2015-2020)
inline const std::vector<uint8_t> SEQ2_CMD1 = {0xA0, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00};
inline const std::vector<uint8_t> SEQ2_CMD2 = {0xF3, 0x81, 0x00, 0x00, 0x02, 0x53, 0x45,
                                               0x52, 0x56, 0x4C, 0x04, 0x02, 0x01};
// SEQ2_CMD3 is the same as SEQ1_CMD3

// Sequence 3 (2020+)
inline const std::vector<uint8_t> SEQ3_CMD1 = {0xA0, 0x00, 0x00, 0x00, 0x18, 0x43, 0x4D, 0x00};
inline const std::vector<uint8_t> SEQ3_CMD2 = {0xA0, 0x00, 0x00, 0x00, 0x18, 0x34, 0x14, 0x01,
                                               0x00, 0x65, 0x56, 0x4C, 0x2D, 0x30, 0x30, 0x31};
inline const std::vector<uint8_t> SEQ3_CMD3 = {0xA0, 0x00, 0x00, 0x00, 0x18, 0x65, 0x56, 0x4C,
                                               0x2D, 0x30, 0x30, 0x31};

// EU standard file FIDs (Directive 2003/127/EC, Table 1)
struct FileFidEntry
{
    uint8_t fidHi;
    uint8_t fidLo;
    const char* name;
    bool isBerTlv; // true for D0xx data files, false for E0xx/C0xx binary
};

inline constexpr FileFidEntry STANDARD_FILES[] = {
    {0xD0, 0x01, "EF.Registration_A", true},
    {0xD0, 0x11, "EF.Registration_B", true},
    {0xE0, 0x01, "EF.Signature_A",    false},
    {0xE0, 0x11, "EF.Signature_B",    false},
    {0xC0, 0x01, "EF.C.IA_A.DS",      false},
    {0xC0, 0x11, "EF.C.IA_B.DS",      false},
};

inline constexpr FileFidEntry NATIONAL_EXTENSION_FILES[] = {
    {0xD0, 0x21, "EF.NationalExt_1", true},
    {0xD0, 0x31, "EF.NationalExt_2", true},
    {0xE0, 0x21, "EF.Signature_Ext", false},
    {0xC0, 0x21, "EF.Cert_Ext",      false},
};

// BER-TLV container tags
constexpr uint32_t TAG_MANDATORY_CONTAINER = 0x71;
constexpr uint32_t TAG_OPTIONAL_CONTAINER  = 0x72;
constexpr uint32_t TAG_ALLOC_AUTHORITY     = 0x78;
constexpr uint32_t TAG_APP_ID              = 0x4F;
constexpr uint32_t TAG_PERSONAL_DATA       = 0xA1;
constexpr uint32_t TAG_REG_HOLDER          = 0xA2;
constexpr uint32_t TAG_VEHICLE_DATA        = 0xA3;
constexpr uint32_t TAG_MASS_DATA           = 0xA4;
constexpr uint32_t TAG_ENGINE_DATA         = 0xA5;
constexpr uint32_t TAG_SEATING_DATA        = 0xA6;
constexpr uint32_t TAG_VEHICLE_OWNER       = 0xA7;
constexpr uint32_t TAG_SECOND_OWNER        = 0xA8;
constexpr uint32_t TAG_USER                = 0xA9;

// EU mandatory field tags (inside container 71)
constexpr uint32_t TAG_VERSION             = 0x80;
constexpr uint32_t TAG_REG_NUMBER          = 0x81;  // A
constexpr uint32_t TAG_FIRST_REG           = 0x82;  // B
constexpr uint32_t TAG_HOLDER_NAME         = 0x83;  // C.1.1
constexpr uint32_t TAG_HOLDER_OTHER_NAMES  = 0x84;  // C.1.2
constexpr uint32_t TAG_HOLDER_ADDRESS      = 0x85;  // C.1.3
constexpr uint32_t TAG_OWNERSHIP_STATUS    = 0x86;  // C.4
constexpr uint32_t TAG_VEHICLE_MAKE        = 0x87;  // D.1
constexpr uint32_t TAG_VEHICLE_TYPE        = 0x88;  // D.2
constexpr uint32_t TAG_COMMERCIAL_DESC     = 0x89;  // D.3
constexpr uint32_t TAG_VIN                 = 0x8A;  // E
constexpr uint32_t TAG_MAX_LADEN_MASS      = 0x8B;  // F.1
constexpr uint32_t TAG_VEHICLE_MASS        = 0x8C;  // G
constexpr uint32_t TAG_EXPIRY              = 0x8D;  // H
constexpr uint32_t TAG_REG_DATE            = 0x8E;  // I
constexpr uint32_t TAG_TYPE_APPROVAL       = 0x8F;  // K
constexpr uint32_t TAG_ENGINE_CAPACITY     = 0x90;  // P.1
constexpr uint32_t TAG_MAX_NET_POWER       = 0x91;  // P.2
constexpr uint32_t TAG_FUEL_TYPE           = 0x92;  // P.3
constexpr uint32_t TAG_POWER_WEIGHT        = 0x93;  // Q
constexpr uint32_t TAG_NUM_SEATS           = 0x94;  // S.1
constexpr uint32_t TAG_STANDING_PLACES     = 0x95;  // S.2

// EU optional field tags (inside container 72)
constexpr uint32_t TAG_MAX_LADEN_SERVICE   = 0x96;  // F.2
constexpr uint32_t TAG_MAX_LADEN_WHOLE     = 0x97;  // F.3
constexpr uint32_t TAG_VEHICLE_CATEGORY    = 0x98;  // J
constexpr uint32_t TAG_NUM_AXLES           = 0x99;  // L
constexpr uint32_t TAG_WHEELBASE           = 0x9A;  // M
constexpr uint32_t TAG_BRAKED_TRAILER      = 0x9B;  // O.1
constexpr uint32_t TAG_UNBRAKED_TRAILER    = 0x9C;  // O.2
constexpr uint32_t TAG_RATED_ENGINE_SPEED  = 0x9D;  // P.4
constexpr uint32_t TAG_ENGINE_ID           = 0x9E;  // P.5
constexpr uint32_t TAG_COLOUR              = 0x9F24; // R
constexpr uint32_t TAG_MAX_SPEED           = 0x9F25; // T
constexpr uint32_t TAG_STATIONARY_SOUND    = 0x9F26; // U.1
constexpr uint32_t TAG_ENGINE_SPEED_REF    = 0x9F27; // U.2
constexpr uint32_t TAG_DRIVEBY_SOUND       = 0x9F28; // U.3
constexpr uint32_t TAG_FUEL_CONSUMPTION    = 0x9F2F; // V.7
constexpr uint32_t TAG_CO2                 = 0x9F30; // V.7
constexpr uint32_t TAG_ENV_CATEGORY        = 0x9F31; // V.9
constexpr uint32_t TAG_FUEL_TANK_CAPACITY  = 0x9F32; // W

// Metadata tags
constexpr uint32_t TAG_MEMBER_STATE        = 0x9F33;
constexpr uint32_t TAG_PREVIOUS_DOC        = 0x9F34;
constexpr uint32_t TAG_COMPETENT_AUTH      = 0x9F35;
constexpr uint32_t TAG_ISSUING_AUTH        = 0x9F36;
constexpr uint32_t TAG_DOC_NUMBER          = 0x9F38;

// File header size for initial read
constexpr uint8_t FILE_HEADER_SIZE = 0x20;

// Read chunk sizes
constexpr uint8_t READ_CHUNK_LARGE = 0xFF; // 255 bytes — try first
constexpr uint8_t READ_CHUNK_SMALL = 0x64; // 100 bytes — fallback

// Returns human-readable EU field name for a tag, or empty string if unknown
inline std::string getEuTagName(uint32_t tag)
{
    static const std::unordered_map<uint32_t, std::string> names = {
        {TAG_VERSION,           "Version"},
        {TAG_REG_NUMBER,        "A: Registration number"},
        {TAG_FIRST_REG,         "B: Date of first registration"},
        {TAG_HOLDER_NAME,       "C.1.1: Holder name"},
        {TAG_HOLDER_OTHER_NAMES,"C.1.2: Holder other names"},
        {TAG_HOLDER_ADDRESS,    "C.1.3: Holder address"},
        {TAG_OWNERSHIP_STATUS,  "C.4: Ownership status"},
        {TAG_VEHICLE_MAKE,      "D.1: Vehicle make"},
        {TAG_VEHICLE_TYPE,      "D.2: Vehicle type"},
        {TAG_COMMERCIAL_DESC,   "D.3: Commercial description"},
        {TAG_VIN,               "E: VIN"},
        {TAG_MAX_LADEN_MASS,    "F.1: Max laden mass"},
        {TAG_VEHICLE_MASS,      "G: Vehicle mass"},
        {TAG_EXPIRY,            "H: Expiry date"},
        {TAG_REG_DATE,          "I: Registration date"},
        {TAG_TYPE_APPROVAL,     "K: Type approval"},
        {TAG_ENGINE_CAPACITY,   "P.1: Engine capacity"},
        {TAG_MAX_NET_POWER,     "P.2: Max net power"},
        {TAG_FUEL_TYPE,         "P.3: Fuel type"},
        {TAG_POWER_WEIGHT,      "Q: Power/weight ratio"},
        {TAG_NUM_SEATS,         "S.1: Number of seats"},
        {TAG_STANDING_PLACES,   "S.2: Standing places"},
        {TAG_MAX_LADEN_SERVICE, "F.2: Max laden mass in service"},
        {TAG_MAX_LADEN_WHOLE,   "F.3: Max laden mass whole"},
        {TAG_VEHICLE_CATEGORY,  "J: Vehicle category"},
        {TAG_NUM_AXLES,         "L: Number of axles"},
        {TAG_WHEELBASE,         "M: Wheelbase"},
        {TAG_BRAKED_TRAILER,    "O.1: Braked trailer mass"},
        {TAG_UNBRAKED_TRAILER,  "O.2: Unbraked trailer mass"},
        {TAG_RATED_ENGINE_SPEED,"P.4: Rated engine speed"},
        {TAG_ENGINE_ID,         "P.5: Engine ID number"},
        {TAG_COLOUR,            "R: Colour"},
        {TAG_MAX_SPEED,         "T: Maximum speed"},
        {TAG_STATIONARY_SOUND,  "U.1: Stationary sound level"},
        {TAG_ENGINE_SPEED_REF,  "U.2: Engine speed reference"},
        {TAG_DRIVEBY_SOUND,     "U.3: Drive-by sound level"},
        {TAG_FUEL_CONSUMPTION,  "V.7: Fuel consumption"},
        {TAG_CO2,               "V.7: CO2"},
        {TAG_ENV_CATEGORY,      "V.9: Environmental category"},
        {TAG_FUEL_TANK_CAPACITY,"W: Fuel tank capacity"},
        {TAG_MEMBER_STATE,      "Member State"},
        {TAG_PREVIOUS_DOC,      "Previous document"},
        {TAG_COMPETENT_AUTH,    "Competent authority"},
        {TAG_ISSUING_AUTH,      "Issuing authority"},
        {TAG_DOC_NUMBER,        "Document number"},
    };

    auto it = names.find(tag);
    return (it != names.end()) ? it->second : "";
}

// Returns true for national extension tags (>= 0xC0, single-byte, in 71/72 containers)
inline bool isNationalExtensionTag(uint32_t tag)
{
    return tag >= 0xC0 && tag <= 0xFF;
}

} // namespace euvrc::protocol
