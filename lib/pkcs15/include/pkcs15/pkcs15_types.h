// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace pkcs15 {

struct TokenInfo
{
    std::string label;
    std::string serialNumber;
    std::string manufacturer;
};

struct CertificateInfo
{
    std::string label;
    std::vector<uint8_t> id;
    bool authority = false;
    std::vector<uint8_t> path;
};

struct PrivateKeyInfo
{
    std::string label;
    std::vector<uint8_t> id;
    uint16_t keySizeBits = 0;
    std::vector<uint8_t> path;
    uint8_t accessFlags = 0;
};

enum class PinType { Bcd = 0, Ascii = 1, Utf8 = 2, HalfNibbleBcd = 3, Iso9564 = 4 };

struct PinInfo
{
    std::string label;
    uint8_t pinReference = 0;
    PinType pinType = PinType::Utf8;
    int minLength = 0;
    int storedLength = 0;
    int maxLength = 0;
    bool hasMaxLength = false;
    int maxRetries = 0;
    uint8_t padChar = 0x00;
    std::string lastPinChange;
    std::vector<uint8_t> path;
    bool local = false;
    bool initialized = false;
    bool unblockDisabled = false;
    bool unblockingPin = false;
};

struct ObjectDirectory
{
    std::vector<uint8_t> privateKeysPath;
    std::vector<uint8_t> publicKeysPath;
    std::vector<uint8_t> trustedPublicKeysPath;
    std::vector<uint8_t> secretKeysPath;
    std::vector<uint8_t> certificatesPath;
    std::vector<uint8_t> trustedCertificatesPath;
    std::vector<uint8_t> usefulCertificatesPath;
    std::vector<uint8_t> dataObjectsPath;
    std::vector<uint8_t> authObjectsPath;
};

struct PKCS15Profile
{
    TokenInfo tokenInfo;
    ObjectDirectory odf;
    std::vector<CertificateInfo> certificates;
    std::vector<PrivateKeyInfo> privateKeys;
    std::vector<PinInfo> pins;
};

struct PinResult
{
    bool success = false;
    int retriesLeft = -1;
    bool blocked = false;
};

} // namespace pkcs15
