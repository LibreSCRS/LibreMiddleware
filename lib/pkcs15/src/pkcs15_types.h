// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

#include <array>
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

enum class KeyType : uint8_t { Rsa = 0, Ec = 1 };

struct PrivateKeyInfo
{
    std::string label;
    std::vector<uint8_t> id;
    std::vector<uint8_t> authId; // from CommonObjectAttributes — references PinInfo.id
    uint16_t keySizeBits = 0;
    std::vector<uint8_t> path;
    uint8_t accessFlags = 0;
    uint8_t keyReference = 0; // from CommonKeyAttributes (used when path is empty)
    bool canSign = false;     // digitalSignature (bit 0) or nonRepudiation (bit 1) in usage flags
    KeyType keyType = KeyType::Rsa;
};

enum class PinType { Bcd = 0, Ascii = 1, Utf8 = 2, HalfNibbleBcd = 3, Iso9564 = 4 };

struct PinInfo
{
    std::string label;
    std::vector<uint8_t> id; // from CommonAuthObjectAttributes — this PIN's PKCS#15 object ID
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
    bool soPin = false;          // pinFlags soPin bit
    bool changeDisabled = false; // pinFlags change-disabled bit
    // Protecting object's id from CommonObjectAttributes (the auth object
    // this PIN is protected/unblocked by — mirrors PrivateKeyInfo.authId).
    // Empty when the entry carries no authId.
    std::vector<uint8_t> authId;
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

// Signing scheme — abstracts PKCS#11 mechanism types for the card layer.
enum class SignScheme : uint8_t {
    RsaPkcs1,
    RsaSha1Pkcs1,
    RsaSha256Pkcs1,
    RsaSha384Pkcs1,
    RsaSha512Pkcs1,
    RsaPssSha256,
    RsaPssSha384,
    RsaPssSha512,
    EcdsaRaw,
};

// ISO 7816-8 / BSI TR-03110 algorithm references for MSE SET.
// Signature algorithms (used in Digital Signature Template, P2=0xB6)
namespace sig_algo {
constexpr uint8_t RSA_PKCS1_V15 = 0x02;    // RSA PKCS#1 v1.5 (de facto standard)
constexpr uint8_t RSA_RAW = 0x08;          // RSA PKCS#1 v1.5 plain (terminal encodes)
constexpr uint8_t RSA_SHA1_PKCS1 = 0x0A;   // RSA PKCS#1 v1.5 with SHA-1
constexpr uint8_t RSA_SHA256_PKCS1 = 0x28; // RSA PKCS#1 v1.5 with SHA-256 (non-IAS-ECC vendors)
constexpr uint8_t RSA_SHA384_PKCS1 = 0x29; // RSA PKCS#1 v1.5 with SHA-384 (non-IAS-ECC vendors)
constexpr uint8_t RSA_SHA512_PKCS1 = 0x2A; // RSA PKCS#1 v1.5 with SHA-512 (non-IAS-ECC vendors)
// IAS-ECC convention (certain hash-on-card SSCDs such as SCE 8.0-C2V0,
// German nPA, and several other QSCDs) combines a base RSA algorithm
// with a hash flag:
//   RSA_PKCS=0x02 | SHA1=0x10 -> 0x12   (same as RSA_SHA1_PKCS1 by coincidence)
//   RSA_PKCS=0x02 | SHA2=0x40 -> 0x42   (the SHA-256 PKCS#1 algo on IAS-ECC)
// Sign emits both legacy (0x28) and IAS-ECC (0x42) attempts so a single
// code path serves both card families.
constexpr uint8_t RSA_SHA256_PKCS1_IASECC = 0x42;
constexpr uint8_t RSASSA_PSS_SHA256 = 0x2B; // RSASSA-PSS with SHA-256
constexpr uint8_t RSASSA_PSS_SHA384 = 0x2C; // RSASSA-PSS with SHA-384
constexpr uint8_t RSASSA_PSS_SHA512 = 0x2D; // RSASSA-PSS with SHA-512
constexpr uint8_t ECDSA_PLAIN = 0x04;       // ECDSA plain (no internal hashing)
} // namespace sig_algo

// PKCS#15 application AID (A0 00 00 00 63 "PKCS-15")
inline constexpr std::array<uint8_t, 12> kPkcs15Aid = {0xA0, 0x00, 0x00, 0x00, 0x63, 0x50,
                                                       0x4B, 0x43, 0x53, 0x2D, 0x31, 0x35};

// PKCS#15 DF file ID
inline constexpr std::array<uint8_t, 2> DF_PKCS15_FID = {0x50, 0x15};

// Vendor AODF defaults used by the deferred-profile path when an applet
// refuses PKCS#15 directory reads pre-login: the slot must guess a
// PinInfo to drive the VERIFY apdu, then read the real AODF once
// authentication succeeds. The reference numbers below match the most
// common vendor convention ("User PIN" / "SO PIN" sections of the
// PKCS#15 token AODF) and have proven stable across hardware variants.
inline constexpr uint8_t kSafeSignDefaultUserPinRef = 0x03; // User PIN reference.
inline constexpr uint8_t kSafeSignDefaultSoPinRef = 0x01;   // SO PIN reference.

} // namespace pkcs15
