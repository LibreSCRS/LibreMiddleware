// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace smartcard {

// PKCS#11 return values for provider use (avoids pkcs11t.h dependency).
// Values from PKCS#11 v2.40 §3.1: CK_RV codes.
namespace pkcs11_rv {
constexpr unsigned long OK = 0x00000000UL;
constexpr unsigned long DEVICE_ERROR = 0x00000030UL;
constexpr unsigned long PIN_INCORRECT = 0x000000A0UL;
constexpr unsigned long PIN_INVALID = 0x000000A1UL;
constexpr unsigned long PIN_LOCKED = 0x000000A4UL;
constexpr unsigned long USER_TYPE_INVALID = 0x00000103UL;
} // namespace pkcs11_rv

struct PKCS11TokenInfo
{
    std::string label;
    std::string manufacturer;
    std::string model;
    std::string serialNumber;
    uint8_t hardwareVersionMajor = 0;
    uint8_t hardwareVersionMinor = 0;
    uint8_t firmwareVersionMajor = 0;
    uint8_t firmwareVersionMinor = 0;
    uint8_t pinMinLen = 4;
    uint8_t pinMaxLen = 8;
    bool hasPIN = false;
    bool hasProtectedAuthPath = false;
};

struct PKCS11ObjectInfo
{
    unsigned long objectClass; // 1=certificate, 3=private key
    std::string label;
    std::vector<uint8_t> id;       // CKA_ID linking cert to key
    std::vector<uint8_t> value;    // DER bytes for certs; empty for keys
    unsigned long certificateType; // 0=X.509 for certs
    unsigned long keyType;         // 0=RSA for keys
    bool isToken = true;
    bool isPrivate = false;
    bool canSign = false;
    bool canDecrypt = false;       // CKA_DECRYPT (key exchange keys)
    bool canEncrypt = false;       // CKA_ENCRYPT (key exchange keys)
    bool canWrap = false;          // CKA_WRAP (key exchange keys)
    bool canUnwrap = false;        // CKA_UNWRAP (key exchange keys)
    uint16_t keyReference = 0;     // on-card key FID for MSE SET (private keys only)
    std::vector<uint8_t> ecParams; // DER-encoded curve OID (EC private keys)
    std::vector<uint8_t> ecPoint;  // DER-encoded EC public key point (EC private keys)
};

// PIN contract for PKCS11CardProvider implementations:
// - login(): Provider SHOULD cache PIN securely if needed for sign re-verification.
// - logout(): Provider MUST clear cached PIN with OPENSSL_cleanse().
// - signData()/signMessage(): Provider MAY re-verify PIN with card if required
//   by the card protocol (e.g., PIV requires PIN per-operation).
// - Use OPENSSL_cleanse() for all PIN copies. Avoid storing in std::string
//   long-term (SSO may prevent cleansing). Prefer std::vector<uint8_t>.

class PKCS11CardProvider
{
public:
    virtual ~PKCS11CardProvider() = default;

    // Create a new instance of this provider type (factory method).
    // Used to create per-slot provider instances.
    virtual std::shared_ptr<PKCS11CardProvider> createInstance() const = 0;

    virtual bool probe(const std::string& readerName) = 0;
    virtual void connect(const std::string& readerName) = 0;
    virtual PKCS11TokenInfo getTokenInfo() = 0;
    virtual std::vector<PKCS11ObjectInfo> getObjects() = 0;

    // Return 0 on success, nonzero PKCS#11 CKR_* error code.
    virtual unsigned long login(unsigned long userType, const std::vector<uint8_t>& pin) = 0;
    virtual unsigned long logout() = 0;

    // Sign data using the private key identified by keyId (CKA_ID).
    // data = DER DigestInfo for CKM_RSA_PKCS; card applies PKCS#1 v1.5 padding.
    // Returns raw signature bytes.
    virtual std::vector<uint8_t> signData(const std::vector<uint8_t>& keyId, const std::vector<uint8_t>& data) = 0;

    // Sign raw message data using a combined hash+sign mechanism.
    // mechanismType = PKCS#11 mechanism (e.g. CKM_SHA256_RSA_PKCS).
    // digestInfo = DER DigestInfo built by the PKCS#11 library (hash + OID wrapper).
    // rawData = original unhashed message bytes.
    // Default: delegates to signData(keyId, digestInfo).
    // Override for cards that require hash-specific signature algorithms.
    virtual std::vector<uint8_t> signMessage(const std::vector<uint8_t>& keyId, const std::vector<uint8_t>& digestInfo,
                                             const std::vector<uint8_t>& /*rawData*/, unsigned long /*mechanismType*/)
    {
        return signData(keyId, digestInfo);
    }

    // Whether this provider supports RSA-PSS mechanisms.
    // Default: true. Override to return false for cards that don't support PSS (e.g. PIV).
    virtual bool supportsPSS() const
    {
        return true;
    }

    // Reconnect the underlying card connection after SCARD_W_RESET_CARD.
    // Default implementation is a no-op (providers that don't hold a persistent
    // connection need not override this).
    virtual void reconnectCard() {}
};

} // namespace smartcard
