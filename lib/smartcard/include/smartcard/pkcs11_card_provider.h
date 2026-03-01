// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright hirashix0@proton.me

#ifndef SMARTCARD_PKCS11_CARD_PROVIDER_H
#define SMARTCARD_PKCS11_CARD_PROVIDER_H

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace smartcard {

struct PKCS11TokenInfo {
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

struct PKCS11ObjectInfo {
    unsigned long objectClass;       // 1=certificate, 3=private key
    std::string label;
    std::vector<uint8_t> id;         // CKA_ID linking cert to key
    std::vector<uint8_t> value;      // DER bytes for certs; empty for keys
    unsigned long certificateType;   // 0=X.509 for certs
    unsigned long keyType;           // 0=RSA for keys
    bool isToken = true;
    bool isPrivate = false;
    bool canSign = false;
    uint16_t keyReference = 0;   // on-card key FID for MSE SET (private keys only)
};

class PKCS11CardProvider {
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
    virtual unsigned long login(unsigned long userType,
                                const std::vector<uint8_t>& pin) = 0;
    virtual unsigned long logout() = 0;

    // Sign data using the private key identified by keyId (CKA_ID).
    // data = DER DigestInfo for CKM_RSA_PKCS; card applies PKCS#1 v1.5 padding.
    // Returns raw signature bytes (256 for RSA-2048).
    virtual std::vector<uint8_t> signData(const std::vector<uint8_t>& keyId,
                                           const std::vector<uint8_t>& data) = 0;

    // Reconnect the underlying card connection after SCARD_W_RESET_CARD.
    // Default implementation is a no-op (providers that don't hold a persistent
    // connection need not override this).
    virtual void reconnectCard() {}
};

} // namespace smartcard

#endif // SMARTCARD_PKCS11_CARD_PROVIDER_H
