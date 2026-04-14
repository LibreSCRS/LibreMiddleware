// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "cardedge/cardedge_pkcs11_provider.h"
#include "cardedge/cardedge.h"
#include "cardedge/pki_applet_guard.h"
#include "smartcard/apdu.h"
#include "cardedge_protocol.h"
#include <openssl/crypto.h>

namespace cardedge {

// Shared PIN-string scrubber lives in smartcard/secure_buffer.h.
using ::smartcard::PinStringScrubber;

CardEdgePKCS11Provider::~CardEdgePKCS11Provider() = default;

std::shared_ptr<smartcard::PKCS11CardProvider> CardEdgePKCS11Provider::createInstance() const
{
    return std::make_shared<CardEdgePKCS11Provider>();
}

bool CardEdgePKCS11Provider::probe(const std::string& readerName)
{
    try {
        smartcard::PCSCConnection conn(readerName);
        PkiAppletGuard guard(conn);
        // SELECT root dir 0x7000 — CardEdge-specific, not present on standard PKCS#15.
        // Without this, generic PKCS#15 cards (e.g. Gemalto AET) would match.
        auto resp = conn.transmit(smartcard::selectByFileId(0x70, 0x00));
        return resp.isSuccess();
    } catch (...) {
        return false;
    }
}

void CardEdgePKCS11Provider::connect(const std::string& readerName)
{
    connection = std::make_unique<smartcard::PCSCConnection>(readerName);
}

smartcard::PKCS11TokenInfo CardEdgePKCS11Provider::getTokenInfo()
{
    if (!connection)
        throw std::runtime_error("CardEdgePKCS11Provider: not connected");

    smartcard::PKCS11TokenInfo info;
    info.label = "Serbian CardEdge";
    info.manufacturer = "CardEdge";
    info.model = "PKCS#15";
    info.serialNumber = "0000000000000000"; // Required by Java SunPKCS11 provider
    info.hasPIN = true;
    return info;
}

std::vector<smartcard::PKCS11ObjectInfo> CardEdgePKCS11Provider::getObjects()
{
    std::vector<smartcard::PKCS11ObjectInfo> objects;
    if (!connection)
        return objects;

    try {
        PkiAppletGuard guard(*connection);
        auto certs = readCertificates(*connection);
        keyReferenceMap.clear();

        uint8_t idCounter = 1;
        for (const auto& cert : certs) {
            std::vector<uint8_t> id = {idCounter};

            if (cert.keyFID != 0)
                keyReferenceMap[id] = cert.keyFID;

            // Certificate object
            smartcard::PKCS11ObjectInfo certObj;
            certObj.objectClass = 1; // CKO_CERTIFICATE
            certObj.label = cert.label;
            certObj.id = id;
            certObj.value = cert.derBytes;
            certObj.certificateType = 0; // CKC_X_509
            certObj.keyType = 0;
            certObj.isToken = true;
            certObj.isPrivate = false;
            certObj.canSign = false;
            objects.push_back(std::move(certObj));

            // Private key object
            smartcard::PKCS11ObjectInfo keyObj;
            keyObj.objectClass = 3; // CKO_PRIVATE_KEY
            keyObj.label = cert.label;
            keyObj.id = id;
            keyObj.value = {};
            keyObj.certificateType = 0;
            keyObj.keyType = 0; // CKK_RSA
            keyObj.isToken = true;
            keyObj.isPrivate = true;
            keyObj.canSign = (cert.keyFID != 0);
            // Key exchange keys (kxc) additionally support encrypt/decrypt/wrap/unwrap.
            // Matches OpenSC srbeid driver: ENCRYPT|DECRYPT|WRAP|UNWRAP|SIGN for kxc,
            // SIGN|NONREPUDIATION for ksc.
            // Detect kxc from FID: AT_KEYEXCHANGE=1 → (keyFID & 0x000C) == 0x0004
            bool isKxc = (cert.keyFID != 0 && (cert.keyFID & 0x000C) == 0x0004);
            keyObj.canDecrypt = isKxc;
            keyObj.canEncrypt = isKxc;
            keyObj.canWrap = isKxc;
            keyObj.canUnwrap = isKxc;
            keyObj.keyReference = cert.keyFID;
            objects.push_back(std::move(keyObj));

            ++idCounter;
        }
    } catch (...) {
        // Cards that don't support certificates return empty
    }

    return objects;
}

unsigned long CardEdgePKCS11Provider::login(unsigned long userType, const std::vector<uint8_t>& pin)
{
    using namespace smartcard::pkcs11_rv;
    if (userType != 1) // CKU_USER
        return USER_TYPE_INVALID;
    if (!connection)
        return DEVICE_ERROR;

    try {
        PkiAppletGuard guard(*connection);
        // SSO-safe: PIN < 22 bytes. Scrubber cleanses pinStr on scope exit
        // (normal or exception); previous explicit cleanse calls are now
        // redundant but harmless.
        std::string pinStr(pin.begin(), pin.end());
        PinStringScrubber scrubber{pinStr};
        auto result = verifyPIN(*connection, pinStr);
        if (result.success) {
            cachedPin = smartcard::SecureBuffer(pinStr);
            return OK;
        }
        if (result.blocked)
            return PIN_LOCKED;
        return PIN_INCORRECT;
    } catch (...) {
        return DEVICE_ERROR;
    }
}

unsigned long CardEdgePKCS11Provider::logout()
{
    cachedPin = smartcard::SecureBuffer{};
    return smartcard::pkcs11_rv::OK;
}

std::vector<uint8_t> CardEdgePKCS11Provider::signData(const std::vector<uint8_t>& keyId,
                                                      const std::vector<uint8_t>& data)
{
    if (!connection)
        throw std::runtime_error("CardEdgePKCS11Provider: not connected");

    auto it = keyReferenceMap.find(keyId);
    if (it == keyReferenceMap.end())
        throw std::runtime_error("CardEdgePKCS11Provider: unknown key ID");

    if (cachedPin.empty())
        throw std::runtime_error("CardEdgePKCS11Provider: not logged in");

    PkiAppletGuard guard(*connection);

    // Re-verify PIN — SELECT applet (via guard) resets security status.
    // SSO-safe + exception-safe via PinScrubber.
    std::string pinStr(cachedPin.begin(), cachedPin.end());
    PinStringScrubber scrubber{pinStr};
    auto pinResult = verifyPIN(*connection, pinStr);
    if (!pinResult.success)
        throw std::runtime_error("CardEdgePKCS11Provider: PIN re-verification failed");

    return cardedge::signData(*connection, it->second, data);
}

void CardEdgePKCS11Provider::reconnectCard()
{
    if (connection)
        connection->reconnect();
}

} // namespace cardedge
