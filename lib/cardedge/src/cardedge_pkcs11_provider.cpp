// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "cardedge/cardedge_pkcs11_provider.h"
#include "cardedge/cardedge.h"
#include "cardedge/pki_applet_guard.h"
#include "smartcard/apdu.h"
#include "cardedge_protocol.h"
#include <openssl/crypto.h>

namespace cardedge {

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
        return true;
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
    if (userType != 1)       // CKU_USER
        return 0x00000103UL; // CKR_USER_TYPE_INVALID
    if (!connection)
        return 0x00000030UL; // CKR_DEVICE_ERROR

    try {
        PkiAppletGuard guard(*connection);
        std::string pinStr(pin.begin(), pin.end());
        auto result = verifyPIN(*connection, pinStr);
        OPENSSL_cleanse(pinStr.data(), pinStr.size());
        if (result.success)
            return 0; // CKR_OK
        if (result.blocked)
            return 0x000000A4UL; // CKR_PIN_LOCKED
        return 0x000000A0UL;     // CKR_PIN_INCORRECT
    } catch (...) {
        return 0x00000030UL; // CKR_DEVICE_ERROR
    }
}

unsigned long CardEdgePKCS11Provider::logout()
{
    return 0; // CKR_OK
}

std::vector<uint8_t> CardEdgePKCS11Provider::signData(const std::vector<uint8_t>& keyId,
                                                      const std::vector<uint8_t>& data)
{
    if (!connection)
        throw std::runtime_error("CardEdgePKCS11Provider: not connected");

    auto it = keyReferenceMap.find(keyId);
    if (it == keyReferenceMap.end())
        throw std::runtime_error("CardEdgePKCS11Provider: unknown key ID");

    PkiAppletGuard guard(*connection);
    return cardedge::signData(*connection, it->second, data);
}

void CardEdgePKCS11Provider::reconnectCard()
{
    if (connection)
        connection->reconnect();
}

} // namespace cardedge
