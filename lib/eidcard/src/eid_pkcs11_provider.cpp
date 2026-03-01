// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright hirashix0@proton.me

#include "eidcard/eid_pkcs11_provider.h"
#include "eidcard/eidcard.h"

namespace eidcard {

EIdPKCS11Provider::~EIdPKCS11Provider() = default;

std::shared_ptr<smartcard::PKCS11CardProvider> EIdPKCS11Provider::createInstance() const
{
    return std::make_shared<EIdPKCS11Provider>();
}

bool EIdPKCS11Provider::probe(const std::string& readerName)
{
    return EIdCard::probe(readerName);
}

void EIdPKCS11Provider::connect(const std::string& readerName)
{
    card = std::make_unique<EIdCard>(readerName);
}

smartcard::PKCS11TokenInfo EIdPKCS11Provider::getTokenInfo()
{
    if (!card)
        throw std::runtime_error("EIdPKCS11Provider: not connected");

    smartcard::PKCS11TokenInfo info;
    auto docData = card->readDocumentData();
    auto type = card->getCardType();

    switch (type) {
    case CardType::Gemalto2014:
        info.label = "Serbian eID";
        info.manufacturer = "Gemalto";
        info.model = "MultiApp ID v2.1";
        info.hasPIN = true;
        break;
    case CardType::ForeignerIF2020:
        info.label = "Serbian eID (Foreigner)";
        info.manufacturer = "Gemalto";
        info.model = "MultiApp ID IF";
        info.hasPIN = true;
        break;
    case CardType::Apollo2008:
        info.label = "Serbian eID";
        info.manufacturer = "Oberthur";
        info.model = "ID One v1";
        info.hasPIN = false;
        break;
    default:
        info.label = "Serbian eID";
        info.manufacturer = "Unknown";
        info.model = "Unknown";
        break;
    }

    info.serialNumber = docData.chipSerialNumber;
    return info;
}

std::vector<smartcard::PKCS11ObjectInfo> EIdPKCS11Provider::getObjects()
{
    std::vector<smartcard::PKCS11ObjectInfo> objects;
    if (!card)
        return objects;

    try {
        // readCertificates() traverses the PKI applet once and populates
        // each cert's keyFID directly — no separate discoverKeyReferences() pass needed.
        auto certs = card->readCertificates();
        keyReferenceMap.clear();

        uint8_t idCounter = 1;
        for (const auto& cert : certs) {
            std::vector<uint8_t> id = {idCounter};

            if (cert.keyFID != 0)
                keyReferenceMap[id] = cert.keyFID;

            // Certificate object
            smartcard::PKCS11ObjectInfo certObj;
            certObj.objectClass = 1;       // CKO_CERTIFICATE
            certObj.label = cert.label;
            certObj.id = id;
            certObj.value = cert.derBytes;
            certObj.certificateType = 0;   // CKC_X_509
            certObj.keyType = 0;
            certObj.isToken = true;
            certObj.isPrivate = false;
            certObj.canSign = false;
            objects.push_back(std::move(certObj));

            // Private key object — keyReference is 0 if the cert has no paired key
            smartcard::PKCS11ObjectInfo keyObj;
            keyObj.objectClass = 3;        // CKO_PRIVATE_KEY
            keyObj.label = cert.label;
            keyObj.id = id;
            keyObj.value = {};
            keyObj.certificateType = 0;
            keyObj.keyType = 0;            // CKK_RSA
            keyObj.isToken = true;
            keyObj.isPrivate = true;
            keyObj.canSign = (cert.keyFID != 0);
            keyObj.keyReference = cert.keyFID;
            objects.push_back(std::move(keyObj));

            ++idCounter;
        }
    } catch (...) {
        // Card types that don't support certificates return empty
    }

    return objects;
}

unsigned long EIdPKCS11Provider::login(unsigned long userType,
                                       const std::vector<uint8_t>& pin)
{
    if (userType != 1)  // CKU_USER
        return 0x00000103UL;  // CKR_USER_TYPE_INVALID
    if (!card)
        return 0x00000030UL;  // CKR_DEVICE_ERROR
    if (card->getCardType() == CardType::Apollo2008)
        return 0x00000103UL;  // CKR_USER_TYPE_INVALID

    try {
        std::string pinStr(pin.begin(), pin.end());
        auto result = card->verifyPIN(pinStr);
        if (result.success) return 0;  // CKR_OK
        if (result.blocked) return 0x000000A4UL;  // CKR_PIN_LOCKED
        return 0x000000A0UL;  // CKR_PIN_INCORRECT
    } catch (...) {
        return 0x00000030UL;  // CKR_DEVICE_ERROR
    }
}

unsigned long EIdPKCS11Provider::logout()
{
    return 0;  // CKR_OK
}

std::vector<uint8_t> EIdPKCS11Provider::signData(const std::vector<uint8_t>& keyId,
                                                   const std::vector<uint8_t>& data)
{
    if (!card)
        throw std::runtime_error("EIdPKCS11Provider: not connected");

    auto it = keyReferenceMap.find(keyId);
    if (it == keyReferenceMap.end())
        throw std::runtime_error("EIdPKCS11Provider: unknown key ID");

    return card->signData(it->second, data);
}

void EIdPKCS11Provider::reconnectCard()
{
    if (card)
        card->reconnectConnection();
}

} // namespace eidcard
