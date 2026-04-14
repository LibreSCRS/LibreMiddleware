// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "piv/piv_pkcs11_provider.h"
#include "piv/piv_card.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <sstream>
#include <iomanip>

namespace piv {

// Shared PIN-string scrubber lives in smartcard/secure_buffer.h.
using ::smartcard::PinStringScrubber;

namespace {

// Extract RSA key info from DER certificate.
// Returns {keySizeBytes, algId, isRSA}. ECC keys return isRSA=false.
struct CertKeyInfo
{
    size_t keySizeBytes;
    uint8_t algId;
    bool isRSA;
};

CertKeyInfo keyInfoFromCert(const std::vector<uint8_t>& derBytes)
{
    const uint8_t* p = derBytes.data();
    X509* cert = d2i_X509(nullptr, &p, static_cast<long>(derBytes.size()));
    if (!cert)
        return {256, 0x07, true}; // assume RSA-2048 on parse failure

    EVP_PKEY* pkey = X509_get0_pubkey(cert);
    CertKeyInfo info{0, 0, false};
    if (pkey && EVP_PKEY_id(pkey) == EVP_PKEY_RSA) {
        int bits = EVP_PKEY_bits(pkey);
        info.keySizeBytes = static_cast<size_t>(bits) / 8;
        // NIST SP 800-78: 0x06=RSA-1024, 0x07=RSA-2048
        info.algId = (bits <= 1024) ? 0x06 : 0x07;
        info.isRSA = true;
    }
    // ECC keys: info stays {0, 0, false} — not supported for signing yet
    X509_free(cert);
    return info;
}

} // namespace

PivPKCS11Provider::PivPKCS11Provider() = default;
PivPKCS11Provider::~PivPKCS11Provider() = default;
PivPKCS11Provider::PivPKCS11Provider(PivPKCS11Provider&&) noexcept = default;
PivPKCS11Provider& PivPKCS11Provider::operator=(PivPKCS11Provider&&) noexcept = default;

std::shared_ptr<smartcard::PKCS11CardProvider> PivPKCS11Provider::createInstance() const
{
    return std::make_shared<PivPKCS11Provider>();
}

bool PivPKCS11Provider::probe(const std::string& readerName)
{
    try {
        smartcard::PCSCConnection conn(readerName);
        PIVCard pivCard(conn);
        return pivCard.probe();
    } catch (...) {
        return false;
    }
}

void PivPKCS11Provider::connect(const std::string& readerName)
{
    connection = std::make_unique<smartcard::PCSCConnection>(readerName);
    card = std::make_unique<PIVCard>(*connection);
}

smartcard::PKCS11TokenInfo PivPKCS11Provider::getTokenInfo()
{
    if (!connection || !card)
        throw std::runtime_error("PivPKCS11Provider: not connected");

    smartcard::PKCS11TokenInfo info;
    info.label = "PIV Card";
    info.manufacturer = "PIV";
    info.model = "NIST SP 800-73";
    info.hasPIN = true;
    info.pinMinLen = 6;
    info.pinMaxLen = 8;

    // Try to read CHUID for serial number (hex-encoded GUID)
    try {
        auto chuid = card->readCHUID();
        if (!chuid.guid.empty()) {
            std::ostringstream oss;
            for (auto b : chuid.guid)
                oss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(b);
            info.serialNumber = oss.str();
        }
    } catch (...) {
        // Non-fatal: use default empty serial
    }

    if (info.serialNumber.empty())
        info.serialNumber = "0000000000000000";

    return info;
}

std::vector<smartcard::PKCS11ObjectInfo> PivPKCS11Provider::getObjects()
{
    std::vector<smartcard::PKCS11ObjectInfo> objects;
    if (!connection || !card)
        return objects;

    try {
        auto certs = card->readCertificates();
        keyInfoMap.clear();

        uint8_t idCounter = 1;
        for (const auto& cert : certs) {
            if (cert.certBytes.empty())
                continue;

            std::vector<uint8_t> id = {idCounter};
            auto certKeyInfo = keyInfoFromCert(cert.certBytes);
            if (certKeyInfo.isRSA)
                keyInfoMap[id] = {cert.keyReference, certKeyInfo.keySizeBytes, certKeyInfo.algId};

            // Certificate object
            smartcard::PKCS11ObjectInfo certObj;
            certObj.objectClass = 1; // CKO_CERTIFICATE
            certObj.label = cert.slotName;
            certObj.id = id;
            certObj.value = cert.certBytes;
            certObj.certificateType = 0; // CKC_X_509
            certObj.keyType = 0;
            certObj.isToken = true;
            certObj.isPrivate = false;
            certObj.canSign = false;
            objects.push_back(std::move(certObj));

            // Private key object
            smartcard::PKCS11ObjectInfo keyObj;
            keyObj.objectClass = 3; // CKO_PRIVATE_KEY
            keyObj.label = cert.slotName;
            keyObj.id = id;
            keyObj.value = {};
            keyObj.certificateType = 0;
            keyObj.keyType = 0; // CKK_RSA
            keyObj.isToken = true;
            keyObj.isPrivate = true;
            keyObj.canSign = certKeyInfo.isRSA; // ECC signing not yet supported
            keyObj.keyReference = cert.keyReference;

            // Key Management key (9D) supports decrypt/encrypt/wrap/unwrap
            bool isKeyMgmt = (cert.keyReference == 0x9D);
            keyObj.canDecrypt = isKeyMgmt;
            keyObj.canEncrypt = isKeyMgmt;
            keyObj.canWrap = isKeyMgmt;
            keyObj.canUnwrap = isKeyMgmt;

            objects.push_back(std::move(keyObj));

            ++idCounter;
        }
    } catch (...) {
        // Cards that don't support certificates return empty
    }

    return objects;
}

unsigned long PivPKCS11Provider::login(unsigned long userType, const std::vector<uint8_t>& pin)
{
    using namespace smartcard::pkcs11_rv;
    if (userType != 1) // CKU_USER
        return USER_TYPE_INVALID;
    if (!connection || !card)
        return DEVICE_ERROR;

    try {
        card->probe(); // Re-select PIV applet (may be lost after reconnect)
        // SSO-safe + exception-safe via PinStringScrubber RAII.
        std::string pinStr(pin.begin(), pin.end());
        PinStringScrubber scrubber{pinStr};
        auto result = card->verifyPIN(0x80, pinStr);
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

unsigned long PivPKCS11Provider::logout()
{
    cachedPin = smartcard::SecureBuffer{};
    return smartcard::pkcs11_rv::OK;
}

std::vector<uint8_t> PivPKCS11Provider::signData(const std::vector<uint8_t>& keyId, const std::vector<uint8_t>& data)
{
    if (!connection || !card)
        throw std::runtime_error("PivPKCS11Provider: not connected");

    auto it = keyInfoMap.find(keyId);
    if (it == keyInfoMap.end())
        throw std::runtime_error("PivPKCS11Provider: unknown key ID");

    if (cachedPin.empty())
        throw std::runtime_error("PivPKCS11Provider: not logged in");

    // Re-select applet and re-verify PIN in same sequence —
    // SELECT AID resets security status on most cards.
    card->probe();
    // SSO-safe + exception-safe via PinStringScrubber RAII.
    std::string pinStr(cachedPin.begin(), cachedPin.end());
    PinStringScrubber scrubber{pinStr};
    auto pinResult = card->verifyPIN(0x80, pinStr);
    if (!pinResult.success)
        throw std::runtime_error("PivPKCS11Provider: PIN re-verification failed");

    const auto& info = it->second;
    return card->signData(info.keyRef, info.algId, info.keySizeBytes, data);
}

void PivPKCS11Provider::reconnectCard()
{
    if (connection)
        connection->reconnect();
}

} // namespace piv
