// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "pkcs15_pkcs11_provider.h"
#include "pkcs15_card.h"
#include <pace.h>
#include <secure_messaging.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <smartcard/secure_buffer.h>
#include <algorithm>
#include <iomanip>
#include <iostream>
#include <sstream>

namespace pkcs15 {

// Shared PIN-string scrubber lives in smartcard/secure_buffer.h as
// smartcard::PinStringScrubber. Alias keeps local call sites terse.
using ::smartcard::PinStringScrubber;

// Translate PKCS#11 mechanism type to card-layer SignScheme.
// Raw hex values used intentionally to avoid pkcs11t.h dependency in the pkcs15 library.
// Values from PKCS#11 v2.40 Table 34: CKM_RSA_PKCS=0x0001, CKM_SHA1_RSA_PKCS=0x0006,
// CKM_SHA256_RSA_PKCS=0x0040, ..., CKM_SHA256_RSA_PKCS_PSS=0x0043, etc.
// CKM_ECDSA=0x1041, CKM_ECDSA_SHA256=0x1044, etc.
static SignScheme mechanismToScheme(unsigned long mechanismType, KeyType keyType)
{
    // Reject RSA mechanisms for EC keys and vice versa
    bool isEcMechanism = (mechanismType >= 0x1040 && mechanismType <= 0x1049);
    if (keyType == KeyType::Ec && !isEcMechanism)
        throw std::runtime_error("Pkcs15PKCS11Provider: RSA mechanism used with EC key");
    if (keyType == KeyType::Rsa && isEcMechanism)
        throw std::runtime_error("Pkcs15PKCS11Provider: EC mechanism used with RSA key");

    switch (mechanismType) {
    case 0x0001:
        return SignScheme::RsaPkcs1;
    case 0x0006:
        return SignScheme::RsaSha1Pkcs1;
    case 0x0040:
        return SignScheme::RsaSha256Pkcs1;
    case 0x0041:
        return SignScheme::RsaSha384Pkcs1;
    case 0x0042:
        return SignScheme::RsaSha512Pkcs1;
    case 0x0043:
        return SignScheme::RsaPssSha256;
    case 0x0044:
        return SignScheme::RsaPssSha384;
    case 0x0045:
        return SignScheme::RsaPssSha512;
    case 0x1041:
        return SignScheme::EcdsaRaw;
    default: {
        std::ostringstream oss;
        oss << "Pkcs15PKCS11Provider: unsupported mechanism 0x" << std::hex << std::setfill('0') << std::setw(4)
            << mechanismType;
        throw std::runtime_error(oss.str());
    }
    }
}

Pkcs15PKCS11Provider::Pkcs15PKCS11Provider() = default;
Pkcs15PKCS11Provider::~Pkcs15PKCS11Provider() = default;
Pkcs15PKCS11Provider::Pkcs15PKCS11Provider(Pkcs15PKCS11Provider&&) noexcept = default;
Pkcs15PKCS11Provider& Pkcs15PKCS11Provider::operator=(Pkcs15PKCS11Provider&&) noexcept = default;

bool Pkcs15PKCS11Provider::isUserPin(const PinInfo& pin)
{
    // Skip PUK (unblocking PINs) and PACE CAN
    if (pin.unblockingPin)
        return false;
    auto label = pin.label;
    std::transform(label.begin(), label.end(), label.begin(), ::tolower);
    if (label.find("puk") != std::string::npos)
        return false;
    if (label.find("can") != std::string::npos || label.find("pace") != std::string::npos)
        return false;
    return true;
}

bool Pkcs15PKCS11Provider::probeForPace(smartcard::PCSCConnection& conn, PaceProbeResult& result)
{
    // Try reading EF.CardAccess from MF (available without PACE)
    // SELECT MF
    auto r1 = conn.transmit(smartcard::selectByFileId(0x3F, 0x00, 0x0C));
    if (!r1.isSuccess())
        r1 = conn.transmit(smartcard::selectByFileId(0x3F, 0x00));
    if (!r1.isSuccess())
        return false;

    // SELECT EF.CardAccess (FID 011C)
    auto r2 = conn.transmit(smartcard::selectByFileId(0x01, 0x1C, 0x0C));
    if (!r2.isSuccess())
        r2 = conn.transmit(smartcard::selectByFileId(0x01, 0x1C));
    if (r2.sw1 != 0x90 && r2.sw1 != 0x62)
        return false;

    // READ BINARY
    auto r3 = conn.transmit(smartcard::APDUCommand{0x00, 0xB0, 0x00, 0x00, {}, 0, true});
    if (r3.data.empty())
        return false;

    // Parse PACE OIDs
    auto paceEntries = emrtd::crypto::parseCardAccessWithParams(r3.data);
    if (paceEntries.empty())
        return false;

    result.cardAccessData = r3.data;
    result.paceRequired = true;
    return true;
}

void Pkcs15PKCS11Provider::installSmFilter()
{
    if (!connection || !sm)
        return;

    auto* smPtr = sm.get();
    auto* connPtr = connection.get();
    connection->setTransmitFilter([smPtr, connPtr](const smartcard::APDUCommand& cmd) -> smartcard::APDUResponse {
        auto cmdBytes = cmd.toBytes();
        auto protectedApdu = smPtr->protect(cmdBytes);
        if (protectedApdu.size() < 5)
            return {{}, 0x69, 0x82};

        auto resp = connPtr->transmitRaw(protectedApdu.data(), static_cast<DWORD>(protectedApdu.size()));

        // Handle 61XX chaining: card has more SM response data available.
        // This occurs when the SM-protected response exceeds Le bytes
        // (e.g., RSA-3072 signature = 384 bytes > short Le max 256).
#ifndef NDEBUG
        if (resp.sw1 == 0x61)
            std::cerr << "[SM] Response chaining: 61" << std::hex << (int)resp.sw2 << std::dec << std::endl;
#endif
        while (resp.sw1 == 0x61) {
            uint8_t getResponseApdu[] = {0x00, 0xC0, 0x00, 0x00, resp.sw2};
            auto grResp = connPtr->transmitRaw(getResponseApdu, sizeof(getResponseApdu));
            resp.data.insert(resp.data.end(), grResp.data.begin(), grResp.data.end());
            resp.sw1 = grResp.sw1;
            resp.sw2 = grResp.sw2;
        }

        std::vector<uint8_t> respBytes = resp.data;
        respBytes.push_back(resp.sw1);
        respBytes.push_back(resp.sw2);

        auto result = smPtr->unprotectWithSW(respBytes);
        if (!result)
            return {{}, 0x69, 0x82};

        return {std::move(result->data), result->sw1, result->sw2};
    });
}

void Pkcs15PKCS11Provider::ensureProfile()
{
    if (!pins.empty())
        return;
    card->selectApplet();
    auto profile = card->readProfile();
    pins = profile.pins;
    privateKeys = profile.privateKeys;
}

const PinInfo& Pkcs15PKCS11Provider::findPinForKey(const PrivateKeyInfo& key) const
{
    if (!key.authId.empty()) {
        for (const auto& pin : pins) {
            if (pin.id == key.authId && isUserPin(pin))
                return pin;
        }
    }
    for (const auto& pin : pins) {
        if (isUserPin(pin))
            return pin;
    }
    throw std::runtime_error("Pkcs15PKCS11Provider: no user PIN found");
}

std::shared_ptr<smartcard::PKCS11CardProvider> Pkcs15PKCS11Provider::createInstance() const
{
    auto instance = std::make_shared<Pkcs15PKCS11Provider>();
    // Look up PACE state for the last probed reader (probe() is always called
    // immediately before createInstance() in refreshSlots()).
    auto it = paceProbeResults.find(lastProbedReader);
    if (it != paceProbeResults.end()) {
        instance->paceRequired = it->second.paceRequired;
        instance->cardAccessData = it->second.cardAccessData;
    }
    return instance;
}

bool Pkcs15PKCS11Provider::probe(const std::string& readerName)
{
    // Clear any previous probe result for this reader
    paceProbeResults.erase(readerName);

    try {
        smartcard::PCSCConnection conn(readerName);

        // Try direct AID SELECT first (fast path, works for contact cards)
        std::vector<uint8_t> aid(kPkcs15Aid.begin(), kPkcs15Aid.end());
        auto aidResp = conn.transmit(smartcard::selectByAID(aid, 0x0C));
        if (aidResp.isSuccess()) {
            lastProbedReader = readerName;
            return true; // AID works directly — normal PKCS#15 card
        }

        // AID failed — check if PACE is needed (6982 = security not satisfied)
        bool securityBlocked = (aidResp.sw1 == 0x69 && aidResp.sw2 == 0x82);

        // Also try EF.DIR path (some cards don't support AID SELECT)
        if (!securityBlocked) {
            PKCS15Card tempCard(conn);
            if (tempCard.probe()) {
                lastProbedReader = readerName;
                return true; // Found via EF.DIR, no security block
            }
        }

        // If security blocked, check for PACE via EF.CardAccess
        PaceProbeResult paceResult;
        if (securityBlocked && probeForPace(conn, paceResult)) {
            paceProbeResults[readerName] = std::move(paceResult);
            lastProbedReader = readerName;
            return true;
        }
        return false;
    } catch (...) {
        return false;
    }
}

void Pkcs15PKCS11Provider::connect(const std::string& readerName)
{
    connection = std::make_unique<smartcard::PCSCConnection>(readerName);
    if (!paceRequired) {
        card = std::make_unique<PKCS15Card>(*connection);
        card->selectApplet();
    }
    // If paceRequired, defer PKCS15Card construction to login()
}

smartcard::PKCS11TokenInfo Pkcs15PKCS11Provider::getTokenInfo()
{
    if (!connection)
        throw std::runtime_error("Pkcs15PKCS11Provider: not connected");

    smartcard::PKCS11TokenInfo info;
    info.model = "PKCS#15";

    if (card) {
        auto tokenInfo = card->readTokenInfo();
        info.label = tokenInfo.label;
        info.manufacturer = tokenInfo.manufacturer;
        info.serialNumber = tokenInfo.serialNumber.empty() ? "0000000000000000" : tokenInfo.serialNumber;

        // Find first user PIN for min/max length
        ensureProfile();
        for (const auto& pin : pins) {
            if (!isUserPin(pin))
                continue;
            info.hasPIN = true;
            info.pinMinLen = static_cast<uint8_t>(pin.minLength);
            info.pinMaxLen =
                pin.hasMaxLength ? static_cast<uint8_t>(pin.maxLength) : static_cast<uint8_t>(pin.storedLength);
            break;
        }
    } else {
        info.label = "PKCS#15 (PACE)";
        info.manufacturer = "";
        info.serialNumber = "0000000000000000";
        info.hasPIN = true;
    }

    // Override pin bounds for PACE cards (CAN:PIN format)
    if (paceRequired) {
        info.pinMinLen = 3;  // minimum: "X:Y"
        info.pinMaxLen = 32; // generous for CAN:PIN
    }

    return info;
}

std::vector<smartcard::PKCS11ObjectInfo> Pkcs15PKCS11Provider::getObjects()
{
    std::vector<smartcard::PKCS11ObjectInfo> objects;
    if (!connection || !card)
        return objects;

    try {
        keyIndexMap.clear();

        card->selectApplet();
        auto profile = card->readProfile();
        privateKeys = profile.privateKeys;
        pins = profile.pins;

#ifndef NDEBUG
        std::cerr << "[PKCS15-P11] getObjects: " << profile.certificates.size() << " certs, " << privateKeys.size()
                  << " keys, " << pins.size() << " pins" << std::endl;
        for (size_t i = 0; i < privateKeys.size(); ++i) {
            std::cerr << "[PKCS15-P11]   key[" << i << "] label='" << privateKeys[i].label << "' id=";
            for (auto b : privateKeys[i].id)
                std::cerr << std::hex << std::setfill('0') << std::setw(2) << (int)b;
            std::cerr << " keyRef=0x" << std::hex << (int)privateKeys[i].keyReference
                      << " canSign=" << privateKeys[i].canSign << " size=" << std::dec << privateKeys[i].keySizeBits
                      << " path=";
            for (auto b : privateKeys[i].path)
                std::cerr << std::hex << std::setfill('0') << std::setw(2) << (int)b;
            std::cerr << std::dec << std::endl;
        }
        for (const auto& c : profile.certificates) {
            std::cerr << "[PKCS15-P11]   cert label='" << c.label << "' id=";
            for (auto b : c.id)
                std::cerr << std::hex << std::setfill('0') << std::setw(2) << (int)b;
            std::cerr << std::dec << std::endl;
        }
#endif

        uint8_t idCounter = 1;
        for (const auto& certInfo : profile.certificates) {
            std::vector<uint8_t> id = {idCounter};

            auto derBytes = card->readCertificate(certInfo);

            // Find matching private key by PKCS#15 id
            size_t matchedKeyIndex = SIZE_MAX;
            for (size_t i = 0; i < privateKeys.size(); ++i) {
                if (privateKeys[i].id == certInfo.id) {
                    matchedKeyIndex = i;
                    break;
                }
            }

            bool hasKey = (matchedKeyIndex != SIZE_MAX);
            // Expose all private keys as signing-capable. The card enforces access
            // control — if a key cannot sign, PSO:Compute DS will fail at card level.
            // Some cards have incorrect/missing sign usage flags in PrKDF but still sign.
            bool canSign = hasKey;
            if (hasKey)
                keyIndexMap[id] = matchedKeyIndex;

            // Certificate object
            smartcard::PKCS11ObjectInfo certObj;
            certObj.objectClass = 1; // CKO_CERTIFICATE
            certObj.label = certInfo.label;
            certObj.id = id;
            certObj.value = derBytes;
            certObj.certificateType = 0; // CKC_X_509
            certObj.keyType = 0;
            certObj.isToken = true;
            certObj.isPrivate = false;
            certObj.canSign = false;
            objects.push_back(std::move(certObj));

            // Private key object
            smartcard::PKCS11ObjectInfo keyObj;
            keyObj.objectClass = 3; // CKO_PRIVATE_KEY
            keyObj.label = certInfo.label;
            keyObj.id = id;
            keyObj.value = {};
            keyObj.certificateType = 0;
            keyObj.keyType =
                (hasKey && privateKeys[matchedKeyIndex].keyType == KeyType::Ec) ? 3 : 0; // CKK_EC=3, CKK_RSA=0
            keyObj.isToken = true;
            keyObj.isPrivate = true;
            keyObj.canSign = canSign;

            // Populate EC params from paired certificate for EC keys
            if (keyObj.keyType == 3 && !derBytes.empty()) { // CKK_EC
                const unsigned char* p = derBytes.data();
                X509* x509 = d2i_X509(nullptr, &p, static_cast<long>(derBytes.size()));
                if (x509) {
                    EVP_PKEY* pkey = X509_get0_pubkey(x509);
                    if (pkey && EVP_PKEY_base_id(pkey) == EVP_PKEY_EC) {
                        // ecParams: DER-encoded curve OID
                        unsigned char* paramsDer = nullptr;
                        int pLen = i2d_KeyParams(pkey, &paramsDer);
                        if (pLen > 0 && paramsDer) {
                            keyObj.ecParams.assign(paramsDer, paramsDer + pLen);
                            OPENSSL_free(paramsDer);
                        }
                        // ecPoint: raw uncompressed EC point
                        size_t pointLen = 0;
                        if (EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, nullptr, 0,
                                                            &pointLen) == 1 &&
                            pointLen > 0) {
                            keyObj.ecPoint.resize(pointLen);
                            EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY,
                                                            keyObj.ecPoint.data(), pointLen, &pointLen);
                        }
                    }
                    X509_free(x509);
                }
            }

            objects.push_back(std::move(keyObj));

            ++idCounter;
        }
    } catch (const std::exception& ex) {
#ifndef NDEBUG
        std::cerr << "[PKCS15-P11] getObjects failed: " << ex.what() << std::endl;
#endif
    } catch (...) {
#ifndef NDEBUG
        std::cerr << "[PKCS15-P11] getObjects failed: unknown exception" << std::endl;
#endif
    }

    return objects;
}

unsigned long Pkcs15PKCS11Provider::login(unsigned long userType, const std::vector<uint8_t>& pin)
{
    using namespace smartcard::pkcs11_rv;
    if (userType != 1) // CKU_USER
        return USER_TYPE_INVALID;
    if (!connection)
        return DEVICE_ERROR;

    try {
        // SSO-safe: PIN < 22 bytes, OPENSSL_cleanse reaches SSO buffer on libstdc++.
        // Scrubber is a safety net against exceptions between construction and
        // the explicit cleanse calls below — no double-cleanse concern
        // (OPENSSL_cleanse is idempotent).
        std::string pinStr(pin.begin(), pin.end());
        PinStringScrubber pinScrub{pinStr};

        if (paceRequired) {
            // Parse "CAN:PIN" format
            auto colonPos = pinStr.find(':');
            if (colonPos == std::string::npos) {
                OPENSSL_cleanse(pinStr.data(), pinStr.size());
                return PIN_INVALID;
            }
            std::string can = pinStr.substr(0, colonPos);
            std::string realPin = pinStr.substr(colonPos + 1);
            OPENSSL_cleanse(pinStr.data(), pinStr.size());

            // Perform PACE with CAN
            auto paceEntries = emrtd::crypto::parseCardAccessWithParams(cardAccessData);
            std::optional<emrtd::crypto::SessionKeys> session;
            for (const auto& [oid, paramId] : paceEntries) {
                emrtd::crypto::PACEParams params;
                params.oid = oid;
                params.passwordType = emrtd::crypto::PACEPasswordType::CAN;
                params.password = std::vector<uint8_t>(can.begin(), can.end());
                params.paramId = paramId;
                session = emrtd::crypto::performPACE(*connection, params);
                if (session)
                    break;
            }
            OPENSSL_cleanse(can.data(), can.size());

            if (!session) {
                OPENSSL_cleanse(realPin.data(), realPin.size());
                return PIN_INCORRECT; // PACE failed
            }

            // Install SM
            auto smAlgo = emrtd::crypto::paceOIDToSMAlgorithm(paceEntries.front().first);
            sm = std::make_unique<emrtd::crypto::SecureMessaging>(*session, smAlgo);
            installSmFilter();

            // Now construct PKCS15Card and select applet (through SM)
            card = std::make_unique<PKCS15Card>(*connection);
            card->selectApplet();

            // Continue with normal PIN verification
            pinStr = std::move(realPin);
        }

        if (!card)
            return DEVICE_ERROR;

        ensureProfile();

        size_t pinIdx = SIZE_MAX;
        for (size_t i = 0; i < pins.size(); ++i) {
            if (isUserPin(pins[i])) {
                pinIdx = i;
                break;
            }
        }
        if (pinIdx == SIZE_MAX)
            return DEVICE_ERROR;

        card->selectApplet();
        auto result = card->verifyPIN(pins[pinIdx], pinStr);
        if (result.success) {
            cachedPin = smartcard::SecureBuffer(pinStr);
            OPENSSL_cleanse(pinStr.data(), pinStr.size());
            return OK;
        }
        OPENSSL_cleanse(pinStr.data(), pinStr.size());
        if (result.blocked)
            return PIN_LOCKED;
        return PIN_INCORRECT;
    } catch (...) {
        return DEVICE_ERROR;
    }
}

unsigned long Pkcs15PKCS11Provider::logout()
{
    cachedPin = smartcard::SecureBuffer{};
    return smartcard::pkcs11_rv::OK;
}

std::vector<uint8_t> Pkcs15PKCS11Provider::signData(const std::vector<uint8_t>& keyId, const std::vector<uint8_t>& data)
{
    if (!connection || !card)
        throw std::runtime_error("Pkcs15PKCS11Provider: not connected");
    auto it = keyIndexMap.find(keyId);
    if (it == keyIndexMap.end())
        throw std::runtime_error("Pkcs15PKCS11Provider: unknown key ID");
    if (cachedPin.empty() || pins.empty())
        throw std::runtime_error("Pkcs15PKCS11Provider: not logged in");

    const auto& key = privateKeys[it->second];
    const auto& pinInfo = findPinForKey(key);
    // SSO-safe: PIN < 22 bytes, OPENSSL_cleanse reaches SSO buffer on libstdc++.
    // Scrubber RAII so an exception from card->sign still cleanses on unwind.
    std::string pinStr(cachedPin.begin(), cachedPin.end());
    PinStringScrubber scrubber{pinStr};
    auto scheme = (key.keyType == KeyType::Ec) ? SignScheme::EcdsaRaw : SignScheme::RsaPkcs1;
    return card->sign(key, pinStr, pinInfo, data, data, scheme);
}

std::vector<uint8_t> Pkcs15PKCS11Provider::signMessage(const std::vector<uint8_t>& keyId,
                                                       const std::vector<uint8_t>& digestInfo,
                                                       const std::vector<uint8_t>& rawData, unsigned long mechanismType)
{
    if (!connection || !card)
        throw std::runtime_error("Pkcs15PKCS11Provider: not connected");
    auto it = keyIndexMap.find(keyId);
    if (it == keyIndexMap.end())
        throw std::runtime_error("Pkcs15PKCS11Provider: unknown key ID");
    if (cachedPin.empty() || pins.empty())
        throw std::runtime_error("Pkcs15PKCS11Provider: not logged in");

    const auto& key = privateKeys[it->second];
    const auto& pinInfo = findPinForKey(key);
    // SSO-safe + exception-safe — see signData for rationale.
    std::string pinStr(cachedPin.begin(), cachedPin.end());
    PinStringScrubber scrubber{pinStr};
    return card->sign(key, pinStr, pinInfo, digestInfo, rawData, mechanismToScheme(mechanismType, key.keyType));
}

void Pkcs15PKCS11Provider::reconnectCard()
{
    if (connection)
        connection->reconnect();
}

} // namespace pkcs15
