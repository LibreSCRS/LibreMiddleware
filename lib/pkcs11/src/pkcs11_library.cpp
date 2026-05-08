// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "pkcs11_library.h"
#include "pkcs11_version.h"
#include "smartcard/pcsc_connection.h"
#include "digest_info.h"
#include <pkcs11/internal/slot_hash.h>
#include <algorithm>
#include <cstring>
#include <memory>
#include <mutex>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include "der_utils.h"
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

PKCS11Library::PKCS11Library(std::vector<std::shared_ptr<smartcard::PKCS11CardProvider>> providers)
    : providers(std::move(providers))
{
    refreshSlots();
}

PKCS11Library::~PKCS11Library()
{
    for (auto& slot : slots) {
        if (slot.loginState.has_value() && slot.provider) {
            try {
                slot.provider->logout();
            } catch (...) {
            }
        }
    }
}

// Fill a CK_UTF8CHAR buffer with a string, space-padded (no null terminator).
static void padString(CK_UTF8CHAR* dest, size_t destLen, const char* src)
{
    std::memset(dest, ' ', destLen);
    auto srcLen = std::strlen(src);
    std::memcpy(dest, src, std::min(srcLen, destLen));
}

CK_RV PKCS11Library::getInfo(CK_INFO_PTR pInfo) const
{
    if (pInfo == nullptr)
        return CKR_ARGUMENTS_BAD;

    std::memset(pInfo, 0, sizeof(CK_INFO));
    // Report v2.40 for Java SunPKCS11 compatibility (see pkcs11.cpp function_list)
    pInfo->cryptokiVersion.major = 2;
    pInfo->cryptokiVersion.minor = 40;
    padString(pInfo->manufacturerID, sizeof(pInfo->manufacturerID), "LibreSCRS");
    pInfo->flags = 0;
    padString(pInfo->libraryDescription, sizeof(pInfo->libraryDescription), "LibreSCRS PKCS#11");
    pInfo->libraryVersion.major = LIBRESCRS_PKCS11_VERSION_MAJOR;
    pInfo->libraryVersion.minor = LIBRESCRS_PKCS11_VERSION_MINOR;

    return CKR_OK;
}

void PKCS11Library::refreshSlots()
{
    slots.clear();
    auto readers = smartcard::PCSCConnection::listReaders();
    for (auto& readerName : readers) {
        SlotEntry entry;
        entry.readerName = readerName;
        entry.mutex = std::make_unique<std::mutex>();
        for (auto& provider : providers) {
            if (provider->probe(readerName)) {
                // Create a separate provider instance per slot to avoid
                // connection conflicts between slots.
                entry.provider = provider->createInstance();
                break;
            }
        }
        slots.push_back(std::move(entry));
    }
}

void PKCS11Library::ensureConnected(CK_SLOT_ID slotID)
{
    auto& slot = slots[slotID];
    if (slot.connected)
        return;
    if (slot.provider) {
        slot.provider->connect(slot.readerName);
        slot.connected = true;
    }
}

// No slot mutex needed — slots vector and slot metadata (readerName, provider pointer)
// are immutable after construction in refreshSlots(). Only mutable per-slot state
// (connected, loginState, objects) requires the slot mutex.
CK_RV PKCS11Library::getSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount)
{
    if (pulCount == nullptr)
        return CKR_ARGUMENTS_BAD;

    // Collect matching slot IDs
    std::vector<CK_SLOT_ID> matching;
    for (CK_SLOT_ID i = 0; i < slots.size(); ++i) {
        if (tokenPresent == CK_TRUE && slots[i].provider == nullptr)
            continue;
        matching.push_back(i);
    }

    if (pSlotList == nullptr) {
        *pulCount = static_cast<CK_ULONG>(matching.size());
        return CKR_OK;
    }

    if (*pulCount < matching.size()) {
        *pulCount = static_cast<CK_ULONG>(matching.size());
        return CKR_BUFFER_TOO_SMALL;
    }

    for (size_t i = 0; i < matching.size(); ++i)
        pSlotList[i] = matching[i];
    *pulCount = static_cast<CK_ULONG>(matching.size());
    return CKR_OK;
}

CK_RV PKCS11Library::getSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo)
{
    if (pInfo == nullptr)
        return CKR_ARGUMENTS_BAD;
    if (slotID >= slots.size())
        return CKR_SLOT_ID_INVALID;

    auto& slot = slots[slotID];

    std::memset(pInfo, 0, sizeof(CK_SLOT_INFO));
    // slotDescription embeds an FNV-1a hash of the full reader name in a
    // fixed-position `[<8-hex>] ` prefix (see internal/slot_hash.h). The
    // hash is truncation-immune — even if two readers share an identical
    // 64-byte slotDescription prefix (same model, serial-suffix beyond
    // byte 64), they produce distinct hashes and Pkcs11Token can
    // disambiguate them. The remaining 53 bytes hold a readable prefix
    // of the reader name for management tools (`pkcs11-tool --list-slots`).
    std::memset(pInfo->slotDescription, ' ', sizeof(pInfo->slotDescription));
    LibreSCRS::Pkcs11::Internal::formatSlotDescription(slot.readerName,
                                                       reinterpret_cast<char*>(pInfo->slotDescription));
    padString(pInfo->manufacturerID, sizeof(pInfo->manufacturerID), "LibreSCRS");

    pInfo->flags = CKF_REMOVABLE_DEVICE | CKF_HW_SLOT;
    if (slot.provider != nullptr)
        pInfo->flags |= CKF_TOKEN_PRESENT;

    pInfo->hardwareVersion = {0, 0};
    pInfo->firmwareVersion = {0, 0};

    return CKR_OK;
}

CK_RV PKCS11Library::getTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo)
{
    if (pInfo == nullptr)
        return CKR_ARGUMENTS_BAD;
    if (slotID >= slots.size())
        return CKR_SLOT_ID_INVALID;

    auto& slot = slots[slotID];
    if (slot.provider == nullptr)
        return CKR_TOKEN_NOT_PRESENT;

    // Count sessions under sessionMutex (released before card I/O)
    CK_ULONG sessionCount = 0;
    CK_ULONG rwSessionCount = 0;
    {
        std::scoped_lock slock(sessionMutex);
        for (auto& [handle, entry] : sessions) {
            if (entry.slotID == slotID) {
                ++sessionCount;
                if (entry.flags & CKF_RW_SESSION)
                    ++rwSessionCount;
            }
        }
    }

    // Card I/O under slot mutex
    std::scoped_lock lock(*slot.mutex);
    ensureConnected(slotID);
    auto tokenInfo = slot.provider->getTokenInfo();

    std::memset(pInfo, 0, sizeof(CK_TOKEN_INFO));
    padString(pInfo->label, sizeof(pInfo->label), tokenInfo.label.c_str());
    padString(pInfo->manufacturerID, sizeof(pInfo->manufacturerID), tokenInfo.manufacturer.c_str());
    padString(pInfo->model, sizeof(pInfo->model), tokenInfo.model.c_str());
    padString(pInfo->serialNumber, sizeof(pInfo->serialNumber), tokenInfo.serialNumber.c_str());

    pInfo->flags = CKF_TOKEN_INITIALIZED | CKF_WRITE_PROTECTED;
    if (tokenInfo.hasPIN) {
        pInfo->flags |= CKF_LOGIN_REQUIRED | CKF_USER_PIN_INITIALIZED;
    }
    if (tokenInfo.hasProtectedAuthPath) {
        pInfo->flags |= CKF_PROTECTED_AUTHENTICATION_PATH;
    }

    pInfo->ulMaxSessionCount = CK_EFFECTIVELY_INFINITE;
    pInfo->ulSessionCount = sessionCount;
    pInfo->ulMaxRwSessionCount = CK_EFFECTIVELY_INFINITE;
    pInfo->ulRwSessionCount = rwSessionCount;
    pInfo->ulMaxPinLen = tokenInfo.pinMaxLen;
    pInfo->ulMinPinLen = tokenInfo.pinMinLen;
    pInfo->ulTotalPublicMemory = CK_UNAVAILABLE_INFORMATION;
    pInfo->ulFreePublicMemory = CK_UNAVAILABLE_INFORMATION;
    pInfo->ulTotalPrivateMemory = CK_UNAVAILABLE_INFORMATION;
    pInfo->ulFreePrivateMemory = CK_UNAVAILABLE_INFORMATION;
    pInfo->hardwareVersion = {tokenInfo.hardwareVersionMajor, tokenInfo.hardwareVersionMinor};
    pInfo->firmwareVersion = {tokenInfo.firmwareVersionMajor, tokenInfo.firmwareVersionMinor};
    padString(pInfo->utcTime, sizeof(pInfo->utcTime), "");

    return CKR_OK;
}

CK_RV PKCS11Library::openSession(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, CK_NOTIFY Notify,
                                 CK_SESSION_HANDLE_PTR phSession)
{
    (void)pApplication;
    (void)Notify;

    if (phSession == nullptr)
        return CKR_ARGUMENTS_BAD;
    if (!(flags & CKF_SERIAL_SESSION))
        return CKR_SESSION_PARALLEL_NOT_SUPPORTED;
    if (slotID >= slots.size())
        return CKR_SLOT_ID_INVALID;

    auto& slot = slots[slotID];
    if (slot.provider == nullptr)
        return CKR_TOKEN_NOT_PRESENT;

    {
        std::scoped_lock lock(*slot.mutex);
        ensureConnected(slotID);
    }

    {
        std::scoped_lock lock(sessionMutex);
        CK_SESSION_HANDLE handle = nextSessionHandle++;
        sessions[handle] = {slotID, flags, {}, {}};
        *phSession = handle;
    }
    return CKR_OK;
}

CK_RV PKCS11Library::closeSession(CK_SESSION_HANDLE hSession)
{
    CK_SLOT_ID slotID;
    bool shouldLogout = false;

    {
        std::scoped_lock lock(sessionMutex);
        auto it = sessions.find(hSession);
        if (it == sessions.end())
            return CKR_SESSION_HANDLE_INVALID;

        if (it->second.busy)
            return CKR_FUNCTION_FAILED;

        slotID = it->second.slotID;
        sessions.erase(it);

        // If no more sessions on this slot, clear login state
        bool hasOtherSessions = false;
        for (auto& [h, entry] : sessions) {
            if (entry.slotID == slotID) {
                hasOtherSessions = true;
                break;
            }
        }
        shouldLogout = !hasOtherSessions;
    }

    if (shouldLogout) {
        std::scoped_lock lock(*slots[slotID].mutex);
        if (slots[slotID].loginState.has_value()) {
            if (slots[slotID].provider) {
                try {
                    slots[slotID].provider->logout();
                } catch (...) {
                }
            }
            slots[slotID].loginState.reset();
        }
        // Keep cached objects and connection — they're slot-scoped, not
        // session-scoped. Re-reading certs from card on every session
        // cycle is expensive. Cache is invalidated on C_Finalize or
        // reconnectCard (SCARD_W_RESET_CARD).
    }

    return CKR_OK;
}

CK_RV PKCS11Library::closeAllSessions(CK_SLOT_ID slotID)
{
    if (slotID >= slots.size())
        return CKR_SLOT_ID_INVALID;

    {
        std::scoped_lock lock(sessionMutex);

        // Check if any session on this slot is busy (sign I/O in progress)
        for (auto& [h, entry] : sessions) {
            if (entry.slotID == slotID && entry.busy)
                return CKR_FUNCTION_FAILED;
        }

        for (auto it = sessions.begin(); it != sessions.end();) {
            if (it->second.slotID == slotID)
                it = sessions.erase(it);
            else
                ++it;
        }
    }

    {
        std::scoped_lock lock(*slots[slotID].mutex);
        if (slots[slotID].loginState.has_value()) {
            if (slots[slotID].provider) {
                try {
                    slots[slotID].provider->logout();
                } catch (...) {
                }
            }
            slots[slotID].loginState.reset();
        }
    }

    // Keep cached objects and connection (slot-scoped, not session-scoped).
    return CKR_OK;
}

CK_RV PKCS11Library::getSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo)
{
    if (pInfo == nullptr)
        return CKR_ARGUMENTS_BAD;

    CK_SLOT_ID slotID;
    CK_FLAGS flags;
    {
        std::scoped_lock lock(sessionMutex);
        auto it = sessions.find(hSession);
        if (it == sessions.end())
            return CKR_SESSION_HANDLE_INVALID;
        slotID = it->second.slotID;
        flags = it->second.flags;
    }

    bool loggedIn;
    {
        std::scoped_lock lock(*slots[slotID].mutex);
        loggedIn = slots[slotID].loginState.has_value();
    }

    std::memset(pInfo, 0, sizeof(CK_SESSION_INFO));
    pInfo->slotID = slotID;
    pInfo->flags = flags;
    pInfo->ulDeviceError = 0;

    bool isRW = (flags & CKF_RW_SESSION) != 0;
    if (isRW) {
        pInfo->state = loggedIn ? CKS_RW_USER_FUNCTIONS : CKS_RW_PUBLIC_SESSION;
    } else {
        pInfo->state = loggedIn ? CKS_RO_USER_FUNCTIONS : CKS_RO_PUBLIC_SESSION;
    }

    return CKR_OK;
}

CK_RV PKCS11Library::login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
    if (userType != CKU_USER)
        return CKR_USER_TYPE_INVALID;
    if (pPin == nullptr)
        return CKR_ARGUMENTS_BAD;

    CK_SLOT_ID slotID;
    {
        std::scoped_lock lock(sessionMutex);
        auto it = sessions.find(hSession);
        if (it == sessions.end())
            return CKR_SESSION_HANDLE_INVALID;
        slotID = it->second.slotID;
    }

    std::scoped_lock lock(*slots[slotID].mutex);

    if (slots[slotID].loginState.has_value())
        return CKR_USER_ALREADY_LOGGED_IN;

    auto& slot = slots[slotID];
    ensureConnected(slotID);
    auto tokenInfo = slot.provider->getTokenInfo();
    if (ulPinLen < tokenInfo.pinMinLen || ulPinLen > tokenInfo.pinMaxLen)
        return CKR_PIN_LEN_RANGE;

    std::vector<uint8_t> pinBytes(pPin, pPin + ulPinLen);
    auto rv = [&]() {
        try {
            return static_cast<CK_RV>(slot.provider->login(userType, pinBytes));
        } catch (...) {
            OPENSSL_cleanse(pinBytes.data(), pinBytes.size());
            throw;
        }
    }();
    OPENSSL_cleanse(pinBytes.data(), pinBytes.size());
    if (rv == CKR_OK) {
        slot.loginState = userType;
        // Invalidate cached objects — PACE cards construct PKCS15Card during
        // login, so objects queried before login are stale (empty).
        slot.objectsLoaded = false;
        slot.objects.clear();
    }

    return rv;
}

CK_RV PKCS11Library::logout(CK_SESSION_HANDLE hSession)
{
    CK_SLOT_ID slotID;
    {
        std::scoped_lock lock(sessionMutex);
        auto it = sessions.find(hSession);
        if (it == sessions.end())
            return CKR_SESSION_HANDLE_INVALID;
        slotID = it->second.slotID;
    }

    std::scoped_lock lock(*slots[slotID].mutex);

    if (!slots[slotID].loginState.has_value())
        return CKR_USER_NOT_LOGGED_IN;

    auto& slot = slots[slotID];
    if (slot.provider) {
        try {
            slot.provider->logout();
        } catch (...) {
        }
    }
    slot.loginState.reset();
    return CKR_OK;
}

// ---------------------------------------------------------------------------
// Object discovery
// ---------------------------------------------------------------------------

void PKCS11Library::ensureObjectsLoaded(CK_SLOT_ID slotID)
{
    auto& slot = slots[slotID];
    if (slot.objectsLoaded)
        return;

    if (!slot.provider)
        return;

    auto infos = slot.provider->getObjects();
    for (auto& info : infos) {
        PKCS11Object obj;
        obj.handle = nextObjectHandle.fetch_add(1);
        obj.slotID = slotID;
        obj.objectClass = static_cast<CK_OBJECT_CLASS>(info.objectClass);
        obj.label = std::move(info.label);
        obj.id = std::move(info.id);
        obj.value = std::move(info.value);
        obj.certType = static_cast<CK_CERTIFICATE_TYPE>(info.certificateType);
        obj.keyType = static_cast<CK_KEY_TYPE>(info.keyType);
        obj.isToken = info.isToken ? CK_TRUE : CK_FALSE;
        obj.isPrivate = info.isPrivate ? CK_TRUE : CK_FALSE;
        obj.canSign = info.canSign ? CK_TRUE : CK_FALSE;
        obj.canDecrypt = info.canDecrypt ? CK_TRUE : CK_FALSE;
        obj.canEncrypt = info.canEncrypt ? CK_TRUE : CK_FALSE;
        obj.canWrap = info.canWrap ? CK_TRUE : CK_FALSE;
        obj.canUnwrap = info.canUnwrap ? CK_TRUE : CK_FALSE;
        obj.keyReference = info.keyReference;
        obj.ecParams = std::move(info.ecParams);
        obj.ecPoint = std::move(info.ecPoint);

        // For certificates, parse DER to extract Subject, Issuer, SerialNumber.
        // NSS requires these to match certs against the server's CA list.
        if (obj.objectClass == CKO_CERTIFICATE && !obj.value.empty()) {
            const unsigned char* p = obj.value.data();
            X509* x509 = d2i_X509(nullptr, &p, static_cast<long>(obj.value.size()));
            if (x509) {
                unsigned char* der = nullptr;
                int len;

                len = i2d_X509_NAME(X509_get_subject_name(x509), &der);
                if (len > 0) {
                    obj.subject.assign(der, der + len);
                    OPENSSL_free(der);
                    der = nullptr;
                }

                len = i2d_X509_NAME(X509_get_issuer_name(x509), &der);
                if (len > 0) {
                    obj.issuer.assign(der, der + len);
                    OPENSSL_free(der);
                    der = nullptr;
                }

                len = i2d_ASN1_INTEGER(X509_get_serialNumber(x509), &der);
                if (len > 0) {
                    obj.serialNumber.assign(der, der + len);
                    OPENSSL_free(der);
                }

                X509_free(x509);
            }
        }

        slot.objects[obj.handle] = std::move(obj);
    }

    // Populate RSA modulus / EC params for private keys from paired certificates.
    // NSS uses CKA_MODULUS to determine RSA signature buffer size before C_Sign.
    // PKCS#11 consumers use CKA_EC_PARAMS/CKA_EC_POINT for ECDSA key discovery.
    for (auto& [keyHandle, keyObj] : slot.objects) {
        if (keyObj.objectClass != CKO_PRIVATE_KEY)
            continue;
        for (auto& [certHandle, certObj] : slot.objects) {
            if (certObj.objectClass != CKO_CERTIFICATE)
                continue;
            if (certObj.id != keyObj.id || certObj.value.empty())
                continue;
            const unsigned char* p = certObj.value.data();
            X509* x509 = d2i_X509(nullptr, &p, static_cast<long>(certObj.value.size()));
            if (!x509)
                break;
            EVP_PKEY* pkey = X509_get_pubkey(x509);
            X509_free(x509);
            if (!pkey)
                break;
            int keyBaseId = EVP_PKEY_base_id(pkey);
            if (keyBaseId == EVP_PKEY_RSA) {
                BIGNUM* n = nullptr;
                if (EVP_PKEY_get_bn_param(pkey, "n", &n) == 1 && n) {
                    int len = BN_num_bytes(n);
                    keyObj.modulus.resize(static_cast<size_t>(len));
                    BN_bn2bin(n, keyObj.modulus.data());
                    BN_free(n);
                }
                BIGNUM* e = nullptr;
                if (EVP_PKEY_get_bn_param(pkey, "e", &e) == 1 && e) {
                    int len = BN_num_bytes(e);
                    keyObj.publicExponent.resize(static_cast<size_t>(len));
                    BN_bn2bin(e, keyObj.publicExponent.data());
                    BN_free(e);
                }
            } else if (keyBaseId == EVP_PKEY_EC) {
                // CKA_EC_PARAMS: DER-encoded curve OID (named curve parameters)
                unsigned char* paramsDer = nullptr;
                int pLen = i2d_KeyParams(pkey, &paramsDer);
                if (pLen > 0 && paramsDer) {
                    keyObj.ecParams.assign(paramsDer, paramsDer + pLen);
                    OPENSSL_free(paramsDer);
                }
                // CKA_EC_POINT: DER-encoded OCTET STRING wrapping the EC point
                size_t pointLen = 0;
                if (EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, nullptr, 0, &pointLen) ==
                        1 &&
                    pointLen > 0) {
                    std::vector<uint8_t> rawPoint(pointLen);
                    EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, rawPoint.data(), pointLen,
                                                    &pointLen);
                    // PKCS#11 CKA_EC_POINT is a DER OCTET STRING wrapping the raw point
                    keyObj.ecPoint = libresign::derOctetString(rawPoint);
                }
            }
            EVP_PKEY_free(pkey);
            break;
        }
    }

    slot.objectsLoaded = true;
}

bool PKCS11Library::matchesTemplate(const PKCS11Object& obj, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount) const
{
    for (CK_ULONG i = 0; i < ulCount; ++i) {
        auto& attr = pTemplate[i];
        switch (attr.type) {
        case CKA_CLASS:
            if (attr.ulValueLen == sizeof(CK_OBJECT_CLASS)) {
                CK_OBJECT_CLASS val;
                std::memcpy(&val, attr.pValue, sizeof(val));
                if (obj.objectClass != val)
                    return false;
            }
            break;
        case CKA_TOKEN:
            if (attr.ulValueLen == sizeof(CK_BBOOL)) {
                CK_BBOOL val;
                std::memcpy(&val, attr.pValue, sizeof(val));
                if (obj.isToken != val)
                    return false;
            }
            break;
        case CKA_PRIVATE:
            if (attr.ulValueLen == sizeof(CK_BBOOL)) {
                CK_BBOOL val;
                std::memcpy(&val, attr.pValue, sizeof(val));
                if (obj.isPrivate != val)
                    return false;
            }
            break;
        case CKA_LABEL:
            if (attr.pValue != nullptr) {
                std::string val(static_cast<char*>(attr.pValue), attr.ulValueLen);
                if (obj.label != val)
                    return false;
            }
            break;
        case CKA_ID:
            if (attr.pValue != nullptr) {
                std::vector<uint8_t> val(static_cast<uint8_t*>(attr.pValue),
                                         static_cast<uint8_t*>(attr.pValue) + attr.ulValueLen);
                if (obj.id != val)
                    return false;
            }
            break;
        case CKA_CERTIFICATE_TYPE:
            if (attr.ulValueLen == sizeof(CK_CERTIFICATE_TYPE)) {
                CK_CERTIFICATE_TYPE val;
                std::memcpy(&val, attr.pValue, sizeof(val));
                if (obj.certType != val)
                    return false;
            }
            break;
        case CKA_KEY_TYPE:
            if (attr.ulValueLen == sizeof(CK_KEY_TYPE)) {
                CK_KEY_TYPE val;
                std::memcpy(&val, attr.pValue, sizeof(val));
                if (obj.keyType != val)
                    return false;
            }
            break;
        case CKA_SIGN:
            if (attr.ulValueLen == sizeof(CK_BBOOL)) {
                CK_BBOOL val;
                std::memcpy(&val, attr.pValue, sizeof(val));
                if (obj.canSign != val)
                    return false;
            }
            break;
        case CKA_VALUE:
            if (attr.pValue != nullptr) {
                std::vector<uint8_t> val(static_cast<uint8_t*>(attr.pValue),
                                         static_cast<uint8_t*>(attr.pValue) + attr.ulValueLen);
                if (obj.value != val)
                    return false;
            }
            break;
        case CKA_SENSITIVE:
        case CKA_ALWAYS_SENSITIVE: {
            // Private keys are always sensitive
            if (obj.objectClass == CKO_PRIVATE_KEY && attr.ulValueLen == sizeof(CK_BBOOL)) {
                CK_BBOOL val;
                std::memcpy(&val, attr.pValue, sizeof(val));
                if (val != CK_TRUE)
                    return false;
            }
            break;
        }
        case CKA_NEVER_EXTRACTABLE:
        case CKA_LOCAL: {
            // Hardware-bound keys: never extractable, locally generated
            // Matches OpenSC default access_flags for emulated cards (pkcs15-syn.c)
            if (obj.objectClass == CKO_PRIVATE_KEY && attr.ulValueLen == sizeof(CK_BBOOL)) {
                CK_BBOOL val;
                std::memcpy(&val, attr.pValue, sizeof(val));
                if (val != CK_TRUE)
                    return false;
            }
            break;
        }
        case CKA_DECRYPT: {
            if (obj.objectClass == CKO_PRIVATE_KEY && attr.ulValueLen == sizeof(CK_BBOOL)) {
                CK_BBOOL val;
                std::memcpy(&val, attr.pValue, sizeof(val));
                if (obj.canDecrypt != val)
                    return false;
            }
            break;
        }
        case CKA_ENCRYPT: {
            if (obj.objectClass == CKO_PRIVATE_KEY && attr.ulValueLen == sizeof(CK_BBOOL)) {
                CK_BBOOL val;
                std::memcpy(&val, attr.pValue, sizeof(val));
                if (obj.canEncrypt != val)
                    return false;
            }
            break;
        }
        case CKA_WRAP: {
            if (obj.objectClass == CKO_PRIVATE_KEY && attr.ulValueLen == sizeof(CK_BBOOL)) {
                CK_BBOOL val;
                std::memcpy(&val, attr.pValue, sizeof(val));
                if (obj.canWrap != val)
                    return false;
            }
            break;
        }
        case CKA_UNWRAP: {
            if (obj.objectClass == CKO_PRIVATE_KEY && attr.ulValueLen == sizeof(CK_BBOOL)) {
                CK_BBOOL val;
                std::memcpy(&val, attr.pValue, sizeof(val));
                if (obj.canUnwrap != val)
                    return false;
            }
            break;
        }
        case CKA_EXTRACTABLE:
        case CKA_ALWAYS_AUTHENTICATE:
        case CKA_DERIVE:
        case CKA_SIGN_RECOVER:
        case CKA_VERIFY:
        case CKA_VERIFY_RECOVER: {
            // Keys are non-extractable, no per-op auth, no derive/sign-recover/verify
            if (obj.objectClass == CKO_PRIVATE_KEY && attr.ulValueLen == sizeof(CK_BBOOL)) {
                CK_BBOOL val;
                std::memcpy(&val, attr.pValue, sizeof(val));
                if (val != CK_FALSE)
                    return false;
            }
            break;
        }
        case CKA_MODULUS_BITS: {
            if (obj.objectClass == CKO_PRIVATE_KEY && !obj.modulus.empty() && attr.ulValueLen == sizeof(CK_ULONG)) {
                CK_ULONG val;
                std::memcpy(&val, attr.pValue, sizeof(val));
                CK_ULONG bits = static_cast<CK_ULONG>(obj.modulus.size() * 8);
                if (val != bits)
                    return false;
            }
            break;
        }
        case CKA_SUBJECT:
            if (obj.objectClass == CKO_CERTIFICATE && attr.pValue != nullptr) {
                std::vector<uint8_t> val(static_cast<uint8_t*>(attr.pValue),
                                         static_cast<uint8_t*>(attr.pValue) + attr.ulValueLen);
                if (obj.subject != val)
                    return false;
            }
            break;
        case CKA_ISSUER:
            if (obj.objectClass == CKO_CERTIFICATE && attr.pValue != nullptr) {
                std::vector<uint8_t> val(static_cast<uint8_t*>(attr.pValue),
                                         static_cast<uint8_t*>(attr.pValue) + attr.ulValueLen);
                if (obj.issuer != val)
                    return false;
            }
            break;
        case CKA_SERIAL_NUMBER:
            if (obj.objectClass == CKO_CERTIFICATE && attr.pValue != nullptr) {
                std::vector<uint8_t> val(static_cast<uint8_t*>(attr.pValue),
                                         static_cast<uint8_t*>(attr.pValue) + attr.ulValueLen);
                if (obj.serialNumber != val)
                    return false;
            }
            break;
        case CKA_EC_PARAMS:
            if (attr.pValue != nullptr && !obj.ecParams.empty()) {
                if (attr.ulValueLen != obj.ecParams.size() ||
                    std::memcmp(attr.pValue, obj.ecParams.data(), attr.ulValueLen) != 0)
                    return false;
            }
            break;
        case CKA_EC_POINT:
            if (attr.pValue != nullptr && !obj.ecPoint.empty()) {
                if (attr.ulValueLen != obj.ecPoint.size() ||
                    std::memcmp(attr.pValue, obj.ecPoint.data(), attr.ulValueLen) != 0)
                    return false;
            }
            break;
        default:
            break; // Unknown/unhandled attribute: ignore, still a potential match
        }
    }
    return true;
}

CK_RV PKCS11Library::findObjectsInit(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
    // Hold sessionMutex across the full body so the iterator found below
    // cannot be invalidated by a concurrent closeSession() on the same
    // handle. Lock order is session → slot throughout this translation
    // unit, so nesting the slot mutex below is safe.
    std::scoped_lock sessLock(sessionMutex);
    auto it = sessions.find(hSession);
    if (it == sessions.end())
        return CKR_SESSION_HANDLE_INVALID;
    auto& session = it->second;

    if (session.busy)
        return CKR_FUNCTION_FAILED;

    const CK_SLOT_ID slotID = session.slotID;

    // Per PKCS#11 spec, a session handle is single-threaded
    if (session.findState.has_value())
        return CKR_OPERATION_ACTIVE;

    if (ulCount > 0 && pTemplate == nullptr)
        return CKR_ARGUMENTS_BAD;

    FindState state;
    {
        std::scoped_lock lock(*slots[slotID].mutex);
        ensureObjectsLoaded(slotID);

        for (auto& [handle, obj] : slots[slotID].objects) {
            if (matchesTemplate(obj, pTemplate, ulCount))
                state.matchedHandles.push_back(handle);
        }
    }

    session.findState = std::move(state);
    return CKR_OK;
}

CK_RV PKCS11Library::findObjects(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject, CK_ULONG ulMaxObjectCount,
                                 CK_ULONG_PTR pulObjectCount)
{
    // See findObjectsInit for the locking rationale.
    std::scoped_lock sessLock(sessionMutex);
    auto it = sessions.find(hSession);
    if (it == sessions.end())
        return CKR_SESSION_HANDLE_INVALID;
    auto& session = it->second;

    if (session.busy)
        return CKR_FUNCTION_FAILED;

    if (!session.findState.has_value())
        return CKR_OPERATION_NOT_INITIALIZED;

    if (phObject == nullptr || pulObjectCount == nullptr)
        return CKR_ARGUMENTS_BAD;

    auto& state = session.findState.value();
    CK_ULONG count = 0;
    while (count < ulMaxObjectCount && state.cursor < state.matchedHandles.size()) {
        phObject[count] = state.matchedHandles[state.cursor];
        ++count;
        ++state.cursor;
    }
    *pulObjectCount = count;
    return CKR_OK;
}

CK_RV PKCS11Library::findObjectsFinal(CK_SESSION_HANDLE hSession)
{
    std::scoped_lock sessLock(sessionMutex);
    auto it = sessions.find(hSession);
    if (it == sessions.end())
        return CKR_SESSION_HANDLE_INVALID;
    auto& session = it->second;

    if (session.busy)
        return CKR_FUNCTION_FAILED;

    if (!session.findState.has_value())
        return CKR_OPERATION_NOT_INITIALIZED;

    session.findState.reset();
    return CKR_OK;
}

CK_RV PKCS11Library::getAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate,
                                       CK_ULONG ulCount)
{
    CK_SLOT_ID slotID;
    {
        std::scoped_lock lock(sessionMutex);
        auto sessIt = sessions.find(hSession);
        if (sessIt == sessions.end())
            return CKR_SESSION_HANDLE_INVALID;
        slotID = sessIt->second.slotID;
    }

    if (pTemplate == nullptr && ulCount > 0)
        return CKR_ARGUMENTS_BAD;

    std::scoped_lock lock(*slots[slotID].mutex);

    auto objIt = slots[slotID].objects.find(hObject);
    if (objIt == slots[slotID].objects.end())
        return CKR_OBJECT_HANDLE_INVALID;

    auto& obj = objIt->second;
    // Slot isolation: an object handle from slot A must not be usable on a
    // session for slot B. Without this check, a client with two open
    // sessions could read attributes of objects belonging to a slot it has
    // not authenticated against (and would not be able to enumerate
    // legitimately via C_FindObjects on that other session).
    if (obj.slotID != slotID)
        return CKR_OBJECT_HANDLE_INVALID;
    CK_RV result = CKR_OK;
    CK_ULONG modulusBits = 0; // scratch variable for CKA_MODULUS_BITS

    for (CK_ULONG i = 0; i < ulCount; ++i) {
        auto& attr = pTemplate[i];
        const void* src = nullptr;
        CK_ULONG srcLen = 0;
        bool found = false;

        switch (attr.type) {
        case CKA_CLASS:
            src = &obj.objectClass;
            srcLen = sizeof(obj.objectClass);
            found = true;
            break;
        case CKA_TOKEN:
            src = &obj.isToken;
            srcLen = sizeof(obj.isToken);
            found = true;
            break;
        case CKA_PRIVATE:
            src = &obj.isPrivate;
            srcLen = sizeof(obj.isPrivate);
            found = true;
            break;
        case CKA_LABEL:
            src = obj.label.data();
            srcLen = static_cast<CK_ULONG>(obj.label.size());
            found = true;
            break;
        case CKA_ID:
            src = obj.id.data();
            srcLen = static_cast<CK_ULONG>(obj.id.size());
            found = true;
            break;
        case CKA_VALUE:
            if (obj.objectClass == CKO_CERTIFICATE) {
                src = obj.value.data();
                srcLen = static_cast<CK_ULONG>(obj.value.size());
                found = true;
            }
            break;
        case CKA_CERTIFICATE_TYPE:
            if (obj.objectClass == CKO_CERTIFICATE) {
                src = &obj.certType;
                srcLen = sizeof(obj.certType);
                found = true;
            }
            break;
        case CKA_KEY_TYPE:
            if (obj.objectClass == CKO_PRIVATE_KEY) {
                src = &obj.keyType;
                srcLen = sizeof(obj.keyType);
                found = true;
            }
            break;
        case CKA_SIGN:
            if (obj.objectClass == CKO_PRIVATE_KEY) {
                src = &obj.canSign;
                srcLen = sizeof(obj.canSign);
                found = true;
            }
            break;
        case CKA_SENSITIVE:
        case CKA_ALWAYS_SENSITIVE: {
            static const CK_BBOOL trueVal = CK_TRUE;
            if (obj.objectClass == CKO_PRIVATE_KEY) {
                src = &trueVal;
                srcLen = sizeof(trueVal);
                found = true;
            }
            break;
        }
        case CKA_NEVER_EXTRACTABLE:
        case CKA_LOCAL: {
            // Hardware-bound keys: never extractable, locally generated
            // Matches OpenSC default access_flags for emulated cards (pkcs15-syn.c)
            static const CK_BBOOL trueVal2 = CK_TRUE;
            if (obj.objectClass == CKO_PRIVATE_KEY) {
                src = &trueVal2;
                srcLen = sizeof(trueVal2);
                found = true;
            }
            break;
        }
        case CKA_DECRYPT:
            if (obj.objectClass == CKO_PRIVATE_KEY) {
                src = &obj.canDecrypt;
                srcLen = sizeof(obj.canDecrypt);
                found = true;
            }
            break;
        case CKA_ENCRYPT:
            if (obj.objectClass == CKO_PRIVATE_KEY) {
                src = &obj.canEncrypt;
                srcLen = sizeof(obj.canEncrypt);
                found = true;
            }
            break;
        case CKA_WRAP:
            if (obj.objectClass == CKO_PRIVATE_KEY) {
                src = &obj.canWrap;
                srcLen = sizeof(obj.canWrap);
                found = true;
            }
            break;
        case CKA_UNWRAP:
            if (obj.objectClass == CKO_PRIVATE_KEY) {
                src = &obj.canUnwrap;
                srcLen = sizeof(obj.canUnwrap);
                found = true;
            }
            break;
        case CKA_EXTRACTABLE:
        case CKA_ALWAYS_AUTHENTICATE:
        case CKA_DERIVE:
        case CKA_SIGN_RECOVER:
        case CKA_VERIFY:
        case CKA_VERIFY_RECOVER: {
            // Keys are non-extractable, no per-op auth, no derive/sign-recover/verify
            static const CK_BBOOL falseVal = CK_FALSE;
            if (obj.objectClass == CKO_PRIVATE_KEY) {
                src = &falseVal;
                srcLen = sizeof(falseVal);
                found = true;
            }
            break;
        }
        case CKA_MODULUS:
            if (obj.objectClass == CKO_PRIVATE_KEY && !obj.modulus.empty()) {
                src = obj.modulus.data();
                srcLen = static_cast<CK_ULONG>(obj.modulus.size());
                found = true;
            }
            break;
        case CKA_PUBLIC_EXPONENT:
            if (obj.objectClass == CKO_PRIVATE_KEY && !obj.publicExponent.empty()) {
                src = obj.publicExponent.data();
                srcLen = static_cast<CK_ULONG>(obj.publicExponent.size());
                found = true;
            }
            break;
        case CKA_MODULUS_BITS: {
            if (obj.objectClass == CKO_PRIVATE_KEY && !obj.modulus.empty()) {
                modulusBits = static_cast<CK_ULONG>(obj.modulus.size() * 8);
                src = &modulusBits;
                srcLen = sizeof(modulusBits);
                found = true;
            }
            break;
        }
        case CKA_EC_PARAMS:
            if (!obj.ecParams.empty()) {
                src = obj.ecParams.data();
                srcLen = static_cast<CK_ULONG>(obj.ecParams.size());
                found = true;
            }
            break;
        case CKA_EC_POINT:
            if (!obj.ecPoint.empty()) {
                src = obj.ecPoint.data();
                srcLen = static_cast<CK_ULONG>(obj.ecPoint.size());
                found = true;
            }
            break;
        case CKA_SUBJECT:
            if (obj.objectClass == CKO_CERTIFICATE && !obj.subject.empty()) {
                src = obj.subject.data();
                srcLen = static_cast<CK_ULONG>(obj.subject.size());
                found = true;
            }
            break;
        case CKA_ISSUER:
            if (obj.objectClass == CKO_CERTIFICATE && !obj.issuer.empty()) {
                src = obj.issuer.data();
                srcLen = static_cast<CK_ULONG>(obj.issuer.size());
                found = true;
            }
            break;
        case CKA_SERIAL_NUMBER:
            if (obj.objectClass == CKO_CERTIFICATE && !obj.serialNumber.empty()) {
                src = obj.serialNumber.data();
                srcLen = static_cast<CK_ULONG>(obj.serialNumber.size());
                found = true;
            }
            break;
        case CKA_TRUSTED: {
            // User certificates are not authority certs (matches OpenSC cert->authority=0)
            static const CK_BBOOL trustedVal = CK_FALSE;
            if (obj.objectClass == CKO_CERTIFICATE) {
                src = &trustedVal;
                srcLen = sizeof(trustedVal);
                found = true;
            }
            break;
        }
        default:
            break;
        }

        if (!found) {
            attr.ulValueLen = CK_UNAVAILABLE_INFORMATION;
            result = CKR_ATTRIBUTE_TYPE_INVALID;
            continue;
        }

        if (attr.pValue == nullptr) {
            attr.ulValueLen = srcLen;
        } else if (attr.ulValueLen < srcLen) {
            attr.ulValueLen = srcLen;
            result = CKR_BUFFER_TOO_SMALL;
        } else {
            std::memcpy(attr.pValue, src, srcLen);
            attr.ulValueLen = srcLen;
        }
    }

    return result;
}

// Returns true if mechanism is a combined hash+sign (CKM_SHA*_RSA_PKCS).
static bool isCombinedHashMechanism(CK_MECHANISM_TYPE mech)
{
    return mech == CKM_SHA1_RSA_PKCS || mech == CKM_SHA256_RSA_PKCS || mech == CKM_SHA384_RSA_PKCS ||
           mech == CKM_SHA512_RSA_PKCS;
}

// Returns true if mechanism is an RSA-PSS combined hash+sign mechanism.
static bool isPSSMechanism(CK_MECHANISM_TYPE mech)
{
    return mech == CKM_SHA256_RSA_PKCS_PSS || mech == CKM_SHA384_RSA_PKCS_PSS || mech == CKM_SHA512_RSA_PKCS_PSS;
}

// Hash data with the algorithm implied by mech and wrap in a DER DigestInfo.
// Called for CKM_SHA*_RSA_PKCS — data is the raw (un-hashed) message.
static std::vector<uint8_t> buildDigestInfo(CK_MECHANISM_TYPE mech, const uint8_t* data, size_t dataLen)
{
    const EVP_MD* md = nullptr;
    switch (mech) {
    case CKM_SHA1_RSA_PKCS:
        md = EVP_sha1();
        break;
    case CKM_SHA256_RSA_PKCS:
        md = EVP_sha256();
        break;
    case CKM_SHA384_RSA_PKCS:
        md = EVP_sha384();
        break;
    case CKM_SHA512_RSA_PKCS:
        md = EVP_sha512();
        break;
    default:
        throw std::runtime_error("buildDigestInfo: unsupported mechanism");
    }

    // Hash the data
    std::vector<uint8_t> hash(static_cast<size_t>(EVP_MD_size(md)));
    auto ctx = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (!ctx)
        throw std::runtime_error("buildDigestInfo: EVP_MD_CTX_new failed");
    unsigned int hLen = static_cast<unsigned int>(hash.size());
    if (!EVP_DigestInit_ex(ctx.get(), md, nullptr) || !EVP_DigestUpdate(ctx.get(), data, dataLen) ||
        !EVP_DigestFinal_ex(ctx.get(), hash.data(), &hLen)) {
        throw std::runtime_error("buildDigestInfo: digest operation failed");
    }

    // DigestInfo prefixes from shared header (libresign::kDigestInfoSha*Prefix)
    const uint8_t* pfx = nullptr;
    size_t pfxLen = 0;
    switch (mech) {
    case CKM_SHA1_RSA_PKCS:
        pfx = libresign::kDigestInfoSha1Prefix;
        pfxLen = sizeof(libresign::kDigestInfoSha1Prefix);
        break;
    case CKM_SHA256_RSA_PKCS:
        pfx = libresign::kDigestInfoSha256Prefix;
        pfxLen = sizeof(libresign::kDigestInfoSha256Prefix);
        break;
    case CKM_SHA384_RSA_PKCS:
        pfx = libresign::kDigestInfoSha384Prefix;
        pfxLen = sizeof(libresign::kDigestInfoSha384Prefix);
        break;
    case CKM_SHA512_RSA_PKCS:
        pfx = libresign::kDigestInfoSha512Prefix;
        pfxLen = sizeof(libresign::kDigestInfoSha512Prefix);
        break;
    default:
        throw std::runtime_error("buildDigestInfo: unreachable");
    }

    std::vector<uint8_t> digestInfo(pfxLen + hash.size());
    std::memcpy(digestInfo.data(), pfx, pfxLen);
    std::memcpy(digestInfo.data() + pfxLen, hash.data(), hash.size());
    return digestInfo;
}

// ---------------------------------------------------------------------------
// RAII guard: marks session busy, unlocks sessionMutex for card I/O
// ---------------------------------------------------------------------------

namespace {

class SessionBusyGuard
{
public:
    SessionBusyGuard(std::unique_lock<std::mutex>& sessLockArg, SessionEntry& sessionArg)
        : sessLock(sessLockArg), session(sessionArg)
    {
        sessLock.unlock();
    }

    ~SessionBusyGuard()
    {
        sessLock.lock();
        session.busy = false;
    }

    SessionBusyGuard(const SessionBusyGuard&) = delete;
    SessionBusyGuard& operator=(const SessionBusyGuard&) = delete;

private:
    std::unique_lock<std::mutex>& sessLock;
    SessionEntry& session;
};

} // anonymous namespace

// ---------------------------------------------------------------------------
// Lookup and utility helpers
// ---------------------------------------------------------------------------

SessionEntry* PKCS11Library::findSession(CK_SESSION_HANDLE h)
{
    auto it = sessions.find(h);
    return (it != sessions.end()) ? &it->second : nullptr;
}

// Parse DER-encoded EC named curve OID and return field size in bytes.
static size_t ecFieldSizeFromParams(const std::vector<uint8_t>& derParams)
{
    // Well-known curves: match OID bytes anywhere in the DER (may be bare OID or wrapped in SEQUENCE)
    static const uint8_t p256[] = {0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07};
    static const uint8_t p384[] = {0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22};
    static const uint8_t p521[] = {0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23};

    auto contains = [&](const uint8_t* oid, size_t len) {
        for (size_t i = 0; i + len <= derParams.size(); ++i)
            if (std::memcmp(derParams.data() + i, oid, len) == 0)
                return true;
        return false;
    };

    if (contains(p256, sizeof(p256)))
        return 32;
    if (contains(p384, sizeof(p384)))
        return 48;
    if (contains(p521, sizeof(p521)))
        return 66;
    return 32; // default P-256
}

CK_ULONG PKCS11Library::signatureSize(const PKCS11Object& key) const
{
    if (!key.modulus.empty())
        return static_cast<CK_ULONG>(key.modulus.size());
    if (!key.ecParams.empty()) {
        size_t fieldBytes = ecFieldSizeFromParams(key.ecParams);
        return static_cast<CK_ULONG>(2 * fieldBytes + 8);
    }
    if (key.keyType == CKK_EC)
        return 72; // P-256 default if params unavailable
    return 256;    // RSA fallback
}

CK_RV PKCS11Library::handleCardError(const std::exception& e, CK_SLOT_ID slotID)
{
    if (auto* pcsc = dynamic_cast<const smartcard::PCSCError*>(&e)) {
        if (pcsc->code() == static_cast<LONG>(SCARD_W_RESET_CARD)) {
            try {
                slots[slotID].provider->reconnectCard();
            } catch (...) {
            }
            slots[slotID].loginState.reset();
            slots[slotID].objectsLoaded = false;
            slots[slotID].objects.clear();
            return CKR_USER_NOT_LOGGED_IN;
        }
    }
    return CKR_DEVICE_ERROR;
}

// ---------------------------------------------------------------------------
// Signing
// ---------------------------------------------------------------------------

CK_RV PKCS11Library::signInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
    // Hold sessionMutex across the full body to prevent a concurrent
    // closeSession() from invalidating the session iterator mid-call.
    std::scoped_lock sessLock(sessionMutex);
    auto sessIt = sessions.find(hSession);
    if (sessIt == sessions.end())
        return CKR_SESSION_HANDLE_INVALID;
    auto& session = sessIt->second;

    if (session.busy)
        return CKR_FUNCTION_FAILED;

    const CK_SLOT_ID slotID = session.slotID;

    if (session.signState.has_value())
        return CKR_OPERATION_ACTIVE;

    if (pMechanism == nullptr)
        return CKR_ARGUMENTS_BAD;

    if (pMechanism->mechanism != CKM_RSA_PKCS && pMechanism->mechanism != CKM_ECDSA &&
        !isCombinedHashMechanism(pMechanism->mechanism) && !isPSSMechanism(pMechanism->mechanism))
        return CKR_MECHANISM_INVALID;

    if (isPSSMechanism(pMechanism->mechanism)) {
        if (pMechanism->pParameter == nullptr || pMechanism->ulParameterLen != sizeof(CK_RSA_PKCS_PSS_PARAMS))
            return CKR_MECHANISM_PARAM_INVALID;
        auto* pssParams = static_cast<CK_RSA_PKCS_PSS_PARAMS*>(pMechanism->pParameter);
        if (pMechanism->mechanism == CKM_SHA256_RSA_PKCS_PSS &&
            (pssParams->hashAlg != CKM_SHA256 || pssParams->mgf != CKG_MGF1_SHA256))
            return CKR_MECHANISM_PARAM_INVALID;
        if (pMechanism->mechanism == CKM_SHA384_RSA_PKCS_PSS &&
            (pssParams->hashAlg != CKM_SHA384 || pssParams->mgf != CKG_MGF1_SHA384))
            return CKR_MECHANISM_PARAM_INVALID;
        if (pMechanism->mechanism == CKM_SHA512_RSA_PKCS_PSS &&
            (pssParams->hashAlg != CKM_SHA512 || pssParams->mgf != CKG_MGF1_SHA512))
            return CKR_MECHANISM_PARAM_INVALID;
    }

    std::scoped_lock lock(*slots[slotID].mutex);

    auto objIt = slots[slotID].objects.find(hKey);
    if (objIt == slots[slotID].objects.end())
        return CKR_KEY_HANDLE_INVALID;

    auto& obj = objIt->second;
    // Slot isolation: a key handle from slot A must not sign on a session
    // bound to slot B. The login-state check below only verifies that the
    // session's slot is logged in — it does NOT verify that the slot owns
    // this key. Without this guard a client could sign with a private key
    // belonging to a different (and possibly differently authenticated)
    // slot.
    if (obj.slotID != slotID)
        return CKR_KEY_HANDLE_INVALID;
    if (obj.objectClass != CKO_PRIVATE_KEY || obj.canSign != CK_TRUE)
        return CKR_KEY_TYPE_INCONSISTENT;

    if (!slots[slotID].loginState.has_value())
        return CKR_USER_NOT_LOGGED_IN;

    SignState state{hKey, pMechanism->mechanism, {}, false};
    session.signState = std::move(state);
    return CKR_OK;
}

CK_RV PKCS11Library::sign(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
                          CK_ULONG_PTR pulSignatureLen)
{
    // --- Phase A: validate and extract state under sessionMutex ---
    std::unique_lock sessLock(sessionMutex);
    auto sessIt = sessions.find(hSession);
    if (sessIt == sessions.end())
        return CKR_SESSION_HANDLE_INVALID;
    auto& session = sessIt->second;

    if (session.busy)
        return CKR_FUNCTION_FAILED;

    const CK_SLOT_ID slotID = session.slotID;

    if (!session.signState.has_value())
        return CKR_OPERATION_NOT_INITIALIZED;

    // Per PKCS#11 spec: C_Sign is single-part only. If C_SignUpdate was
    // called, the caller must use C_SignFinal instead.
    if (session.signState->multiPart) {
        session.signState.reset();
        return CKR_FUNCTION_FAILED;
    }

    if (pulSignatureLen == nullptr)
        return CKR_ARGUMENTS_BAD;

    // Size query and buffer-too-small: brief nested slot lock, return early.
    // Do NOT set busy — operation is preserved, no card I/O needed.
    {
        std::scoped_lock lock(*slots[slotID].mutex);

        auto keyIt = slots[slotID].objects.find(session.signState->keyHandle);
        if (keyIt == slots[slotID].objects.end()) {
            session.signState.reset();
            return CKR_DEVICE_ERROR;
        }
        CK_ULONG sigSize = signatureSize(keyIt->second);

        // Size query: pSignature == NULL — do NOT consume sign state
        if (pSignature == nullptr) {
            *pulSignatureLen = sigSize;
            return CKR_OK;
        }

        // Check buffer size before consuming sign state.
        // Per PKCS#11 spec, CKR_BUFFER_TOO_SMALL must preserve the active
        // signing operation so callers can retry with a larger buffer.
        if (*pulSignatureLen < sigSize) {
            *pulSignatureLen = sigSize;
            return CKR_BUFFER_TOO_SMALL;
        }
    }

    // Copy signState locally, reset session state, mark busy.
    auto localSignState = session.signState.value();
    session.signState.reset();
    session.busy = true;

    // SessionBusyGuard unlocks sessionMutex now, relocks + clears busy in dtor.
    SessionBusyGuard busyGuard(sessLock, session);

    // --- Phase B: card I/O under slot mutex only ---
    {
        std::scoped_lock lock(*slots[slotID].mutex);

        auto keyIt = slots[slotID].objects.find(localSignState.keyHandle);
        if (keyIt == slots[slotID].objects.end())
            return CKR_DEVICE_ERROR;

        auto& obj = keyIt->second;
        if (!slots[slotID].provider)
            return CKR_DEVICE_ERROR;

        try {
            std::vector<uint8_t> sig;

            if (isCombinedHashMechanism(localSignState.mechanism) || isPSSMechanism(localSignState.mechanism)) {
                // Combined hash+sign: build DigestInfo locally, pass both DigestInfo and
                // raw data to provider. Cards that do raw RSA use DigestInfo (default).
                // Cards that require hash-specific algorithms use rawData to hash locally.
                // PSS mechanisms skip DigestInfo (padding is done differently).
                std::vector<uint8_t> digestInfo;
                if (!isPSSMechanism(localSignState.mechanism))
                    digestInfo = buildDigestInfo(localSignState.mechanism, pData, ulDataLen);
                std::vector<uint8_t> rawData(pData, pData + ulDataLen);
                sig = slots[slotID].provider->signMessage(obj.id, digestInfo, rawData, localSignState.mechanism);
            } else if (localSignState.mechanism == CKM_ECDSA) {
                // ECDSA: caller provides pre-hashed data, no DigestInfo wrapping.
                std::vector<uint8_t> dataVec(pData, pData + ulDataLen);
                sig = slots[slotID].provider->signData(obj.id, dataVec);
            } else {
                // CKM_RSA_PKCS: caller provides pre-built DigestInfo.
                // Max input = key_size_bytes - 11 (PKCS#1 v1.5 overhead).
                if (!obj.modulus.empty() && obj.modulus.size() <= 11)
                    return CKR_KEY_SIZE_RANGE;
                CK_ULONG maxInput = obj.modulus.empty() ? 245 : static_cast<CK_ULONG>(obj.modulus.size()) - 11;
                if (ulDataLen > maxInput)
                    return CKR_DATA_LEN_RANGE;
                std::vector<uint8_t> dataVec(pData, pData + ulDataLen);
                sig = slots[slotID].provider->signData(obj.id, dataVec);
            }

            if (*pulSignatureLen < sig.size()) {
                *pulSignatureLen = static_cast<CK_ULONG>(sig.size());
                // Sign state already consumed — operation cannot be retried.
                // CKR_BUFFER_TOO_SMALL would violate PKCS#11 spec; use CKR_DEVICE_ERROR.
                return CKR_DEVICE_ERROR;
            }

            std::memcpy(pSignature, sig.data(), sig.size());
            *pulSignatureLen = static_cast<CK_ULONG>(sig.size());
            return CKR_OK;
        } catch (const std::exception& e) {
            return handleCardError(e, slotID);
        } catch (...) {
            return CKR_DEVICE_ERROR;
        }
    }
    // --- Phase C: ~SessionBusyGuard relocks sessionMutex, clears busy ---
}

CK_RV PKCS11Library::signUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
    std::scoped_lock sessLock(sessionMutex);
    auto sessIt = sessions.find(hSession);
    if (sessIt == sessions.end())
        return CKR_SESSION_HANDLE_INVALID;
    auto& session = sessIt->second;

    if (session.busy)
        return CKR_FUNCTION_FAILED;

    if (!session.signState.has_value())
        return CKR_OPERATION_NOT_INITIALIZED;

    if (pPart == nullptr && ulPartLen > 0) {
        session.signState.reset(); // per spec, error terminates the operation
        return CKR_ARGUMENTS_BAD;
    }

    // Only combined-hash mechanisms (including PSS) support multi-part signing.
    // CKM_RSA_PKCS is single-part only (caller provides pre-built DigestInfo).
    if (!isCombinedHashMechanism(session.signState->mechanism) && !isPSSMechanism(session.signState->mechanism)) {
        session.signState.reset();
        return CKR_FUNCTION_NOT_SUPPORTED;
    }

    session.signState->multiPart = true;
    constexpr size_t kMaxSignBuffer = 64 * 1024 * 1024; // 64 MB
    // Overflow-safe accumulation check: write the addition as a subtraction
    // against the cap so it cannot wrap when ulPartLen is huge.
    if (ulPartLen > kMaxSignBuffer || session.signState->buffer.size() > kMaxSignBuffer - ulPartLen) {
        session.signState.reset(); // Per spec: error terminates operation
        return CKR_DATA_LEN_RANGE;
    }
    if (ulPartLen > 0)
        session.signState->buffer.insert(session.signState->buffer.end(), pPart, pPart + ulPartLen);
    return CKR_OK;
}

CK_RV PKCS11Library::signFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
    // --- Phase A: validate and extract state under sessionMutex ---
    std::unique_lock sessLock(sessionMutex);
    auto sessIt = sessions.find(hSession);
    if (sessIt == sessions.end())
        return CKR_SESSION_HANDLE_INVALID;
    auto& session = sessIt->second;

    if (session.busy)
        return CKR_FUNCTION_FAILED;

    const CK_SLOT_ID slotID = session.slotID;

    if (!session.signState.has_value())
        return CKR_OPERATION_NOT_INITIALIZED;

    // C_SignFinal is only valid for multi-part (combined-hash or PSS) mechanisms
    if (!isCombinedHashMechanism(session.signState->mechanism) && !isPSSMechanism(session.signState->mechanism)) {
        session.signState.reset();
        return CKR_FUNCTION_NOT_SUPPORTED;
    }

    if (pulSignatureLen == nullptr)
        return CKR_ARGUMENTS_BAD;

    // Size query and buffer-too-small: brief nested slot lock, return early.
    // Do NOT set busy — operation is preserved, no card I/O needed.
    {
        std::scoped_lock lock(*slots[slotID].mutex);

        auto keyIt = slots[slotID].objects.find(session.signState->keyHandle);
        if (keyIt == slots[slotID].objects.end()) {
            session.signState.reset();
            return CKR_DEVICE_ERROR;
        }
        CK_ULONG sigSize = signatureSize(keyIt->second);

        // Size query
        if (pSignature == nullptr) {
            *pulSignatureLen = sigSize;
            return CKR_OK;
        }

        // Check buffer size before consuming sign state
        if (*pulSignatureLen < sigSize) {
            *pulSignatureLen = sigSize;
            return CKR_BUFFER_TOO_SMALL;
        }
    }

    // Copy signState locally, reset session state, mark busy.
    auto localSignState = std::move(session.signState.value());
    session.signState.reset();
    session.busy = true;

    // SessionBusyGuard unlocks sessionMutex now, relocks + clears busy in dtor.
    SessionBusyGuard busyGuard(sessLock, session);

    // --- Phase B: card I/O under slot mutex only ---
    {
        std::scoped_lock lock(*slots[slotID].mutex);

        auto keyIt = slots[slotID].objects.find(localSignState.keyHandle);
        if (keyIt == slots[slotID].objects.end())
            return CKR_DEVICE_ERROR;

        auto& obj = keyIt->second;
        if (!slots[slotID].provider)
            return CKR_DEVICE_ERROR;

        try {
            // Hash the accumulated data, build DigestInfo, sign on card.
            // Pass raw data alongside DigestInfo for hash-specific algorithm support.
            // PSS mechanisms skip DigestInfo (padding is done differently).
            std::vector<uint8_t> digestInfo;
            if (!isPSSMechanism(localSignState.mechanism))
                digestInfo = buildDigestInfo(localSignState.mechanism, localSignState.buffer.data(),
                                             static_cast<CK_ULONG>(localSignState.buffer.size()));
            auto sig = slots[slotID].provider->signMessage(obj.id, digestInfo, localSignState.buffer,
                                                           localSignState.mechanism);

            if (*pulSignatureLen < sig.size()) {
                *pulSignatureLen = static_cast<CK_ULONG>(sig.size());
                // Sign state already consumed — operation cannot be retried.
                // CKR_BUFFER_TOO_SMALL would violate PKCS#11 spec; use CKR_DEVICE_ERROR.
                return CKR_DEVICE_ERROR;
            }

            std::memcpy(pSignature, sig.data(), sig.size());
            *pulSignatureLen = static_cast<CK_ULONG>(sig.size());
            return CKR_OK;
        } catch (const std::exception& e) {
            return handleCardError(e, slotID);
        } catch (...) {
            return CKR_DEVICE_ERROR;
        }
    }
    // --- Phase C: ~SessionBusyGuard relocks sessionMutex, clears busy ---
}

// ---------------------------------------------------------------------------
// Mechanism enumeration
// ---------------------------------------------------------------------------

CK_RV PKCS11Library::getMechanismList(CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG_PTR pulCount)
{
    if (pulCount == nullptr)
        return CKR_ARGUMENTS_BAD;
    if (slotID >= slots.size())
        return CKR_SLOT_ID_INVALID;
    if (slots[slotID].provider == nullptr)
        return CKR_TOKEN_NOT_PRESENT;

    std::scoped_lock lock(*slots[slotID].mutex);

    static const CK_MECHANISM_TYPE allMechanisms[] = {
        CKM_RSA_PKCS,        CKM_SHA1_RSA_PKCS,       CKM_SHA256_RSA_PKCS,     CKM_SHA384_RSA_PKCS,
        CKM_SHA512_RSA_PKCS, CKM_SHA256_RSA_PKCS_PSS, CKM_SHA384_RSA_PKCS_PSS, CKM_SHA512_RSA_PKCS_PSS,
        CKM_ECDSA,
    };

    // Filter out PSS mechanisms for providers that don't support them
    bool hasPSS = slots[slotID].provider->supportsPSS();
    constexpr size_t kMaxMechanisms = 12; // room for future mechanisms
    CK_MECHANISM_TYPE filteredList[kMaxMechanisms];
    CK_ULONG count = 0;
    for (auto mech : allMechanisms) {
        if (!hasPSS && isPSSMechanism(mech))
            continue;
        filteredList[count++] = mech;
    }

    if (pMechanismList == nullptr) {
        *pulCount = count;
        return CKR_OK;
    }

    if (*pulCount < count) {
        *pulCount = count;
        return CKR_BUFFER_TOO_SMALL;
    }

    for (CK_ULONG i = 0; i < count; ++i)
        pMechanismList[i] = filteredList[i];
    *pulCount = count;
    return CKR_OK;
}

CK_RV PKCS11Library::getMechanismInfo(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo)
{
    if (pInfo == nullptr)
        return CKR_ARGUMENTS_BAD;
    if (slotID >= slots.size())
        return CKR_SLOT_ID_INVALID;
    if (slots[slotID].provider == nullptr)
        return CKR_TOKEN_NOT_PRESENT;

    if (type != CKM_RSA_PKCS && type != CKM_ECDSA && !isCombinedHashMechanism(type) && !isPSSMechanism(type))
        return CKR_MECHANISM_INVALID;

    std::scoped_lock lock(*slots[slotID].mutex);

    std::memset(pInfo, 0, sizeof(CK_MECHANISM_INFO));

    if (type == CKM_ECDSA) {
        pInfo->ulMinKeySize = 256;
        pInfo->ulMaxKeySize = 521;
        pInfo->flags = CKF_SIGN | CKF_HW;
        return CKR_OK;
    }

    // RSA: determine actual key size range from loaded objects on this slot
    CK_ULONG minBits = 0, maxBits = 0;
    for (const auto& [h, obj] : slots[slotID].objects) {
        if (obj.objectClass == CKO_PRIVATE_KEY && !obj.modulus.empty()) {
            auto bits = static_cast<CK_ULONG>(obj.modulus.size() * 8);
            if (minBits == 0 || bits < minBits)
                minBits = bits;
            if (bits > maxBits)
                maxBits = bits;
        }
    }
    if (minBits == 0) {
        minBits = 1024;
        maxBits = 8192;
    } // fallback — permissive range; actual key size validated at sign time

    pInfo->ulMinKeySize = minBits;
    pInfo->ulMaxKeySize = maxBits;
    pInfo->flags = CKF_SIGN | CKF_HW;
    return CKR_OK;
}
