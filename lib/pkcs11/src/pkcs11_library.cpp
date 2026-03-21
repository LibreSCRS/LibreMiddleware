// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "pkcs11_library.h"
#include "pkcs11_version.h"
#include "smartcard/pcsc_connection.h"
#include <algorithm>
#include <cstring>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

PKCS11Library::PKCS11Library(std::vector<std::shared_ptr<smartcard::PKCS11CardProvider>> providers)
    : providers(std::move(providers))
{}

PKCS11Library::~PKCS11Library()
{
    for (auto& [slotID, userType] : loginState) {
        if (slotID < slots.size() && slots[slotID].provider) {
            try {
                slots[slotID].provider->logout();
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
    pInfo->cryptokiVersion.major = CRYPTOKI_VERSION_MAJOR;
    pInfo->cryptokiVersion.minor = CRYPTOKI_VERSION_MINOR;
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
    connectedSlots.clear();
    auto readers = smartcard::PCSCConnection::listReaders();
    for (auto& readerName : readers) {
        SlotEntry entry{readerName, nullptr};
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
    if (connectedSlots.contains(slotID))
        return;
    auto& slot = slots[slotID];
    if (slot.provider) {
        slot.provider->connect(slot.readerName);
        connectedSlots.insert(slotID);
    }
}

CK_RV PKCS11Library::getSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount)
{
    if (pulCount == nullptr)
        return CKR_ARGUMENTS_BAD;

    // Only enumerate readers once.  The slot list is fixed for
    // this library instance (we don't support C_WaitForSlotEvent).
    if (slots.empty())
        refreshSlots();

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
    padString(pInfo->slotDescription, sizeof(pInfo->slotDescription), slot.readerName.c_str());
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

    CK_ULONG sessionCount = 0;
    CK_ULONG rwSessionCount = 0;
    for (auto& [handle, entry] : sessions) {
        if (entry.slotID == slotID) {
            ++sessionCount;
            if (entry.flags & CKF_RW_SESSION)
                ++rwSessionCount;
        }
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

    ensureConnected(slotID);

    CK_SESSION_HANDLE handle = nextSessionHandle++;
    sessions[handle] = {slotID, flags};
    *phSession = handle;
    return CKR_OK;
}

CK_RV PKCS11Library::closeSession(CK_SESSION_HANDLE hSession)
{
    auto it = sessions.find(hSession);
    if (it == sessions.end())
        return CKR_SESSION_HANDLE_INVALID;

    CK_SLOT_ID slotID = it->second.slotID;
    sessions.erase(it);

    // If no more sessions on this slot, clear login state
    bool hasOtherSessions = false;
    for (auto& [h, entry] : sessions) {
        if (entry.slotID == slotID) {
            hasOtherSessions = true;
            break;
        }
    }
    if (!hasOtherSessions) {
        if (loginState.contains(slotID)) {
            if (slotID < slots.size() && slots[slotID].provider) {
                try {
                    slots[slotID].provider->logout();
                } catch (...) {
                }
            }
            loginState.erase(slotID);
        }
        // Clean up cached objects for this slot
        for (auto it = objects.begin(); it != objects.end();) {
            if (it->second.slotID == slotID)
                it = objects.erase(it);
            else
                ++it;
        }
        loadedSlots.erase(slotID);
        connectedSlots.erase(slotID);
    }

    return CKR_OK;
}

CK_RV PKCS11Library::closeAllSessions(CK_SLOT_ID slotID)
{
    if (slotID >= slots.size())
        return CKR_SLOT_ID_INVALID;

    for (auto it = sessions.begin(); it != sessions.end();) {
        if (it->second.slotID == slotID)
            it = sessions.erase(it);
        else
            ++it;
    }

    if (loginState.contains(slotID)) {
        if (slots[slotID].provider) {
            try {
                slots[slotID].provider->logout();
            } catch (...) {
            }
        }
        loginState.erase(slotID);
    }

    // Clean up cached objects for this slot
    for (auto it = objects.begin(); it != objects.end();) {
        if (it->second.slotID == slotID)
            it = objects.erase(it);
        else
            ++it;
    }
    loadedSlots.erase(slotID);
    connectedSlots.erase(slotID);

    return CKR_OK;
}

CK_RV PKCS11Library::getSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo)
{
    if (pInfo == nullptr)
        return CKR_ARGUMENTS_BAD;

    auto it = sessions.find(hSession);
    if (it == sessions.end())
        return CKR_SESSION_HANDLE_INVALID;

    auto& entry = it->second;
    std::memset(pInfo, 0, sizeof(CK_SESSION_INFO));
    pInfo->slotID = entry.slotID;
    pInfo->flags = entry.flags;
    pInfo->ulDeviceError = 0;

    bool isRW = (entry.flags & CKF_RW_SESSION) != 0;
    bool loggedIn = loginState.contains(entry.slotID);

    if (isRW) {
        pInfo->state = loggedIn ? CKS_RW_USER_FUNCTIONS : CKS_RW_PUBLIC_SESSION;
    } else {
        pInfo->state = loggedIn ? CKS_RO_USER_FUNCTIONS : CKS_RO_PUBLIC_SESSION;
    }

    return CKR_OK;
}

CK_RV PKCS11Library::login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
    auto it = sessions.find(hSession);
    if (it == sessions.end())
        return CKR_SESSION_HANDLE_INVALID;

    if (userType != CKU_USER)
        return CKR_USER_TYPE_INVALID;

    CK_SLOT_ID slotID = it->second.slotID;
    if (loginState.contains(slotID))
        return CKR_USER_ALREADY_LOGGED_IN;

    if (pPin == nullptr)
        return CKR_ARGUMENTS_BAD;

    auto& slot = slots[slotID];
    ensureConnected(slotID);
    auto tokenInfo = slot.provider->getTokenInfo();
    if (ulPinLen < tokenInfo.pinMinLen || ulPinLen > tokenInfo.pinMaxLen)
        return CKR_PIN_LEN_RANGE;

    std::vector<uint8_t> pinBytes(pPin, pPin + ulPinLen);
    auto rv = static_cast<CK_RV>(slot.provider->login(userType, pinBytes));
    if (rv == CKR_OK)
        loginState[slotID] = userType;

    return rv;
}

CK_RV PKCS11Library::logout(CK_SESSION_HANDLE hSession)
{
    auto it = sessions.find(hSession);
    if (it == sessions.end())
        return CKR_SESSION_HANDLE_INVALID;

    CK_SLOT_ID slotID = it->second.slotID;
    if (!loginState.contains(slotID))
        return CKR_USER_NOT_LOGGED_IN;

    auto& slot = slots[slotID];
    if (slot.provider) {
        try {
            slot.provider->logout();
        } catch (...) {
        }
    }
    loginState.erase(slotID);
    return CKR_OK;
}

// ---------------------------------------------------------------------------
// Object discovery
// ---------------------------------------------------------------------------

void PKCS11Library::ensureObjectsLoaded(CK_SLOT_ID slotID)
{
    if (loadedSlots.contains(slotID))
        return;

    auto& slot = slots[slotID];
    if (!slot.provider)
        return;

    auto infos = slot.provider->getObjects();
    for (auto& info : infos) {
        PKCS11Object obj;
        obj.handle = nextObjectHandle++;
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

        objects[obj.handle] = std::move(obj);
    }

    // Populate RSA modulus for private keys from their paired certificates.
    // NSS uses CKA_MODULUS to determine the signature buffer size before calling C_Sign.
    for (auto& [keyHandle, keyObj] : objects) {
        if (keyObj.objectClass != CKO_PRIVATE_KEY || keyObj.slotID != slotID)
            continue;
        for (auto& [certHandle, certObj] : objects) {
            if (certObj.objectClass != CKO_CERTIFICATE || certObj.slotID != slotID)
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
            EVP_PKEY_free(pkey);
            break;
        }
    }

    loadedSlots.insert(slotID);
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
        default:
            break; // Unknown/unhandled attribute: ignore, still a potential match
        }
    }
    return true;
}

CK_RV PKCS11Library::findObjectsInit(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
    auto it = sessions.find(hSession);
    if (it == sessions.end())
        return CKR_SESSION_HANDLE_INVALID;

    auto& session = it->second;
    if (session.findState.has_value())
        return CKR_OPERATION_ACTIVE;

    if (ulCount > 0 && pTemplate == nullptr)
        return CKR_ARGUMENTS_BAD;

    ensureObjectsLoaded(session.slotID);

    FindState state;
    for (auto& [handle, obj] : objects) {
        if (obj.slotID != session.slotID)
            continue;
        if (matchesTemplate(obj, pTemplate, ulCount))
            state.matchedHandles.push_back(handle);
    }
    session.findState = std::move(state);
    return CKR_OK;
}

CK_RV PKCS11Library::findObjects(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject, CK_ULONG ulMaxObjectCount,
                                 CK_ULONG_PTR pulObjectCount)
{
    auto it = sessions.find(hSession);
    if (it == sessions.end())
        return CKR_SESSION_HANDLE_INVALID;

    auto& session = it->second;
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
    auto it = sessions.find(hSession);
    if (it == sessions.end())
        return CKR_SESSION_HANDLE_INVALID;

    auto& session = it->second;
    if (!session.findState.has_value())
        return CKR_OPERATION_NOT_INITIALIZED;

    session.findState.reset();
    return CKR_OK;
}

CK_RV PKCS11Library::getAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate,
                                       CK_ULONG ulCount)
{
    auto sessIt = sessions.find(hSession);
    if (sessIt == sessions.end())
        return CKR_SESSION_HANDLE_INVALID;

    auto objIt = objects.find(hObject);
    if (objIt == objects.end())
        return CKR_OBJECT_HANDLE_INVALID;

    if (pTemplate == nullptr && ulCount > 0)
        return CKR_ARGUMENTS_BAD;

    auto& obj = objIt->second;
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
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx)
        throw std::runtime_error("buildDigestInfo: EVP_MD_CTX_new failed");
    EVP_DigestInit_ex(ctx, md, nullptr);
    EVP_DigestUpdate(ctx, data, dataLen);
    unsigned int hLen = static_cast<unsigned int>(hash.size());
    EVP_DigestFinal_ex(ctx, hash.data(), &hLen);
    EVP_MD_CTX_free(ctx);

    // DER DigestInfo prefixes (AlgorithmIdentifier + OCTET STRING tag+len)
    // SHA-1:   OID 1.3.14.3.2.26  (5 bytes), hash = 20 bytes
    // SHA-256: OID 2.16.840.1.101.3.4.2.1 (9 bytes), hash = 32 bytes
    // SHA-384: OID 2.16.840.1.101.3.4.2.2 (9 bytes), hash = 48 bytes
    // SHA-512: OID 2.16.840.1.101.3.4.2.3 (9 bytes), hash = 64 bytes
    static const uint8_t sha1Pfx[] = {0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e,
                                      0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14};
    static const uint8_t sha256Pfx[] = {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
                                        0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20};
    static const uint8_t sha384Pfx[] = {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
                                        0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30};
    static const uint8_t sha512Pfx[] = {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
                                        0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40};

    const uint8_t* pfx = nullptr;
    size_t pfxLen = 0;
    switch (mech) {
    case CKM_SHA1_RSA_PKCS:
        pfx = sha1Pfx;
        pfxLen = sizeof(sha1Pfx);
        break;
    case CKM_SHA256_RSA_PKCS:
        pfx = sha256Pfx;
        pfxLen = sizeof(sha256Pfx);
        break;
    case CKM_SHA384_RSA_PKCS:
        pfx = sha384Pfx;
        pfxLen = sizeof(sha384Pfx);
        break;
    case CKM_SHA512_RSA_PKCS:
        pfx = sha512Pfx;
        pfxLen = sizeof(sha512Pfx);
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
// Signing
// ---------------------------------------------------------------------------

CK_RV PKCS11Library::signInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
    auto sessIt = sessions.find(hSession);
    if (sessIt == sessions.end())
        return CKR_SESSION_HANDLE_INVALID;

    auto& session = sessIt->second;
    if (session.signState.has_value())
        return CKR_OPERATION_ACTIVE;

    if (pMechanism == nullptr)
        return CKR_ARGUMENTS_BAD;

    if (pMechanism->mechanism != CKM_RSA_PKCS && !isCombinedHashMechanism(pMechanism->mechanism))
        return CKR_MECHANISM_INVALID;

    auto objIt = objects.find(hKey);
    if (objIt == objects.end())
        return CKR_KEY_HANDLE_INVALID;

    auto& obj = objIt->second;
    if (obj.objectClass != CKO_PRIVATE_KEY || obj.canSign != CK_TRUE)
        return CKR_KEY_TYPE_INCONSISTENT;

    if (!loginState.contains(session.slotID))
        return CKR_USER_NOT_LOGGED_IN;

    SignState state{hKey, pMechanism->mechanism};
    session.signState = std::move(state);
    return CKR_OK;
}

CK_RV PKCS11Library::sign(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
                          CK_ULONG_PTR pulSignatureLen)
{
    auto sessIt = sessions.find(hSession);
    if (sessIt == sessions.end())
        return CKR_SESSION_HANDLE_INVALID;

    auto& session = sessIt->second;
    if (!session.signState.has_value())
        return CKR_OPERATION_NOT_INITIALIZED;

    if (pulSignatureLen == nullptr)
        return CKR_ARGUMENTS_BAD;

    constexpr CK_ULONG RSA2048_SIG_SIZE = 256;

    // Size query: pSignature == NULL — do NOT consume sign state
    if (pSignature == nullptr) {
        *pulSignatureLen = RSA2048_SIG_SIZE;
        return CKR_OK;
    }

    // From here on, sign state is consumed regardless of outcome
    auto signState = session.signState.value();
    session.signState.reset();

    auto objIt = objects.find(signState.keyHandle);
    if (objIt == objects.end())
        return CKR_DEVICE_ERROR;

    auto& obj = objIt->second;
    if (obj.slotID >= slots.size() || !slots[obj.slotID].provider)
        return CKR_DEVICE_ERROR;

    try {
        std::vector<uint8_t> sig;

        if (isCombinedHashMechanism(signState.mechanism)) {
            // Hash data, build DigestInfo, then sign with PKCS#1 v1.5 on card
            auto digestInfo = buildDigestInfo(signState.mechanism, pData, ulDataLen);
            sig = slots[obj.slotID].provider->signData(obj.id, digestInfo);
        } else {
            // CKM_RSA_PKCS: caller provides pre-built DigestInfo
            std::vector<uint8_t> dataVec(pData, pData + ulDataLen);
            sig = slots[obj.slotID].provider->signData(obj.id, dataVec);
        }

        if (*pulSignatureLen < sig.size()) {
            *pulSignatureLen = static_cast<CK_ULONG>(sig.size());
            return CKR_BUFFER_TOO_SMALL;
        }

        std::memcpy(pSignature, sig.data(), sig.size());
        *pulSignatureLen = static_cast<CK_ULONG>(sig.size());
        return CKR_OK;
    } catch (const smartcard::PCSCError& e) {
        if (e.code() == static_cast<LONG>(SCARD_W_RESET_CARD)) {
            // The card was physically reset by another process while we were signing.
            // Reconnect our handle (SCARD_LEAVE_CARD) and force the caller to re-login
            // (the card no longer has our PIN verified).
            try {
                slots[obj.slotID].provider->reconnectCard();
            } catch (...) {
            }
            loginState.erase(obj.slotID);
            return CKR_USER_NOT_LOGGED_IN;
        }
        return CKR_DEVICE_ERROR;
    } catch (const std::exception&) {
        return CKR_DEVICE_ERROR;
    } catch (...) {
        return CKR_DEVICE_ERROR;
    }
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

    // CKM_RSA_PKCS_PSS is intentionally NOT advertised: the CardEdge card
    // performs PKCS#1 v1.5 padding internally and does not support raw RSA
    // exponentiation (required for PSS). Advertising PSS causes NSS/Firefox
    // to prefer TLS 1.3 (which mandates PSS) over TLS 1.2 (CKM_RSA_PKCS).
    constexpr CK_ULONG MECHANISM_COUNT = 5;
    static const CK_MECHANISM_TYPE mechanismList[MECHANISM_COUNT] = {
        CKM_RSA_PKCS, CKM_SHA1_RSA_PKCS, CKM_SHA256_RSA_PKCS, CKM_SHA384_RSA_PKCS, CKM_SHA512_RSA_PKCS,
    };

    if (pMechanismList == nullptr) {
        *pulCount = MECHANISM_COUNT;
        return CKR_OK;
    }

    if (*pulCount < MECHANISM_COUNT) {
        *pulCount = MECHANISM_COUNT;
        return CKR_BUFFER_TOO_SMALL;
    }

    for (CK_ULONG i = 0; i < MECHANISM_COUNT; ++i)
        pMechanismList[i] = mechanismList[i];
    *pulCount = MECHANISM_COUNT;
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

    if (type != CKM_RSA_PKCS && !isCombinedHashMechanism(type))
        return CKR_MECHANISM_INVALID;

    std::memset(pInfo, 0, sizeof(CK_MECHANISM_INFO));
    pInfo->ulMinKeySize = 2048;
    pInfo->ulMaxKeySize = 2048;
    pInfo->flags = CKF_SIGN | CKF_HW;
    return CKR_OK;
}
