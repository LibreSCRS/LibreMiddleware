// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright hirashix0@proton.me

#ifndef PKCS11_LIBRARY_H
#define PKCS11_LIBRARY_H

#include "smartcard/pkcs11_card_provider.h"
#include "pkcs11_platform.h"
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <vector>

struct SlotEntry
{
    std::string readerName;
    std::shared_ptr<smartcard::PKCS11CardProvider> provider; // null = no token
};

struct PKCS11Object
{
    CK_OBJECT_HANDLE handle;
    CK_SLOT_ID slotID;
    CK_OBJECT_CLASS objectClass;
    std::string label;
    std::vector<uint8_t> id;
    std::vector<uint8_t> value; // DER for certs, empty for keys
    // X.509 cert fields parsed from DER (certificates only)
    std::vector<uint8_t> subject;
    std::vector<uint8_t> issuer;
    std::vector<uint8_t> serialNumber;
    CK_CERTIFICATE_TYPE certType;
    CK_KEY_TYPE keyType;
    CK_BBOOL isToken;
    CK_BBOOL isPrivate;
    CK_BBOOL canSign;
    CK_BBOOL canDecrypt;
    CK_BBOOL canEncrypt;
    CK_BBOOL canWrap;
    CK_BBOOL canUnwrap;
    uint16_t keyReference = 0;           // on-card key FID (private keys only)
    std::vector<uint8_t> modulus;        // RSA public modulus (private keys only, from paired cert)
    std::vector<uint8_t> publicExponent; // RSA public exponent (private keys only, from paired cert)
};

struct FindState
{
    std::vector<CK_OBJECT_HANDLE> matchedHandles;
    size_t cursor = 0;
};

struct SignState
{
    CK_OBJECT_HANDLE keyHandle;
    CK_MECHANISM_TYPE mechanism;
};

struct SessionEntry
{
    CK_SLOT_ID slotID;
    CK_FLAGS flags; // CKF_SERIAL_SESSION | optional CKF_RW_SESSION
    std::optional<FindState> findState;
    std::optional<SignState> signState;
};

class PKCS11Library
{
public:
    explicit PKCS11Library(std::vector<std::shared_ptr<smartcard::PKCS11CardProvider>> providers);
    ~PKCS11Library();

    CK_RV getInfo(CK_INFO_PTR pInfo) const;
    CK_RV getSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount);
    CK_RV getSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo);
    CK_RV getTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo);

    CK_RV openSession(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, CK_NOTIFY Notify,
                      CK_SESSION_HANDLE_PTR phSession);
    CK_RV closeSession(CK_SESSION_HANDLE hSession);
    CK_RV closeAllSessions(CK_SLOT_ID slotID);
    CK_RV getSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo);
    CK_RV login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen);
    CK_RV logout(CK_SESSION_HANDLE hSession);

    CK_RV findObjectsInit(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
    CK_RV findObjects(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject, CK_ULONG ulMaxObjectCount,
                      CK_ULONG_PTR pulObjectCount);
    CK_RV findObjectsFinal(CK_SESSION_HANDLE hSession);
    CK_RV getAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate,
                            CK_ULONG ulCount);

    CK_RV signInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
    CK_RV sign(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
               CK_ULONG_PTR pulSignatureLen);

    CK_RV getMechanismList(CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG_PTR pulCount);
    CK_RV getMechanismInfo(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo);

private:
    std::vector<std::shared_ptr<smartcard::PKCS11CardProvider>> providers;
    std::vector<SlotEntry> slots;
    CK_SESSION_HANDLE nextSessionHandle = 1;
    std::map<CK_SESSION_HANDLE, SessionEntry> sessions;
    std::map<CK_SLOT_ID, CK_USER_TYPE> loginState; // absent = not logged in

    CK_OBJECT_HANDLE nextObjectHandle = 1;
    std::map<CK_OBJECT_HANDLE, PKCS11Object> objects;
    std::set<CK_SLOT_ID> loadedSlots;

    void refreshSlots();
    void ensureConnected(CK_SLOT_ID slotID);
    void ensureObjectsLoaded(CK_SLOT_ID slotID);
    bool matchesTemplate(const PKCS11Object& obj, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount) const;
    std::set<CK_SLOT_ID> connectedSlots;
};

#endif // PKCS11_LIBRARY_H
