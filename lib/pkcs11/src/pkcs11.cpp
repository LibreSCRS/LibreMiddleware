// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "pkcs11_library.h"
#include "cardedge/cardedge_pkcs11_provider.h"
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <mutex>
#include <vector>

// Optional trace logging: set PKCS11_DEBUG=1 in environment to enable.
static void pkcs11_debug(const char* fmt, ...)
{
    static const bool enabled = (getenv("PKCS11_DEBUG") != nullptr);
    if (!enabled)
        return;
    fprintf(stderr, "[PKCS11] ");
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}

// PKCS#11 is a C API — exceptions must never escape.
// Wrap every delegating function body with this macro.
#define PKCS11_TRY try {
#define PKCS11_CATCH                                                                                                   \
    }                                                                                                                  \
    catch (const std::exception& e)                                                                                    \
    {                                                                                                                  \
        pkcs11_debug("exception: %s", e.what());                                                                       \
        return CKR_DEVICE_ERROR;                                                                                       \
    }                                                                                                                  \
    catch (...)                                                                                                        \
    {                                                                                                                  \
        pkcs11_debug("unknown exception");                                                                             \
        return CKR_DEVICE_ERROR;                                                                                       \
    }

// ---------------------------------------------------------------------------
// File-scoped library state
// ---------------------------------------------------------------------------

// TODO: libraryMutex is held during card I/O, causing starvation under concurrent access.
// Consider per-slot mutexes to allow parallel operations on different cards.
static std::mutex libraryMutex;
static std::unique_ptr<PKCS11Library> library;

static std::vector<std::shared_ptr<smartcard::PKCS11CardProvider>> createDefaultProviders()
{
    std::vector<std::shared_ptr<smartcard::PKCS11CardProvider>> providers;
    providers.push_back(std::make_shared<cardedge::CardEdgePKCS11Provider>());
    return providers;
}

// ---------------------------------------------------------------------------
// General-purpose
// ---------------------------------------------------------------------------

CK_DECLARE_FUNCTION(CK_RV, C_Initialize)(CK_VOID_PTR pInitArgs)
{
    PKCS11_TRY
    std::scoped_lock lock(libraryMutex);
    if (library)
        return CKR_CRYPTOKI_ALREADY_INITIALIZED;

    if (pInitArgs != NULL_PTR) {
        auto args = static_cast<CK_C_INITIALIZE_ARGS_PTR>(pInitArgs);
        if (args->pReserved != NULL_PTR)
            return CKR_ARGUMENTS_BAD;
        // If custom mutex functions are provided without CKF_OS_LOCKING_OK, reject
        bool hasCustomMutex = (args->CreateMutex != NULL_PTR || args->DestroyMutex != NULL_PTR ||
                               args->LockMutex != NULL_PTR || args->UnlockMutex != NULL_PTR);
        if (hasCustomMutex && !(args->flags & CKF_OS_LOCKING_OK))
            return CKR_CANT_LOCK;
    }

    library = std::make_unique<PKCS11Library>(createDefaultProviders());
    return CKR_OK;
    PKCS11_CATCH
}

CK_DECLARE_FUNCTION(CK_RV, C_Finalize)(CK_VOID_PTR pReserved)
{
    PKCS11_TRY
    std::scoped_lock lock(libraryMutex);
    if (!library)
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (pReserved != NULL_PTR)
        return CKR_ARGUMENTS_BAD;
    library.reset();
    return CKR_OK;
    PKCS11_CATCH
}

CK_DECLARE_FUNCTION(CK_RV, C_GetInfo)(CK_INFO_PTR pInfo)
{
    PKCS11_TRY
    std::scoped_lock lock(libraryMutex);
    if (!library)
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    return library->getInfo(pInfo);
    PKCS11_CATCH
}

// C_GetFunctionList is defined at the end of this file (needs the function table).

// ---------------------------------------------------------------------------
// Slot and token management
// ---------------------------------------------------------------------------

CK_DECLARE_FUNCTION(CK_RV, C_GetSlotList)(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount)
{
    PKCS11_TRY
    std::scoped_lock lock(libraryMutex);
    if (!library)
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    return library->getSlotList(tokenPresent, pSlotList, pulCount);
    PKCS11_CATCH
}

CK_DECLARE_FUNCTION(CK_RV, C_GetSlotInfo)(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo)
{
    PKCS11_TRY
    std::scoped_lock lock(libraryMutex);
    if (!library)
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    return library->getSlotInfo(slotID, pInfo);
    PKCS11_CATCH
}

CK_DECLARE_FUNCTION(CK_RV, C_GetTokenInfo)(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo)
{
    PKCS11_TRY
    std::scoped_lock lock(libraryMutex);
    if (!library)
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    return library->getTokenInfo(slotID, pInfo);
    PKCS11_CATCH
}

CK_DECLARE_FUNCTION(CK_RV, C_GetMechanismList)(CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pMechanismList,
                                               CK_ULONG_PTR pulCount)
{
    PKCS11_TRY
    std::scoped_lock lock(libraryMutex);
    if (!library)
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    return library->getMechanismList(slotID, pMechanismList, pulCount);
    PKCS11_CATCH
}

CK_DECLARE_FUNCTION(CK_RV, C_GetMechanismInfo)(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo)
{
    PKCS11_TRY
    std::scoped_lock lock(libraryMutex);
    if (!library)
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    return library->getMechanismInfo(slotID, type, pInfo);
    PKCS11_CATCH
}

CK_DECLARE_FUNCTION(CK_RV, C_InitToken)(CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen,
                                        CK_UTF8CHAR_PTR pLabel)
{
    (void)slotID;
    (void)pPin;
    (void)ulPinLen;
    (void)pLabel;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_InitPIN)(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
    (void)hSession;
    (void)pPin;
    (void)ulPinLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_SetPIN)(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pOldPin, CK_ULONG ulOldLen,
                                     CK_UTF8CHAR_PTR pNewPin, CK_ULONG ulNewLen)
{
    (void)hSession;
    (void)pOldPin;
    (void)ulOldLen;
    (void)pNewPin;
    (void)ulNewLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

// ---------------------------------------------------------------------------
// Session management
// ---------------------------------------------------------------------------

CK_DECLARE_FUNCTION(CK_RV, C_OpenSession)(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, CK_NOTIFY Notify,
                                          CK_SESSION_HANDLE_PTR phSession)
{
    PKCS11_TRY
    std::scoped_lock lock(libraryMutex);
    if (!library)
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    return library->openSession(slotID, flags, pApplication, Notify, phSession);
    PKCS11_CATCH
}

CK_DECLARE_FUNCTION(CK_RV, C_CloseSession)(CK_SESSION_HANDLE hSession)
{
    PKCS11_TRY
    std::scoped_lock lock(libraryMutex);
    if (!library)
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    return library->closeSession(hSession);
    PKCS11_CATCH
}

CK_DECLARE_FUNCTION(CK_RV, C_CloseAllSessions)(CK_SLOT_ID slotID)
{
    PKCS11_TRY
    std::scoped_lock lock(libraryMutex);
    if (!library)
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    return library->closeAllSessions(slotID);
    PKCS11_CATCH
}

CK_DECLARE_FUNCTION(CK_RV, C_GetSessionInfo)(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo)
{
    PKCS11_TRY
    std::scoped_lock lock(libraryMutex);
    if (!library)
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    return library->getSessionInfo(hSession, pInfo);
    PKCS11_CATCH
}

CK_DECLARE_FUNCTION(CK_RV, C_GetOperationState)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState,
                                                CK_ULONG_PTR pulOperationStateLen)
{
    (void)hSession;
    (void)pOperationState;
    (void)pulOperationStateLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_SetOperationState)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState,
                                                CK_ULONG ulOperationStateLen, CK_OBJECT_HANDLE hEncryptionKey,
                                                CK_OBJECT_HANDLE hAuthenticationKey)
{
    (void)hSession;
    (void)pOperationState;
    (void)ulOperationStateLen;
    (void)hEncryptionKey;
    (void)hAuthenticationKey;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_Login)(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin,
                                    CK_ULONG ulPinLen)
{
    PKCS11_TRY
    std::scoped_lock lock(libraryMutex);
    if (!library)
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    pkcs11_debug("C_Login session=%lu userType=%lu", (unsigned long)hSession, (unsigned long)userType);
    CK_RV rv = library->login(hSession, userType, pPin, ulPinLen);
    pkcs11_debug("C_Login -> rv=0x%08lx", (unsigned long)rv);
    return rv;
    PKCS11_CATCH
}

CK_DECLARE_FUNCTION(CK_RV, C_Logout)(CK_SESSION_HANDLE hSession)
{
    PKCS11_TRY
    std::scoped_lock lock(libraryMutex);
    if (!library)
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    return library->logout(hSession);
    PKCS11_CATCH
}

// ---------------------------------------------------------------------------
// Object management
// ---------------------------------------------------------------------------

CK_DECLARE_FUNCTION(CK_RV, C_CreateObject)(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
                                           CK_OBJECT_HANDLE_PTR phObject)
{
    (void)hSession;
    (void)pTemplate;
    (void)ulCount;
    (void)phObject;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_CopyObject)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
                                         CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phNewObject)
{
    (void)hSession;
    (void)hObject;
    (void)pTemplate;
    (void)ulCount;
    (void)phNewObject;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_DestroyObject)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject)
{
    (void)hSession;
    (void)hObject;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_GetObjectSize)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ULONG_PTR pulSize)
{
    (void)hSession;
    (void)hObject;
    (void)pulSize;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_GetAttributeValue)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
                                                CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
    PKCS11_TRY
    std::scoped_lock lock(libraryMutex);
    if (!library)
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    pkcs11_debug("C_GetAttributeValue session=%lu object=%lu attrs=%lu", (unsigned long)hSession,
                 (unsigned long)hObject, (unsigned long)ulCount);
    for (CK_ULONG i = 0; pTemplate && i < ulCount; ++i)
        pkcs11_debug("  attr[%lu] type=0x%08lx", (unsigned long)i, (unsigned long)pTemplate[i].type);
    CK_RV rv = library->getAttributeValue(hSession, hObject, pTemplate, ulCount);
    pkcs11_debug("C_GetAttributeValue -> rv=0x%08lx", (unsigned long)rv);
    return rv;
    PKCS11_CATCH
}

CK_DECLARE_FUNCTION(CK_RV, C_SetAttributeValue)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
                                                CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
    (void)hSession;
    (void)hObject;
    (void)pTemplate;
    (void)ulCount;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_FindObjectsInit)(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
    PKCS11_TRY
    std::scoped_lock lock(libraryMutex);
    if (!library)
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    pkcs11_debug("C_FindObjectsInit session=%lu attrs=%lu", (unsigned long)hSession, (unsigned long)ulCount);
    for (CK_ULONG i = 0; pTemplate && i < ulCount; ++i) {
        // For CKA_CLASS (0) log the class value, for CKA_TOKEN (1) log the bool
        if (pTemplate[i].type == CKA_CLASS && pTemplate[i].pValue &&
            pTemplate[i].ulValueLen == sizeof(CK_OBJECT_CLASS)) {
            CK_OBJECT_CLASS cls = 0;
            std::memcpy(&cls, pTemplate[i].pValue, sizeof(cls));
            pkcs11_debug("  attr[%lu] CKA_CLASS=0x%lx", (unsigned long)i, (unsigned long)cls);
        } else if (pTemplate[i].type == CKA_TOKEN && pTemplate[i].pValue &&
                   pTemplate[i].ulValueLen == sizeof(CK_BBOOL)) {
            pkcs11_debug("  attr[%lu] CKA_TOKEN=%d", (unsigned long)i,
                         (int)*static_cast<CK_BBOOL*>(pTemplate[i].pValue));
        } else {
            pkcs11_debug("  attr[%lu] type=0x%08lx len=%lu", (unsigned long)i, (unsigned long)pTemplate[i].type,
                         (unsigned long)pTemplate[i].ulValueLen);
        }
    }
    return library->findObjectsInit(hSession, pTemplate, ulCount);
    PKCS11_CATCH
}

CK_DECLARE_FUNCTION(CK_RV, C_FindObjects)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject,
                                          CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount)
{
    PKCS11_TRY
    std::scoped_lock lock(libraryMutex);
    if (!library)
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    CK_RV rv = library->findObjects(hSession, phObject, ulMaxObjectCount, pulObjectCount);
    if (pulObjectCount)
        pkcs11_debug("C_FindObjects -> %lu handles returned", (unsigned long)*pulObjectCount);
    return rv;
    PKCS11_CATCH
}

CK_DECLARE_FUNCTION(CK_RV, C_FindObjectsFinal)(CK_SESSION_HANDLE hSession)
{
    PKCS11_TRY
    std::scoped_lock lock(libraryMutex);
    if (!library)
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    return library->findObjectsFinal(hSession);
    PKCS11_CATCH
}

// ---------------------------------------------------------------------------
// Encryption
// ---------------------------------------------------------------------------

CK_DECLARE_FUNCTION(CK_RV, C_EncryptInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                                          CK_OBJECT_HANDLE hKey)
{
    (void)hSession;
    (void)pMechanism;
    (void)hKey;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_Encrypt)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
                                      CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen)
{
    (void)hSession;
    (void)pData;
    (void)ulDataLen;
    (void)pEncryptedData;
    (void)pulEncryptedDataLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_EncryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen,
                                            CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)
{
    (void)hSession;
    (void)pPart;
    (void)ulPartLen;
    (void)pEncryptedPart;
    (void)pulEncryptedPartLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_EncryptFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastEncryptedPart,
                                           CK_ULONG_PTR pulLastEncryptedPartLen)
{
    (void)hSession;
    (void)pLastEncryptedPart;
    (void)pulLastEncryptedPartLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

// ---------------------------------------------------------------------------
// Decryption
// ---------------------------------------------------------------------------

CK_DECLARE_FUNCTION(CK_RV, C_DecryptInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                                          CK_OBJECT_HANDLE hKey)
{
    (void)hSession;
    (void)pMechanism;
    (void)hKey;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_Decrypt)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData,
                                      CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
    (void)hSession;
    (void)pEncryptedData;
    (void)ulEncryptedDataLen;
    (void)pData;
    (void)pulDataLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_DecryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart,
                                            CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
{
    (void)hSession;
    (void)pEncryptedPart;
    (void)ulEncryptedPartLen;
    (void)pPart;
    (void)pulPartLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_DecryptFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastPart,
                                           CK_ULONG_PTR pulLastPartLen)
{
    (void)hSession;
    (void)pLastPart;
    (void)pulLastPartLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

// ---------------------------------------------------------------------------
// Message digesting
// ---------------------------------------------------------------------------

CK_DECLARE_FUNCTION(CK_RV, C_DigestInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism)
{
    (void)hSession;
    (void)pMechanism;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_Digest)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
                                     CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen)
{
    (void)hSession;
    (void)pData;
    (void)ulDataLen;
    (void)pDigest;
    (void)pulDigestLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_DigestUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
    (void)hSession;
    (void)pPart;
    (void)ulPartLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_DigestKey)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey)
{
    (void)hSession;
    (void)hKey;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_DigestFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen)
{
    (void)hSession;
    (void)pDigest;
    (void)pulDigestLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

// ---------------------------------------------------------------------------
// Signing and MACing
// ---------------------------------------------------------------------------

CK_DECLARE_FUNCTION(CK_RV, C_SignInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
    PKCS11_TRY
    std::scoped_lock lock(libraryMutex);
    if (!library)
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (pMechanism)
        pkcs11_debug("C_SignInit session=%lu mech=0x%08lx key=%lu", (unsigned long)hSession,
                     (unsigned long)pMechanism->mechanism, (unsigned long)hKey);
    CK_RV rv = library->signInit(hSession, pMechanism, hKey);
    pkcs11_debug("C_SignInit -> rv=0x%08lx", (unsigned long)rv);
    return rv;
    PKCS11_CATCH
}

CK_DECLARE_FUNCTION(CK_RV, C_Sign)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
                                   CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
    PKCS11_TRY
    std::scoped_lock lock(libraryMutex);
    if (!library)
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    pkcs11_debug("C_Sign session=%lu dataLen=%lu sigBuf=%s", (unsigned long)hSession, (unsigned long)ulDataLen,
                 pSignature ? "provided" : "NULL(size query)");
    CK_RV rv = library->sign(hSession, pData, ulDataLen, pSignature, pulSignatureLen);
    pkcs11_debug("C_Sign -> rv=0x%08lx sigLen=%lu", (unsigned long)rv,
                 pulSignatureLen ? (unsigned long)*pulSignatureLen : 0UL);
    return rv;
    PKCS11_CATCH
}

CK_DECLARE_FUNCTION(CK_RV, C_SignUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
    (void)hSession;
    (void)pPart;
    (void)ulPartLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_SignFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature,
                                        CK_ULONG_PTR pulSignatureLen)
{
    (void)hSession;
    (void)pSignature;
    (void)pulSignatureLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_SignRecoverInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                                              CK_OBJECT_HANDLE hKey)
{
    (void)hSession;
    (void)pMechanism;
    (void)hKey;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_SignRecover)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
                                          CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
    (void)hSession;
    (void)pData;
    (void)ulDataLen;
    (void)pSignature;
    (void)pulSignatureLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

// ---------------------------------------------------------------------------
// Verifying signatures and MACs
// ---------------------------------------------------------------------------

CK_DECLARE_FUNCTION(CK_RV, C_VerifyInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
    (void)hSession;
    (void)pMechanism;
    (void)hKey;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_Verify)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
                                     CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
    (void)hSession;
    (void)pData;
    (void)ulDataLen;
    (void)pSignature;
    (void)ulSignatureLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_VerifyUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
    (void)hSession;
    (void)pPart;
    (void)ulPartLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_VerifyFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
    (void)hSession;
    (void)pSignature;
    (void)ulSignatureLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_VerifyRecoverInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                                                CK_OBJECT_HANDLE hKey)
{
    (void)hSession;
    (void)pMechanism;
    (void)hKey;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_VerifyRecover)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen,
                                            CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
    (void)hSession;
    (void)pSignature;
    (void)ulSignatureLen;
    (void)pData;
    (void)pulDataLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

// ---------------------------------------------------------------------------
// Dual-function cryptographic operations
// ---------------------------------------------------------------------------

CK_DECLARE_FUNCTION(CK_RV, C_DigestEncryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen,
                                                  CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)
{
    (void)hSession;
    (void)pPart;
    (void)ulPartLen;
    (void)pEncryptedPart;
    (void)pulEncryptedPartLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_DecryptDigestUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart,
                                                  CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart,
                                                  CK_ULONG_PTR pulPartLen)
{
    (void)hSession;
    (void)pEncryptedPart;
    (void)ulEncryptedPartLen;
    (void)pPart;
    (void)pulPartLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_SignEncryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen,
                                                CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)
{
    (void)hSession;
    (void)pPart;
    (void)ulPartLen;
    (void)pEncryptedPart;
    (void)pulEncryptedPartLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_DecryptVerifyUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart,
                                                  CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart,
                                                  CK_ULONG_PTR pulPartLen)
{
    (void)hSession;
    (void)pEncryptedPart;
    (void)ulEncryptedPartLen;
    (void)pPart;
    (void)pulPartLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

// ---------------------------------------------------------------------------
// Key management
// ---------------------------------------------------------------------------

CK_DECLARE_FUNCTION(CK_RV, C_GenerateKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                                          CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phKey)
{
    (void)hSession;
    (void)pMechanism;
    (void)pTemplate;
    (void)ulCount;
    (void)phKey;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_GenerateKeyPair)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                                              CK_ATTRIBUTE_PTR pPublicKeyTemplate, CK_ULONG ulPublicKeyAttributeCount,
                                              CK_ATTRIBUTE_PTR pPrivateKeyTemplate, CK_ULONG ulPrivateKeyAttributeCount,
                                              CK_OBJECT_HANDLE_PTR phPublicKey, CK_OBJECT_HANDLE_PTR phPrivateKey)
{
    (void)hSession;
    (void)pMechanism;
    (void)pPublicKeyTemplate;
    (void)ulPublicKeyAttributeCount;
    (void)pPrivateKeyTemplate;
    (void)ulPrivateKeyAttributeCount;
    (void)phPublicKey;
    (void)phPrivateKey;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_WrapKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                                      CK_OBJECT_HANDLE hWrappingKey, CK_OBJECT_HANDLE hKey, CK_BYTE_PTR pWrappedKey,
                                      CK_ULONG_PTR pulWrappedKeyLen)
{
    (void)hSession;
    (void)pMechanism;
    (void)hWrappingKey;
    (void)hKey;
    (void)pWrappedKey;
    (void)pulWrappedKeyLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_UnwrapKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                                        CK_OBJECT_HANDLE hUnwrappingKey, CK_BYTE_PTR pWrappedKey,
                                        CK_ULONG ulWrappedKeyLen, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount,
                                        CK_OBJECT_HANDLE_PTR phKey)
{
    (void)hSession;
    (void)pMechanism;
    (void)hUnwrappingKey;
    (void)pWrappedKey;
    (void)ulWrappedKeyLen;
    (void)pTemplate;
    (void)ulAttributeCount;
    (void)phKey;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_DeriveKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                                        CK_OBJECT_HANDLE hBaseKey, CK_ATTRIBUTE_PTR pTemplate,
                                        CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey)
{
    (void)hSession;
    (void)pMechanism;
    (void)hBaseKey;
    (void)pTemplate;
    (void)ulAttributeCount;
    (void)phKey;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

// ---------------------------------------------------------------------------
// Random number generation
// ---------------------------------------------------------------------------

CK_DECLARE_FUNCTION(CK_RV, C_SeedRandom)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen)
{
    (void)hSession;
    (void)pSeed;
    (void)ulSeedLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_GenerateRandom)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR RandomData, CK_ULONG ulRandomLen)
{
    (void)hSession;
    (void)RandomData;
    (void)ulRandomLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

// ---------------------------------------------------------------------------
// Parallel function management (legacy)
// ---------------------------------------------------------------------------

CK_DECLARE_FUNCTION(CK_RV, C_GetFunctionStatus)(CK_SESSION_HANDLE hSession)
{
    (void)hSession;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_CancelFunction)(CK_SESSION_HANDLE hSession)
{
    (void)hSession;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

// ---------------------------------------------------------------------------
// Slot event
// ---------------------------------------------------------------------------

CK_DECLARE_FUNCTION(CK_RV, C_WaitForSlotEvent)(CK_FLAGS flags, CK_SLOT_ID_PTR pSlot, CK_VOID_PTR pRserved)
{
    (void)flags;
    (void)pSlot;
    (void)pRserved;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

// ---------------------------------------------------------------------------
// Function list table and C_GetFunctionList
// ---------------------------------------------------------------------------

static CK_FUNCTION_LIST function_list = {
    {CRYPTOKI_VERSION_MAJOR, CRYPTOKI_VERSION_MINOR},
    C_Initialize,
    C_Finalize,
    C_GetInfo,
    C_GetFunctionList,
    C_GetSlotList,
    C_GetSlotInfo,
    C_GetTokenInfo,
    C_GetMechanismList,
    C_GetMechanismInfo,
    C_InitToken,
    C_InitPIN,
    C_SetPIN,
    C_OpenSession,
    C_CloseSession,
    C_CloseAllSessions,
    C_GetSessionInfo,
    C_GetOperationState,
    C_SetOperationState,
    C_Login,
    C_Logout,
    C_CreateObject,
    C_CopyObject,
    C_DestroyObject,
    C_GetObjectSize,
    C_GetAttributeValue,
    C_SetAttributeValue,
    C_FindObjectsInit,
    C_FindObjects,
    C_FindObjectsFinal,
    C_EncryptInit,
    C_Encrypt,
    C_EncryptUpdate,
    C_EncryptFinal,
    C_DecryptInit,
    C_Decrypt,
    C_DecryptUpdate,
    C_DecryptFinal,
    C_DigestInit,
    C_Digest,
    C_DigestUpdate,
    C_DigestKey,
    C_DigestFinal,
    C_SignInit,
    C_Sign,
    C_SignUpdate,
    C_SignFinal,
    C_SignRecoverInit,
    C_SignRecover,
    C_VerifyInit,
    C_Verify,
    C_VerifyUpdate,
    C_VerifyFinal,
    C_VerifyRecoverInit,
    C_VerifyRecover,
    C_DigestEncryptUpdate,
    C_DecryptDigestUpdate,
    C_SignEncryptUpdate,
    C_DecryptVerifyUpdate,
    C_GenerateKey,
    C_GenerateKeyPair,
    C_WrapKey,
    C_UnwrapKey,
    C_DeriveKey,
    C_SeedRandom,
    C_GenerateRandom,
    C_GetFunctionStatus,
    C_CancelFunction,
    C_WaitForSlotEvent,
};

CK_DECLARE_FUNCTION(CK_RV, C_GetFunctionList)(CK_FUNCTION_LIST_PTR_PTR ppFunctionList)
{
    if (ppFunctionList == NULL_PTR)
        return CKR_ARGUMENTS_BAD;
    *ppFunctionList = &function_list;
    return CKR_OK;
}
