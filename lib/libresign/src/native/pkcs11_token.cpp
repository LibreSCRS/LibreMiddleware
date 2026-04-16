// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "libresign/native/pkcs11_token.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <dlfcn.h>
#include <mutex>
#include <stdexcept>

#define CK_PTR *
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType(*name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType(*name)
#ifndef NULL_PTR
#define NULL_PTR 0
#endif

#include "pkcs11/pkcs11.h"

namespace libresign {

namespace {

void checkRv(CK_RV rv, const char* operation)
{
    if (rv != CKR_OK) {
        char buf[32];
        std::snprintf(buf, sizeof(buf), "0x%08lX", static_cast<unsigned long>(rv));
        throw std::runtime_error(std::string(operation) + " failed: CKR " + buf);
    }
}

} // namespace

struct Pkcs11Token::Impl
{
    void* module = nullptr;
    CK_FUNCTION_LIST* funcs = nullptr;
    CK_SESSION_HANDLE session = 0;
    CK_OBJECT_HANDLE privateKey = 0;
    bool loggedIn = false;
    std::mutex sessionMutex;

    ~Impl()
    {
        if (funcs) {
            if (loggedIn)
                funcs->C_Logout(session);
            if (session)
                funcs->C_CloseSession(session);
            funcs->C_Finalize(nullptr);
        }
        if (module)
            dlclose(module);
    }

    void loadModule(const std::string& modulePath)
    {
        module = dlopen(modulePath.c_str(), RTLD_NOW);
        if (!module)
            throw std::runtime_error("Cannot load PKCS#11 module: " + std::string(dlerror()));

        auto getList = reinterpret_cast<CK_C_GetFunctionList>(dlsym(module, "C_GetFunctionList"));
        if (!getList)
            throw std::runtime_error("C_GetFunctionList not found in module");

        checkRv(getList(&funcs), "C_GetFunctionList");
        checkRv(funcs->C_Initialize(nullptr), "C_Initialize");
    }

    void openSessionAndLogin(CK_SLOT_ID slotId, std::span<const uint8_t> pin)
    {
        checkRv(funcs->C_OpenSession(slotId, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr, &session),
                "C_OpenSession");
        // C_Login copies the PIN into the module's session state — we do not
        // retain the view, and the caller owns and cleanses the underlying
        // storage.
        CK_RV rv =
            funcs->C_Login(session, CKU_USER, reinterpret_cast<CK_UTF8CHAR_PTR>(const_cast<uint8_t*>(pin.data())),
                           static_cast<CK_ULONG>(pin.size()));
        checkRv(rv, "C_Login");
        loggedIn = true;
    }

    void findPrivateKey(const std::string& keyAlias)
    {
        CK_OBJECT_CLASS keyClass = CKO_PRIVATE_KEY;
        CK_BBOOL canSign = CK_TRUE;

        std::vector<CK_ATTRIBUTE> keyTemplate;
        keyTemplate.push_back({CKA_CLASS, &keyClass, sizeof(keyClass)});

        if (!keyAlias.empty()) {
            keyTemplate.push_back(
                {CKA_LABEL, const_cast<char*>(keyAlias.c_str()), static_cast<CK_ULONG>(keyAlias.size())});
        } else {
            keyTemplate.push_back({CKA_SIGN, &canSign, sizeof(canSign)});
        }

        checkRv(funcs->C_FindObjectsInit(session, keyTemplate.data(), static_cast<CK_ULONG>(keyTemplate.size())),
                "C_FindObjectsInit");

        // RAII: always call C_FindObjectsFinal on scope exit, even if
        // C_FindObjects (or later code in this block) throws — otherwise
        // the session stays in find-active state, and subsequent
        // FindObjects calls on it fail with CKR_OPERATION_ACTIVE per
        // PKCS#11 §11.7.
        struct FindFinalizer
        {
            CK_FUNCTION_LIST_PTR f;
            CK_SESSION_HANDLE s;
            ~FindFinalizer()
            {
                if (f)
                    f->C_FindObjectsFinal(s);
            }
        };
        FindFinalizer finalizer{funcs, session};

        CK_ULONG found = 0;
        checkRv(funcs->C_FindObjects(session, &privateKey, 1, &found), "C_FindObjects");

        if (found == 0)
            throw std::runtime_error(keyAlias.empty() ? "No signing private key found on token"
                                                      : "Private key '" + keyAlias + "' not found on token");
    }

    std::vector<uint8_t> getKeyId()
    {
        std::vector<uint8_t> keyId;
        CK_ATTRIBUTE idAttr = {CKA_ID, nullptr, 0};
        if (funcs->C_GetAttributeValue(session, privateKey, &idAttr, 1) == CKR_OK && idAttr.ulValueLen > 0 &&
            idAttr.ulValueLen != CK_UNAVAILABLE_INFORMATION) {
            keyId.resize(idAttr.ulValueLen);
            idAttr.pValue = keyId.data();
            if (funcs->C_GetAttributeValue(session, privateKey, &idAttr, 1) != CKR_OK)
                keyId.clear();
        }
        return keyId;
    }

    CK_SLOT_ID findSlotByLabel(const std::string& tokenLabel)
    {
        CK_ULONG slotCount = 0;
        checkRv(funcs->C_GetSlotList(CK_TRUE, nullptr, &slotCount), "C_GetSlotList");
        if (slotCount == 0)
            throw std::runtime_error("No PKCS#11 slots with tokens found");

        std::vector<CK_SLOT_ID> slots(slotCount);
        checkRv(funcs->C_GetSlotList(CK_TRUE, slots.data(), &slotCount), "C_GetSlotList");

        for (auto slotId : slots) {
            CK_TOKEN_INFO tokenInfo;
            std::memset(&tokenInfo, 0, sizeof(tokenInfo));
            if (funcs->C_GetTokenInfo(slotId, &tokenInfo) != CKR_OK)
                continue;

            // CK_TOKEN_INFO.label is 32 bytes, space-padded, not null-terminated
            std::string label(reinterpret_cast<char*>(tokenInfo.label), 32);
            // Trim trailing spaces
            auto end = label.find_last_not_of(' ');
            if (end != std::string::npos)
                label.resize(end + 1);
            else
                label.clear();

            if (label.find(tokenLabel) != std::string::npos)
                return slotId;
        }

        throw std::runtime_error("No token with label containing '" + tokenLabel + "' found");
    }
};

Pkcs11Token::Pkcs11Token(const std::string& modulePath, std::span<const uint8_t> pin, const std::string& keyAlias,
                         int slotIndex)
    : impl(std::make_unique<Impl>())
{
    impl->loadModule(modulePath);

    CK_ULONG slotCount = 0;
    checkRv(impl->funcs->C_GetSlotList(CK_TRUE, nullptr, &slotCount), "C_GetSlotList");
    if (slotCount == 0)
        throw std::runtime_error("No PKCS#11 slots with tokens found");

    std::vector<CK_SLOT_ID> slots(slotCount);
    checkRv(impl->funcs->C_GetSlotList(CK_TRUE, slots.data(), &slotCount), "C_GetSlotList");

    CK_SLOT_ID slotId;
    if (slotIndex >= 0) {
        // Use slotIndex as the physical PKCS#11 slot ID directly
        slotId = static_cast<CK_SLOT_ID>(slotIndex);
    } else {
        // Use first available token-present slot
        slotId = slots[0];
    }

    impl->openSessionAndLogin(slotId, pin);
    impl->findPrivateKey(keyAlias);
}

Pkcs11Token::Pkcs11Token(const std::string& modulePath, std::span<const uint8_t> pin, const std::string& keyAlias,
                         const std::string& tokenLabel)
    : impl(std::make_unique<Impl>())
{
    impl->loadModule(modulePath);
    CK_SLOT_ID slotId = impl->findSlotByLabel(tokenLabel);
    impl->openSessionAndLogin(slotId, pin);
    impl->findPrivateKey(keyAlias);
}

Pkcs11Token::~Pkcs11Token() = default;

std::vector<uint8_t> Pkcs11Token::sign(std::span<const uint8_t> hash, const std::string& algorithm)
{
    std::scoped_lock lock(impl->sessionMutex);

    // Route to CKM_ECDSA for ECDSA / JWS ES256/ES384/ES512 aliases.
    // Previously we matched any string starting with "ES" which would
    // also accept "ES-PSS" or typos; narrow to the three canonical JWS
    // alg names plus OpenSSL "ECDSA…" variants.
    const bool isEcdsa = algorithm.find("ECDSA") != std::string::npos || algorithm == "ES256" || algorithm == "ES384" ||
                         algorithm == "ES512";
    CK_MECHANISM mechanism;
    if (isEcdsa)
        mechanism = {CKM_ECDSA, nullptr, 0};
    else
        mechanism = {CKM_RSA_PKCS, nullptr, 0};
    checkRv(impl->funcs->C_SignInit(impl->session, &mechanism, impl->privateKey), "C_SignInit");

    CK_ULONG sigLen = 0;
    checkRv(impl->funcs->C_Sign(impl->session, const_cast<CK_BYTE_PTR>(hash.data()), hash.size(), nullptr, &sigLen),
            "C_Sign (length)");

    std::vector<uint8_t> signature(sigLen);
    checkRv(impl->funcs->C_Sign(impl->session, const_cast<CK_BYTE_PTR>(hash.data()), hash.size(), signature.data(),
                                &sigLen),
            "C_Sign");
    signature.resize(sigLen);
    return signature;
}

std::vector<uint8_t> Pkcs11Token::certificate() const
{
    std::scoped_lock lock(impl->sessionMutex);

    CK_OBJECT_CLASS certClass = CKO_CERTIFICATE;

    // Try to get CKA_ID from the private key to match the correct certificate
    auto keyId = impl->getKeyId();

    // Build template: always filter by CKO_CERTIFICATE, optionally by CKA_ID
    std::vector<CK_ATTRIBUTE> certTemplate;
    certTemplate.push_back({CKA_CLASS, &certClass, sizeof(certClass)});
    if (!keyId.empty())
        certTemplate.push_back({CKA_ID, keyId.data(), static_cast<CK_ULONG>(keyId.size())});

    if (impl->funcs->C_FindObjectsInit(impl->session, certTemplate.data(),
                                       static_cast<CK_ULONG>(certTemplate.size())) != CKR_OK)
        return {};

    CK_OBJECT_HANDLE certHandle = 0;
    CK_ULONG found = 0;
    CK_RV rv = impl->funcs->C_FindObjects(impl->session, &certHandle, 1, &found);
    impl->funcs->C_FindObjectsFinal(impl->session);

    // Fallback: if CKA_ID filter matched nothing, retry without it
    if ((rv != CKR_OK || found == 0) && !keyId.empty()) {
        CK_ATTRIBUTE fallbackTemplate[] = {{CKA_CLASS, &certClass, sizeof(certClass)}};
        if (impl->funcs->C_FindObjectsInit(impl->session, fallbackTemplate, 1) != CKR_OK)
            return {};
        rv = impl->funcs->C_FindObjects(impl->session, &certHandle, 1, &found);
        impl->funcs->C_FindObjectsFinal(impl->session);
    }

    if (rv != CKR_OK || found == 0)
        return {};

    CK_ATTRIBUTE valueAttr = {CKA_VALUE, nullptr, 0};
    if (impl->funcs->C_GetAttributeValue(impl->session, certHandle, &valueAttr, 1) != CKR_OK)
        return {};
    // Per PKCS#11 §5.7 C_GetAttributeValue, a sensitive/unavailable
    // attribute sets ulValueLen to CK_UNAVAILABLE_INFORMATION (= (CK_ULONG)-1)
    // while still returning CKR_OK. Guard against using that sentinel as a
    // size — vector(ulValueLen) would throw bad_alloc trying to allocate
    // SIZE_MAX bytes.
    if (valueAttr.ulValueLen == CK_UNAVAILABLE_INFORMATION || valueAttr.ulValueLen == 0)
        return {};

    std::vector<uint8_t> certData(valueAttr.ulValueLen);
    valueAttr.pValue = certData.data();
    if (impl->funcs->C_GetAttributeValue(impl->session, certHandle, &valueAttr, 1) != CKR_OK)
        return {};

    return certData;
}

std::vector<std::vector<uint8_t>> Pkcs11Token::certificateChain() const
{
    std::scoped_lock lock(impl->sessionMutex);

    // Get CKA_ID from private key to identify the signer certificate
    auto keyId = impl->getKeyId();

    // Find ALL certificates on the token
    CK_OBJECT_CLASS certClass = CKO_CERTIFICATE;
    CK_ATTRIBUTE tmpl[] = {{CKA_CLASS, &certClass, sizeof(certClass)}};

    if (impl->funcs->C_FindObjectsInit(impl->session, tmpl, 1) != CKR_OK)
        return {};

    // RAII: always call C_FindObjectsFinal on scope exit — same pattern as
    // findPrivateKey(). Without this, an exception from C_FindObjects
    // leaves the session in find-active state.
    struct FindFinalizer
    {
        CK_FUNCTION_LIST_PTR f;
        CK_SESSION_HANDLE s;
        ~FindFinalizer()
        {
            if (f)
                f->C_FindObjectsFinal(s);
        }
    };
    FindFinalizer finalizer{impl->funcs, impl->session};

    // Per PKCS#11 spec §5.7.7, C_FindObjects may return fewer handles than
    // the buffer can hold even when more objects match — we must loop until
    // it returns zero. Earlier revision used a single call into a 64-slot
    // buffer which silently dropped certs on tokens that paginate in
    // smaller batches (observed on some PIV and HSM implementations).
    std::vector<CK_OBJECT_HANDLE> allHandles;
    constexpr CK_ULONG kBatchSize = 64;
    CK_RV rv = CKR_OK;
    for (;;) {
        CK_OBJECT_HANDLE batch[kBatchSize];
        CK_ULONG found = 0;
        rv = impl->funcs->C_FindObjects(impl->session, batch, kBatchSize, &found);
        if (rv != CKR_OK || found == 0)
            break;
        allHandles.insert(allHandles.end(), batch, batch + found);
        // Defensive upper bound so a misbehaving token can't OOM us.
        if (allHandles.size() > 4096)
            break;
    }

    if (rv != CKR_OK)
        return {};

    // Read each certificate and check if its CKA_ID matches the private key
    std::vector<std::vector<uint8_t>> chain;
    int signerIndex = -1;

    for (CK_OBJECT_HANDLE handle : allHandles) {
        CK_ATTRIBUTE valueAttr = {CKA_VALUE, nullptr, 0};
        if (impl->funcs->C_GetAttributeValue(impl->session, handle, &valueAttr, 1) != CKR_OK)
            continue;
        // Skip sensitive/unavailable certs — see certificate() for the
        // CK_UNAVAILABLE_INFORMATION rationale.
        if (valueAttr.ulValueLen == CK_UNAVAILABLE_INFORMATION || valueAttr.ulValueLen == 0)
            continue;

        std::vector<uint8_t> certData(valueAttr.ulValueLen);
        valueAttr.pValue = certData.data();
        if (impl->funcs->C_GetAttributeValue(impl->session, handle, &valueAttr, 1) != CKR_OK)
            continue;

        // Check CKA_ID match for this certificate
        if (!keyId.empty() && signerIndex < 0) {
            CK_ATTRIBUTE certIdAttr = {CKA_ID, nullptr, 0};
            if (impl->funcs->C_GetAttributeValue(impl->session, handle, &certIdAttr, 1) == CKR_OK &&
                certIdAttr.ulValueLen != CK_UNAVAILABLE_INFORMATION && certIdAttr.ulValueLen == keyId.size()) {
                std::vector<uint8_t> certId(certIdAttr.ulValueLen);
                certIdAttr.pValue = certId.data();
                if (impl->funcs->C_GetAttributeValue(impl->session, handle, &certIdAttr, 1) == CKR_OK &&
                    certId == keyId) {
                    signerIndex = static_cast<int>(chain.size());
                }
            }
        }

        chain.push_back(std::move(certData));
    }

    // Move signer certificate to front of chain
    if (signerIndex > 0)
        std::swap(chain[0], chain[static_cast<size_t>(signerIndex)]);

    return chain;
}

} // namespace libresign
