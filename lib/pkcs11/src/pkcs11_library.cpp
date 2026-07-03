// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

/// @file
/// @brief @ref PKCS11Library implementation routed through the
///        multi-PIN Card+Slot architecture.

#include "pkcs11_library.h"

#include "digest_info.h"
#include "pkcs11_version.h"

#include <internal/Crv.h>
#include <internal/PKCS11Card.h>
#include <internal/PKCS11CardProvider.h>
#include <internal/PKCS11ObjectInfo.h>
#include <internal/PKCS11Slot.h>
#include <internal/PKCS11TokenInfo.h>
#include <pkcs11/internal/slot_hash.h>

#include <pcsc_connection.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>

#include <algorithm>
#include <cstring>
#include <memory>
#include <mutex>
#include <utility>
#include <vector>

namespace {

namespace LcInt = LibreSCRS::Pkcs11::Internal;

// ---------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------

/// @brief Pad a UTF-8 string into a fixed-width PKCS#11 buffer.
void padString(CK_UTF8CHAR* dest, std::size_t destLen, const char* src)
{
    std::memset(dest, ' ', destLen);
    auto srcLen = std::strlen(src);
    std::memcpy(dest, src, std::min(srcLen, destLen));
}

/// @brief Combined hash+sign mechanism predicate.
[[nodiscard]] bool isCombinedHashMechanism(CK_MECHANISM_TYPE mech) noexcept
{
    return mech == CKM_SHA1_RSA_PKCS || mech == CKM_SHA256_RSA_PKCS || mech == CKM_SHA384_RSA_PKCS ||
           mech == CKM_SHA512_RSA_PKCS;
}

/// @brief RSA-PSS combined hash+sign mechanism predicate.
[[nodiscard]] bool isPSSMechanism(CK_MECHANISM_TYPE mech) noexcept
{
    return mech == CKM_SHA256_RSA_PKCS_PSS || mech == CKM_SHA384_RSA_PKCS_PSS || mech == CKM_SHA512_RSA_PKCS_PSS;
}

/// @brief Hash @p data and prepend the RFC-3447 DigestInfo prefix.
[[nodiscard]] std::vector<std::uint8_t> buildDigestInfo(CK_MECHANISM_TYPE mech, const std::uint8_t* data,
                                                        std::size_t dataLen)
{
    const EVP_MD* md = nullptr;
    const std::uint8_t* pfx = nullptr;
    std::size_t pfxLen = 0;
    switch (mech) {
    case CKM_SHA1_RSA_PKCS:
        md = EVP_sha1();
        pfx = libresign::kDigestInfoSha1Prefix;
        pfxLen = sizeof(libresign::kDigestInfoSha1Prefix);
        break;
    case CKM_SHA256_RSA_PKCS:
        md = EVP_sha256();
        pfx = libresign::kDigestInfoSha256Prefix;
        pfxLen = sizeof(libresign::kDigestInfoSha256Prefix);
        break;
    case CKM_SHA384_RSA_PKCS:
        md = EVP_sha384();
        pfx = libresign::kDigestInfoSha384Prefix;
        pfxLen = sizeof(libresign::kDigestInfoSha384Prefix);
        break;
    case CKM_SHA512_RSA_PKCS:
        md = EVP_sha512();
        pfx = libresign::kDigestInfoSha512Prefix;
        pfxLen = sizeof(libresign::kDigestInfoSha512Prefix);
        break;
    default:
        throw std::runtime_error("buildDigestInfo: unsupported mechanism");
    }

    std::vector<std::uint8_t> hash(static_cast<std::size_t>(EVP_MD_size(md)));
    auto ctx = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (!ctx)
        throw std::runtime_error("buildDigestInfo: EVP_MD_CTX_new failed");
    unsigned int hLen = static_cast<unsigned int>(hash.size());
    if (!EVP_DigestInit_ex(ctx.get(), md, nullptr) || !EVP_DigestUpdate(ctx.get(), data, dataLen) ||
        !EVP_DigestFinal_ex(ctx.get(), hash.data(), &hLen)) {
        throw std::runtime_error("buildDigestInfo: digest operation failed");
    }

    std::vector<std::uint8_t> digestInfo(pfxLen + hash.size());
    std::memcpy(digestInfo.data(), pfx, pfxLen);
    std::memcpy(digestInfo.data() + pfxLen, hash.data(), hash.size());
    return digestInfo;
}

/// @brief Map @ref Crv to a PKCS#11 @c CK_RV.
[[nodiscard]] CK_RV crvToCkRv(unsigned long crv) noexcept
{
    // Crv constants intentionally share their numeric values with the
    // PKCS#11 standard CKR_* codes (see internal/Crv.h). The cast is
    // therefore the identity transform but routed through the named
    // CK_RV type to keep callers honest.
    return static_cast<CK_RV>(crv);
}

/// @brief RAII guard that releases @c sessionMutex while card I/O runs
///        and re-acquires it (clearing @c busy) on scope exit.
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

/// @brief PKCS#11 v2.40 numeric constants reused on the new path.
constexpr unsigned long kCkoCertificate = 1UL;
constexpr unsigned long kCkoPrivateKey = 3UL;
constexpr unsigned long kCkkRsa = 0UL;
constexpr unsigned long kCkkEc = 3UL;

} // namespace

// ---------------------------------------------------------------------
// Construction / destruction
// ---------------------------------------------------------------------

PKCS11Library::PKCS11Library() = default;

PKCS11Library::~PKCS11Library()
{
    // Best-effort: log out every slot. Slot/Card destructors handle
    // their own transport teardown; we only need to drop authentication
    // state so the next instance starts clean.
    std::scoped_lock lk(cardSlotLibMutex);
    for (auto& [_, slot] : slotMap) {
        if (slot && slot->isLoggedIn()) {
            try {
                (void)slot->logout();
            } catch (...) {
            }
        }
    }
}

// ---------------------------------------------------------------------
// General-purpose
// ---------------------------------------------------------------------

CK_RV PKCS11Library::getInfo(CK_INFO_PTR pInfo) const
{
    if (pInfo == nullptr)
        return CKR_ARGUMENTS_BAD;

    std::memset(pInfo, 0, sizeof(CK_INFO));
    pInfo->cryptokiVersion.major = 2;
    pInfo->cryptokiVersion.minor = 40;
    padString(pInfo->manufacturerID, sizeof(pInfo->manufacturerID), "LibreSCRS");
    pInfo->flags = 0;
    padString(pInfo->libraryDescription, sizeof(pInfo->libraryDescription), "LibreSCRS PKCS#11");
    pInfo->libraryVersion.major = LIBRESCRS_PKCS11_VERSION_MAJOR;
    pInfo->libraryVersion.minor = LIBRESCRS_PKCS11_VERSION_MINOR;
    return CKR_OK;
}

// ---------------------------------------------------------------------
// Provider registration / slot enumeration
// ---------------------------------------------------------------------

void PKCS11Library::registerProvider(std::shared_ptr<LcInt::PKCS11CardProvider> provider)
{
    if (!provider)
        return;
    std::scoped_lock lk(cardSlotLibMutex);
    cardSlotProviders.push_back(std::move(provider));
}

std::vector<std::string> PKCS11Library::snapshotPcscReaders()
{
    try {
        return LibreSCRS::SmartCard::Internal::PCSCConnection::listReaders();
    } catch (...) {
        return {};
    }
}

void PKCS11Library::probeReadersOnce(const std::vector<std::string>& readers)
{
    // Snapshot providers under the lock; probe outside the lock; commit
    // back under the lock. Per-reader probing is exactly-once via
    // std::call_once on a per-reader flag whose lifetime is decoupled
    // from the iterator (shared_ptr-owned).
    std::vector<std::shared_ptr<LcInt::PKCS11CardProvider>> providersSnapshot;
    {
        std::scoped_lock lk(cardSlotLibMutex);
        providersSnapshot = cardSlotProviders;
    }

    for (const auto& reader : readers) {
        std::shared_ptr<std::once_flag> flag;
        {
            std::scoped_lock lk(cardSlotLibMutex);
            auto& slot = readerProbeFlags[reader];
            if (!slot)
                slot = std::make_shared<std::once_flag>();
            flag = slot;
        }

        std::call_once(*flag, [&]() {
            std::shared_ptr<LcInt::PKCS11Card> card;
            for (const auto& provider : providersSnapshot) {
                if (!provider)
                    continue;
                try {
                    card = provider->probe(reader);
                } catch (...) {
                    card = nullptr;
                }
                if (card)
                    break;
            }
            if (!card)
                return;

            std::scoped_lock lk(cardSlotLibMutex);
            cardMap.insert_or_assign(reader, card);
            for (const auto& s : card->enumerateSlots()) {
                if (s)
                    slotMap.insert_or_assign(s->stableId(), s);
            }
        });
    }
}

std::vector<unsigned long> PKCS11Library::enumerateSlotIds()
{
    const auto readers = snapshotPcscReaders();
    probeReadersOnce(readers);

    std::vector<unsigned long> result;
    {
        std::scoped_lock lk(cardSlotLibMutex);
        result.reserve(slotMap.size());
        for (const auto& [id, _] : slotMap)
            result.push_back(id);
    }
    return result;
}

std::shared_ptr<LcInt::PKCS11Slot> PKCS11Library::findSlot(unsigned long slotId) const
{
    std::scoped_lock lk(cardSlotLibMutex);
    auto it = slotMap.find(slotId);
    if (it == slotMap.end())
        return nullptr;
    return it->second;
}

// ---------------------------------------------------------------------
// C_GetSlotList / C_GetSlotInfo / C_GetTokenInfo
// ---------------------------------------------------------------------

CK_RV PKCS11Library::getSlotList(CK_BBOOL /*tokenPresent*/, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount)
{
    if (pulCount == nullptr)
        return CKR_ARGUMENTS_BAD;

    auto slotIds = enumerateSlotIds();

    if (pSlotList == nullptr) {
        *pulCount = static_cast<CK_ULONG>(slotIds.size());
        return CKR_OK;
    }

    if (*pulCount < slotIds.size()) {
        *pulCount = static_cast<CK_ULONG>(slotIds.size());
        return CKR_BUFFER_TOO_SMALL;
    }

    for (std::size_t i = 0; i < slotIds.size(); ++i)
        pSlotList[i] = static_cast<CK_SLOT_ID>(slotIds[i]);
    *pulCount = static_cast<CK_ULONG>(slotIds.size());
    return CKR_OK;
}

CK_RV PKCS11Library::getSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo)
{
    if (pInfo == nullptr)
        return CKR_ARGUMENTS_BAD;

    auto slot = findSlot(static_cast<unsigned long>(slotID));
    if (!slot)
        return CKR_SLOT_ID_INVALID;

    std::string readerName;
    if (auto card = slot->lockParentCard()) {
        readerName = card->reader();
    }

    std::memset(pInfo, 0, sizeof(CK_SLOT_INFO));
    std::memset(pInfo->slotDescription, ' ', sizeof(pInfo->slotDescription));
    LcInt::formatSlotDescription(readerName, reinterpret_cast<char*>(pInfo->slotDescription));
    padString(pInfo->manufacturerID, sizeof(pInfo->manufacturerID), "LibreSCRS");
    pInfo->flags = CKF_REMOVABLE_DEVICE | CKF_HW_SLOT | CKF_TOKEN_PRESENT;
    pInfo->hardwareVersion = {0, 0};
    pInfo->firmwareVersion = {0, 0};
    return CKR_OK;
}

CK_RV PKCS11Library::getTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo)
{
    if (pInfo == nullptr)
        return CKR_ARGUMENTS_BAD;

    auto slot = findSlot(static_cast<unsigned long>(slotID));
    if (!slot)
        return CKR_SLOT_ID_INVALID;

    auto info = slot->tokenInfo();

    // Count sessions for this slot (under sessionMutex only).
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

    std::memset(pInfo, 0, sizeof(CK_TOKEN_INFO));
    padString(pInfo->label, sizeof(pInfo->label), info.label.c_str());
    padString(pInfo->manufacturerID, sizeof(pInfo->manufacturerID), info.manufacturerId.c_str());
    padString(pInfo->model, sizeof(pInfo->model), info.model.c_str());
    padString(pInfo->serialNumber, sizeof(pInfo->serialNumber), info.serialNumber.c_str());

    // Derive the standard PKCS#11 flags: any provider that publishes a
    // login-required token must surface CKF_TOKEN_INITIALIZED,
    // CKF_LOGIN_REQUIRED, and CKF_USER_PIN_INITIALIZED so consumers can
    // open a session, log in, and search. Bits beyond those are
    // forwarded verbatim if the provider set them. WRITE_PROTECTED is
    // unconditionally set: this library never modifies card state.
    pInfo->flags = info.flags | CKF_WRITE_PROTECTED;

    pInfo->ulMaxSessionCount = CK_EFFECTIVELY_INFINITE;
    pInfo->ulSessionCount = sessionCount;
    pInfo->ulMaxRwSessionCount = CK_EFFECTIVELY_INFINITE;
    pInfo->ulRwSessionCount = rwSessionCount;
    pInfo->ulMaxPinLen = info.maxPinLen;
    pInfo->ulMinPinLen = info.minPinLen;
    pInfo->ulTotalPublicMemory = CK_UNAVAILABLE_INFORMATION;
    pInfo->ulFreePublicMemory = CK_UNAVAILABLE_INFORMATION;
    pInfo->ulTotalPrivateMemory = CK_UNAVAILABLE_INFORMATION;
    pInfo->ulFreePrivateMemory = CK_UNAVAILABLE_INFORMATION;
    pInfo->hardwareVersion = {info.hardwareVersionMajor, info.hardwareVersionMinor};
    pInfo->firmwareVersion = {info.firmwareVersionMajor, info.firmwareVersionMinor};
    padString(pInfo->utcTime, sizeof(pInfo->utcTime), "");
    return CKR_OK;
}

// ---------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------

CK_RV PKCS11Library::openSession(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, CK_NOTIFY Notify,
                                 CK_SESSION_HANDLE_PTR phSession)
{
    (void)pApplication;
    (void)Notify;

    if (phSession == nullptr)
        return CKR_ARGUMENTS_BAD;
    if (!(flags & CKF_SERIAL_SESSION))
        return CKR_SESSION_PARALLEL_NOT_SUPPORTED;

    auto slot = findSlot(static_cast<unsigned long>(slotID));
    if (!slot)
        return CKR_SLOT_ID_INVALID;

    std::scoped_lock lock(sessionMutex);
    CK_SESSION_HANDLE handle = nextSessionHandle++;
    sessions[handle] = {slotID, flags, {}, {}, false};
    *phSession = handle;
    return CKR_OK;
}

CK_RV PKCS11Library::closeSession(CK_SESSION_HANDLE hSession)
{
    CK_SLOT_ID slotID = 0;
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

        bool hasOther = false;
        for (auto& [h, entry] : sessions) {
            if (entry.slotID == slotID) {
                hasOther = true;
                break;
            }
        }
        shouldLogout = !hasOther;
    }

    if (shouldLogout) {
        if (auto slot = findSlot(static_cast<unsigned long>(slotID))) {
            if (slot->isLoggedIn()) {
                try {
                    (void)slot->logout();
                } catch (...) {
                }
                invalidateSlotObjects(slotID);
            }
        }
    }
    return CKR_OK;
}

CK_RV PKCS11Library::closeAllSessions(CK_SLOT_ID slotID)
{
    auto slot = findSlot(static_cast<unsigned long>(slotID));
    if (!slot)
        return CKR_SLOT_ID_INVALID;

    {
        std::scoped_lock lock(sessionMutex);
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

    if (slot->isLoggedIn()) {
        try {
            (void)slot->logout();
        } catch (...) {
        }
        invalidateSlotObjects(slotID);
    }
    return CKR_OK;
}

CK_RV PKCS11Library::getSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo)
{
    if (pInfo == nullptr)
        return CKR_ARGUMENTS_BAD;

    CK_SLOT_ID slotID = 0;
    CK_FLAGS flags = 0;
    {
        std::scoped_lock lock(sessionMutex);
        auto it = sessions.find(hSession);
        if (it == sessions.end())
            return CKR_SESSION_HANDLE_INVALID;
        slotID = it->second.slotID;
        flags = it->second.flags;
    }

    bool loggedIn = false;
    if (auto slot = findSlot(static_cast<unsigned long>(slotID)))
        loggedIn = slot->isLoggedIn();

    std::memset(pInfo, 0, sizeof(CK_SESSION_INFO));
    pInfo->slotID = slotID;
    pInfo->flags = flags;
    pInfo->ulDeviceError = 0;

    bool isRW = (flags & CKF_RW_SESSION) != 0;
    if (isRW)
        pInfo->state = loggedIn ? CKS_RW_USER_FUNCTIONS : CKS_RW_PUBLIC_SESSION;
    else
        pInfo->state = loggedIn ? CKS_RO_USER_FUNCTIONS : CKS_RO_PUBLIC_SESSION;
    return CKR_OK;
}

CK_RV PKCS11Library::login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
    if (userType != CKU_USER)
        return CKR_USER_TYPE_INVALID;
    if (pPin == nullptr)
        return CKR_ARGUMENTS_BAD;

    CK_SLOT_ID slotID = 0;
    {
        std::scoped_lock lock(sessionMutex);
        auto it = sessions.find(hSession);
        if (it == sessions.end())
            return CKR_SESSION_HANDLE_INVALID;
        slotID = it->second.slotID;
    }

    auto slot = findSlot(static_cast<unsigned long>(slotID));
    if (!slot)
        return CKR_SLOT_ID_INVALID;

    if (slot->isLoggedIn())
        return CKR_USER_ALREADY_LOGGED_IN;

    auto info = slot->tokenInfo();
    if (ulPinLen < info.minPinLen || ulPinLen > info.maxPinLen)
        return CKR_PIN_LEN_RANGE;

    auto rv = crvToCkRv(slot->login(static_cast<unsigned long>(userType),
                                    std::span<const std::uint8_t>{static_cast<std::uint8_t*>(pPin), ulPinLen}));
    if (rv == CKR_OK) {
        // Login may rebuild the on-card view (e.g. PACE flow); drop the
        // cached object table for this slot so the next FindObjectsInit
        // re-enumerates against the post-login surface.
        invalidateSlotObjects(slotID);
    }
    return rv;
}

CK_RV PKCS11Library::logout(CK_SESSION_HANDLE hSession)
{
    CK_SLOT_ID slotID = 0;
    {
        std::scoped_lock lock(sessionMutex);
        auto it = sessions.find(hSession);
        if (it == sessions.end())
            return CKR_SESSION_HANDLE_INVALID;
        slotID = it->second.slotID;
    }
    auto slot = findSlot(static_cast<unsigned long>(slotID));
    if (!slot)
        return CKR_SLOT_ID_INVALID;
    if (!slot->isLoggedIn())
        return CKR_USER_NOT_LOGGED_IN;
    auto rv = crvToCkRv(slot->logout());
    if (rv == CKR_OK) {
        // Symmetric to login(): drop the cached object table so any private
        // objects that became inaccessible at logout don't leave stale
        // handles in objectHandleMap.
        invalidateSlotObjects(slotID);
    }
    return rv;
}

// ---------------------------------------------------------------------
// Object discovery
// ---------------------------------------------------------------------

void PKCS11Library::ensureSlotObjectsLoaded(CK_SLOT_ID slotID, LcInt::PKCS11Slot& slot)
{
    {
        std::scoped_lock lk(slotCacheMutex);
        auto it = slotCache.find(slotID);
        if (it != slotCache.end() && it->second.loaded)
            return;
    }

    // Run enumerateObjects OUTSIDE slotCacheMutex (it can do card I/O).
    auto infos = slot.enumerateObjects();

    std::scoped_lock lk(slotCacheMutex);
    auto& entry = slotCache[slotID];
    if (entry.loaded)
        return; // raced; another caller populated.

    entry.objects.clear();
    entry.objects.reserve(infos.size());
    for (auto& info : infos) {
        ObjectEntry oe;
        oe.slotID = slotID;
        oe.handle = nextObjectHandle.fetch_add(1, std::memory_order_relaxed);
        oe.info = std::make_shared<LcInt::PKCS11ObjectInfo>(std::move(info));
        entry.objects.push_back(std::move(oe));
    }
    entry.loaded = true;
}

void PKCS11Library::notifyCardRemoved(const std::string& readerName)
{
    // Collect the slot IDs the departing card owned so we can drop
    // their object caches outside cardSlotLibMutex.
    std::vector<unsigned long> doomedSlotIds;
    {
        std::scoped_lock lk(cardSlotLibMutex);
        auto cardIt = cardMap.find(readerName);
        if (cardIt != cardMap.end() && cardIt->second) {
            for (const auto& slot : cardIt->second->enumerateSlots()) {
                if (slot)
                    doomedSlotIds.push_back(slot->stableId());
            }
            cardMap.erase(cardIt);
        }
        for (auto id : doomedSlotIds)
            slotMap.erase(id);
        // Drop the once-flag so the next enumerateSlotIds reprobes.
        // Resetting (rather than erasing-and-reinserting) keeps any
        // racing reader alive on its shared_ptr until its call_once
        // body returns; the next reader will allocate a fresh flag.
        readerProbeFlags.erase(readerName);
    }
    for (auto id : doomedSlotIds)
        invalidateSlotObjects(static_cast<CK_SLOT_ID>(id));
}

void PKCS11Library::invalidateSlotObjects(CK_SLOT_ID slotID)
{
    std::vector<CK_OBJECT_HANDLE> dropped;
    {
        std::scoped_lock lk(slotCacheMutex);
        auto it = slotCache.find(slotID);
        if (it == slotCache.end())
            return;
        dropped.reserve(it->second.objects.size());
        for (auto& oe : it->second.objects)
            dropped.push_back(oe.handle);
        it->second.objects.clear();
        it->second.loaded = false;
    }

    if (dropped.empty())
        return;
    std::scoped_lock sk(sessionMutex);
    for (auto h : dropped)
        objectHandleMap.erase(h);
}

bool PKCS11Library::matchesTemplate(const LcInt::PKCS11ObjectInfo& obj, CK_ATTRIBUTE_PTR pTemplate,
                                    CK_ULONG ulCount) const
{
    for (CK_ULONG i = 0; i < ulCount; ++i) {
        auto& attr = pTemplate[i];
        switch (attr.type) {
        case CKA_CLASS:
            if (attr.ulValueLen == sizeof(CK_OBJECT_CLASS)) {
                CK_OBJECT_CLASS val;
                std::memcpy(&val, attr.pValue, sizeof(val));
                if (static_cast<unsigned long>(val) != obj.objectClass)
                    return false;
            }
            break;
        case CKA_TOKEN:
            if (attr.ulValueLen == sizeof(CK_BBOOL)) {
                CK_BBOOL val;
                std::memcpy(&val, attr.pValue, sizeof(val));
                if ((obj.token ? CK_TRUE : CK_FALSE) != val)
                    return false;
            }
            break;
        case CKA_PRIVATE:
            if (attr.ulValueLen == sizeof(CK_BBOOL)) {
                CK_BBOOL val;
                std::memcpy(&val, attr.pValue, sizeof(val));
                if ((obj.privateObj ? CK_TRUE : CK_FALSE) != val)
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
                if (attr.ulValueLen != obj.id.size() || std::memcmp(attr.pValue, obj.id.data(), attr.ulValueLen) != 0)
                    return false;
            }
            break;
        case CKA_KEY_TYPE:
            if (attr.ulValueLen == sizeof(CK_KEY_TYPE)) {
                CK_KEY_TYPE val;
                std::memcpy(&val, attr.pValue, sizeof(val));
                if (static_cast<unsigned long>(val) != obj.keyType)
                    return false;
            }
            break;
        case CKA_VALUE:
            if (attr.pValue != nullptr) {
                if (attr.ulValueLen != obj.value.size() ||
                    std::memcmp(attr.pValue, obj.value.data(), attr.ulValueLen) != 0)
                    return false;
            }
            break;
        case CKA_MODULUS_BITS: {
            if (obj.objectClass == kCkoPrivateKey && !obj.modulus.empty() && attr.ulValueLen == sizeof(CK_ULONG)) {
                CK_ULONG val;
                std::memcpy(&val, attr.pValue, sizeof(val));
                CK_ULONG bits = static_cast<CK_ULONG>(obj.modulus.size() * 8);
                if (val != bits)
                    return false;
            }
            break;
        }
        case CKA_SIGN: {
            // Private keys advertised by the slot are signing keys; the
            // legacy provider-driven path also unconditionally returned
            // CK_TRUE for CKA_SIGN on enumerated private keys.
            if (obj.objectClass == kCkoPrivateKey && attr.ulValueLen == sizeof(CK_BBOOL)) {
                CK_BBOOL val;
                std::memcpy(&val, attr.pValue, sizeof(val));
                if (val != CK_TRUE)
                    return false;
            }
            break;
        }
        case CKA_SENSITIVE:
        case CKA_ALWAYS_SENSITIVE:
        case CKA_NEVER_EXTRACTABLE:
        case CKA_LOCAL: {
            if (obj.objectClass == kCkoPrivateKey && attr.ulValueLen == sizeof(CK_BBOOL)) {
                CK_BBOOL val;
                std::memcpy(&val, attr.pValue, sizeof(val));
                if (val != CK_TRUE)
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
            if (obj.objectClass == kCkoPrivateKey && attr.ulValueLen == sizeof(CK_BBOOL)) {
                CK_BBOOL val;
                std::memcpy(&val, attr.pValue, sizeof(val));
                if (val != CK_FALSE)
                    return false;
            }
            break;
        }
        case CKA_SUBJECT:
            if (obj.objectClass == kCkoCertificate && attr.pValue != nullptr) {
                if (attr.ulValueLen != obj.subject.size() ||
                    std::memcmp(attr.pValue, obj.subject.data(), attr.ulValueLen) != 0)
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
            break;
        }
    }
    return true;
}

CK_RV PKCS11Library::findObjectsInit(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
    std::unique_lock sessLock(sessionMutex);
    auto it = sessions.find(hSession);
    if (it == sessions.end())
        return CKR_SESSION_HANDLE_INVALID;
    auto& session = it->second;
    if (session.busy)
        return CKR_FUNCTION_FAILED;
    if (session.findState.has_value())
        return CKR_OPERATION_ACTIVE;
    if (ulCount > 0 && pTemplate == nullptr)
        return CKR_ARGUMENTS_BAD;

    const CK_SLOT_ID slotID = session.slotID;
    auto slot = findSlot(static_cast<unsigned long>(slotID));
    if (!slot)
        return CKR_SLOT_ID_INVALID;

    // Drop the session lock while ensureSlotObjectsLoaded does card I/O;
    // re-acquire to publish findState. ConcurrentCloseSession on this
    // handle in the interim is detected by the post-I/O re-lookup.
    sessLock.unlock();
    ensureSlotObjectsLoaded(slotID, *slot);

    FindState state;
    {
        std::scoped_lock lk(slotCacheMutex);
        auto cit = slotCache.find(slotID);
        if (cit != slotCache.end()) {
            for (auto& oe : cit->second.objects) {
                if (matchesTemplate(*oe.info, pTemplate, ulCount))
                    state.matchedHandles.push_back(oe.handle);
            }
        }
    }

    sessLock.lock();
    {
        std::scoped_lock cacheLk(slotCacheMutex);
        auto cit = slotCache.find(slotID);
        if (cit != slotCache.end()) {
            for (auto& oe : cit->second.objects)
                objectHandleMap[oe.handle] = oe;
        }
    }

    auto it2 = sessions.find(hSession);
    if (it2 == sessions.end())
        return CKR_SESSION_HANDLE_INVALID;
    if (it2->second.busy)
        return CKR_FUNCTION_FAILED;
    if (it2->second.findState.has_value())
        return CKR_OPERATION_ACTIVE;
    it2->second.findState = std::move(state);
    return CKR_OK;
}

CK_RV PKCS11Library::findObjects(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject, CK_ULONG ulMaxObjectCount,
                                 CK_ULONG_PTR pulObjectCount)
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
    if (pTemplate == nullptr && ulCount > 0)
        return CKR_ARGUMENTS_BAD;

    CK_SLOT_ID slotID = 0;
    {
        std::scoped_lock lock(sessionMutex);
        auto sessIt = sessions.find(hSession);
        if (sessIt == sessions.end())
            return CKR_SESSION_HANDLE_INVALID;
        slotID = sessIt->second.slotID;
    }

    std::shared_ptr<LcInt::PKCS11ObjectInfo> info;
    {
        std::scoped_lock lock(sessionMutex);
        auto it = objectHandleMap.find(hObject);
        if (it == objectHandleMap.end())
            return CKR_OBJECT_HANDLE_INVALID;
        if (it->second.slotID != slotID)
            return CKR_OBJECT_HANDLE_INVALID;
        info = it->second.info;
    }

    const auto& obj = *info;
    CK_RV result = CKR_OK;
    CK_ULONG modulusBits = 0;

    static const CK_BBOOL kBoolTrue = CK_TRUE;
    static const CK_BBOOL kBoolFalse = CK_FALSE;

    for (CK_ULONG i = 0; i < ulCount; ++i) {
        auto& attr = pTemplate[i];
        const void* src = nullptr;
        CK_ULONG srcLen = 0;
        bool found = false;

        // We materialise CK_OBJECT_CLASS, CK_KEY_TYPE, CK_CERTIFICATE_TYPE
        // on the stack because the PKCS#11 type widths differ from the
        // unsigned-long fields stored on @c PKCS11ObjectInfo on some
        // platforms.
        CK_OBJECT_CLASS classOut = static_cast<CK_OBJECT_CLASS>(obj.objectClass);
        CK_KEY_TYPE keyTypeOut = static_cast<CK_KEY_TYPE>(obj.keyType);
        // Certificates come from the PKCS#15 / CardEdge / PIV slots as
        // X.509 (CKC_X_509 == 0). The new ObjectInfo surface does not
        // carry a separate certificateType field so we hard-code it.
        static constexpr CK_CERTIFICATE_TYPE kCertTypeX509 = CKC_X_509;

        switch (attr.type) {
        case CKA_CLASS:
            src = &classOut;
            srcLen = sizeof(classOut);
            found = true;
            break;
        case CKA_TOKEN: {
            src = obj.token ? &kBoolTrue : &kBoolFalse;
            srcLen = sizeof(CK_BBOOL);
            found = true;
            break;
        }
        case CKA_PRIVATE: {
            src = obj.privateObj ? &kBoolTrue : &kBoolFalse;
            srcLen = sizeof(CK_BBOOL);
            found = true;
            break;
        }
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
            if (obj.objectClass == kCkoCertificate) {
                src = obj.value.data();
                srcLen = static_cast<CK_ULONG>(obj.value.size());
                found = true;
            }
            break;
        case CKA_CERTIFICATE_TYPE:
            if (obj.objectClass == kCkoCertificate) {
                src = &kCertTypeX509;
                srcLen = sizeof(kCertTypeX509);
                found = true;
            }
            break;
        case CKA_KEY_TYPE:
            if (obj.objectClass == kCkoPrivateKey) {
                src = &keyTypeOut;
                srcLen = sizeof(keyTypeOut);
                found = true;
            }
            break;
        case CKA_SIGN:
            // Slots only enumerate signing keys today; surface CK_TRUE
            // unconditionally for private-key objects.
            if (obj.objectClass == kCkoPrivateKey) {
                src = &kBoolTrue;
                srcLen = sizeof(kBoolTrue);
                found = true;
            }
            break;
        case CKA_SENSITIVE:
        case CKA_ALWAYS_SENSITIVE:
            if (obj.objectClass == kCkoPrivateKey) {
                src = &kBoolTrue;
                srcLen = sizeof(kBoolTrue);
                found = true;
            }
            break;
        case CKA_NEVER_EXTRACTABLE:
        case CKA_LOCAL:
            if (obj.objectClass == kCkoPrivateKey) {
                src = &kBoolTrue;
                srcLen = sizeof(kBoolTrue);
                found = true;
            }
            break;
        case CKA_DECRYPT:
        case CKA_ENCRYPT:
        case CKA_WRAP:
        case CKA_UNWRAP:
            if (obj.objectClass == kCkoPrivateKey) {
                src = &kBoolFalse;
                srcLen = sizeof(kBoolFalse);
                found = true;
            }
            break;
        case CKA_EXTRACTABLE:
        case CKA_ALWAYS_AUTHENTICATE:
        case CKA_DERIVE:
        case CKA_SIGN_RECOVER:
        case CKA_VERIFY:
        case CKA_VERIFY_RECOVER:
            if (obj.objectClass == kCkoPrivateKey) {
                src = &kBoolFalse;
                srcLen = sizeof(kBoolFalse);
                found = true;
            }
            break;
        case CKA_MODULUS:
            if (obj.objectClass == kCkoPrivateKey && !obj.modulus.empty()) {
                src = obj.modulus.data();
                srcLen = static_cast<CK_ULONG>(obj.modulus.size());
                found = true;
            }
            break;
        case CKA_PUBLIC_EXPONENT:
            if (obj.objectClass == kCkoPrivateKey && !obj.publicExponent.empty()) {
                src = obj.publicExponent.data();
                srcLen = static_cast<CK_ULONG>(obj.publicExponent.size());
                found = true;
            }
            break;
        case CKA_MODULUS_BITS:
            if (obj.objectClass == kCkoPrivateKey && !obj.modulus.empty()) {
                modulusBits = static_cast<CK_ULONG>(obj.modulus.size() * 8);
                src = &modulusBits;
                srcLen = sizeof(modulusBits);
                found = true;
            }
            break;
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
            if (obj.objectClass == kCkoCertificate && !obj.subject.empty()) {
                src = obj.subject.data();
                srcLen = static_cast<CK_ULONG>(obj.subject.size());
                found = true;
            }
            break;
        case CKA_TRUSTED:
            if (obj.objectClass == kCkoCertificate) {
                src = &kBoolFalse;
                srcLen = sizeof(kBoolFalse);
                found = true;
            }
            break;
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

// ---------------------------------------------------------------------
// Sign
// ---------------------------------------------------------------------

CK_RV PKCS11Library::signInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
    std::scoped_lock sessLock(sessionMutex);
    auto sessIt = sessions.find(hSession);
    if (sessIt == sessions.end())
        return CKR_SESSION_HANDLE_INVALID;
    auto& session = sessIt->second;
    if (session.busy)
        return CKR_FUNCTION_FAILED;
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

    const CK_SLOT_ID slotID = session.slotID;
    auto objIt = objectHandleMap.find(hKey);
    if (objIt == objectHandleMap.end())
        return CKR_KEY_HANDLE_INVALID;
    if (objIt->second.slotID != slotID)
        return CKR_KEY_HANDLE_INVALID;

    auto& obj = *objIt->second.info;
    if (obj.objectClass != kCkoPrivateKey)
        return CKR_KEY_TYPE_INCONSISTENT;

    auto slot = findSlot(static_cast<unsigned long>(slotID));
    if (!slot)
        return CKR_SLOT_ID_INVALID;
    if (!slot->isLoggedIn())
        return CKR_USER_NOT_LOGGED_IN;

    SignState state{hKey, pMechanism->mechanism, {}, false};
    session.signState = std::move(state);
    return CKR_OK;
}

CK_RV PKCS11Library::sign(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
                          CK_ULONG_PTR pulSignatureLen)
{
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
    if (session.signState->multiPart) {
        session.signState.reset();
        return CKR_FUNCTION_FAILED;
    }
    if (pulSignatureLen == nullptr)
        return CKR_ARGUMENTS_BAD;
    // pData may be null only for an empty input; a null pointer with a non-zero
    // length would otherwise reach buildDigestInfo -> EVP_DigestUpdate(nullptr).
    if (pData == nullptr && ulDataLen > 0)
        return CKR_ARGUMENTS_BAD;

    auto handle = session.signState->keyHandle;
    auto mech = session.signState->mechanism;

    auto objIt = objectHandleMap.find(handle);
    if (objIt == objectHandleMap.end()) {
        session.signState.reset();
        return CKR_DEVICE_ERROR;
    }
    auto info = objIt->second.info;

    auto slot = findSlot(static_cast<unsigned long>(slotID));
    if (!slot) {
        session.signState.reset();
        return CKR_SLOT_ID_INVALID;
    }

    CK_ULONG sigSize = static_cast<CK_ULONG>(slot->signatureSize(info->id));
    if (sigSize == 0) {
        // Reasonable defaults: RSA = modulus length (256 = 2048-bit) /
        // ECDSA = 2*field + 8 DER overhead.
        sigSize = info->keyType == kCkkEc ? 72u : 256u;
    }

    if (pSignature == nullptr) {
        *pulSignatureLen = sigSize;
        return CKR_OK;
    }
    if (*pulSignatureLen < sigSize) {
        *pulSignatureLen = sigSize;
        return CKR_BUFFER_TOO_SMALL;
    }

    // RSA-PKCS data length validation (legacy parity).
    if (mech == CKM_RSA_PKCS && !info->modulus.empty() && info->modulus.size() > 11) {
        const CK_ULONG maxInput = static_cast<CK_ULONG>(info->modulus.size()) - 11;
        if (ulDataLen > maxInput) {
            session.signState.reset();
            return CKR_DATA_LEN_RANGE;
        }
    }

    // Consume sign state, mark busy, drop session lock for card I/O.
    session.signState.reset();
    session.busy = true;
    SessionBusyGuard busyGuard(sessLock, session);

    try {
        std::vector<std::uint8_t> sig;
        std::span<const std::uint8_t> keyIdSpan{info->id};

        auto attemptSign = [&]() {
            if (isCombinedHashMechanism(mech) || isPSSMechanism(mech)) {
                std::vector<std::uint8_t> digestInfo;
                if (!isPSSMechanism(mech))
                    digestInfo = buildDigestInfo(mech, pData, ulDataLen);
                std::vector<std::uint8_t> rawData(pData, pData + ulDataLen);
                sig = slot->signWithDigestInfo(std::span<const std::uint8_t>{digestInfo},
                                               std::span<const std::uint8_t>{rawData}, mech, keyIdSpan);
            } else {
                // CKM_RSA_PKCS / CKM_ECDSA: pre-built input.
                std::span<const std::uint8_t> dataSpan{pData, ulDataLen};
                sig = slot->signData(dataSpan, mech, keyIdSpan);
            }
        };

        attemptSign();

        // Inline RESET-recovery retry-once. Empty signature is the slot's
        // signal for transport failure (legacy path mapped SCARD_W_RESET_CARD
        // to CKR_DEVICE_ERROR); attempt a card-level reattach via
        // PKCS11Card::handleReset() under cardMutex and retry the sign once.
        if (sig.empty()) {
            if (auto card = slot->lockParentCard()) {
                if (card->handleReset() == LcInt::Crv::Ok)
                    attemptSign();
            }
        }

        if (sig.empty())
            return CKR_DEVICE_ERROR;
        if (*pulSignatureLen < sig.size()) {
            *pulSignatureLen = static_cast<CK_ULONG>(sig.size());
            return CKR_DEVICE_ERROR;
        }
        std::memcpy(pSignature, sig.data(), sig.size());
        *pulSignatureLen = static_cast<CK_ULONG>(sig.size());
        return CKR_OK;
    } catch (...) {
        return CKR_DEVICE_ERROR;
    }
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
        session.signState.reset();
        return CKR_ARGUMENTS_BAD;
    }
    if (!isCombinedHashMechanism(session.signState->mechanism) && !isPSSMechanism(session.signState->mechanism)) {
        session.signState.reset();
        return CKR_FUNCTION_NOT_SUPPORTED;
    }

    session.signState->multiPart = true;
    constexpr std::size_t kMaxSignBuffer = 64u * 1024u * 1024u;
    if (ulPartLen > kMaxSignBuffer || session.signState->buffer.size() > kMaxSignBuffer - ulPartLen) {
        session.signState.reset();
        return CKR_DATA_LEN_RANGE;
    }
    if (ulPartLen > 0)
        session.signState->buffer.insert(session.signState->buffer.end(), pPart, pPart + ulPartLen);
    return CKR_OK;
}

CK_RV PKCS11Library::signFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
    std::unique_lock sessLock(sessionMutex);
    auto sessIt = sessions.find(hSession);
    if (sessIt == sessions.end())
        return CKR_SESSION_HANDLE_INVALID;
    auto& session = sessIt->second;
    if (session.busy)
        return CKR_FUNCTION_FAILED;
    if (!session.signState.has_value())
        return CKR_OPERATION_NOT_INITIALIZED;
    if (!isCombinedHashMechanism(session.signState->mechanism) && !isPSSMechanism(session.signState->mechanism)) {
        session.signState.reset();
        return CKR_FUNCTION_NOT_SUPPORTED;
    }
    if (pulSignatureLen == nullptr)
        return CKR_ARGUMENTS_BAD;

    const CK_SLOT_ID slotID = session.slotID;
    auto handle = session.signState->keyHandle;
    auto mech = session.signState->mechanism;

    auto objIt = objectHandleMap.find(handle);
    if (objIt == objectHandleMap.end()) {
        session.signState.reset();
        return CKR_DEVICE_ERROR;
    }
    auto info = objIt->second.info;

    auto slot = findSlot(static_cast<unsigned long>(slotID));
    if (!slot) {
        session.signState.reset();
        return CKR_SLOT_ID_INVALID;
    }

    CK_ULONG sigSize = static_cast<CK_ULONG>(slot->signatureSize(info->id));
    if (sigSize == 0)
        sigSize = info->keyType == kCkkEc ? 72u : 256u;

    if (pSignature == nullptr) {
        *pulSignatureLen = sigSize;
        return CKR_OK;
    }
    if (*pulSignatureLen < sigSize) {
        *pulSignatureLen = sigSize;
        return CKR_BUFFER_TOO_SMALL;
    }

    auto buffer = std::move(session.signState->buffer);
    session.signState.reset();
    session.busy = true;
    SessionBusyGuard busyGuard(sessLock, session);

    try {
        std::vector<std::uint8_t> digestInfo;
        if (!isPSSMechanism(mech))
            digestInfo = buildDigestInfo(mech, buffer.data(), buffer.size());
        auto sig =
            slot->signWithDigestInfo(std::span<const std::uint8_t>{digestInfo}, std::span<const std::uint8_t>{buffer},
                                     mech, std::span<const std::uint8_t>{info->id});

        // Inline RESET-recovery retry-once (parity with single-shot sign path).
        if (sig.empty()) {
            if (auto card = slot->lockParentCard()) {
                if (card->handleReset() == LcInt::Crv::Ok) {
                    sig = slot->signWithDigestInfo(std::span<const std::uint8_t>{digestInfo},
                                                   std::span<const std::uint8_t>{buffer}, mech,
                                                   std::span<const std::uint8_t>{info->id});
                }
            }
        }

        if (sig.empty())
            return CKR_DEVICE_ERROR;
        if (*pulSignatureLen < sig.size()) {
            *pulSignatureLen = static_cast<CK_ULONG>(sig.size());
            return CKR_DEVICE_ERROR;
        }
        std::memcpy(pSignature, sig.data(), sig.size());
        *pulSignatureLen = static_cast<CK_ULONG>(sig.size());
        return CKR_OK;
    } catch (...) {
        return CKR_DEVICE_ERROR;
    }
}

// ---------------------------------------------------------------------
// Mechanisms
// ---------------------------------------------------------------------

CK_RV PKCS11Library::getMechanismList(CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG_PTR pulCount)
{
    if (pulCount == nullptr)
        return CKR_ARGUMENTS_BAD;

    auto slot = findSlot(static_cast<unsigned long>(slotID));
    if (!slot)
        return CKR_SLOT_ID_INVALID;

    auto mechs = slot->mechanisms();
    if (pMechanismList == nullptr) {
        *pulCount = static_cast<CK_ULONG>(mechs.size());
        return CKR_OK;
    }
    if (*pulCount < mechs.size()) {
        *pulCount = static_cast<CK_ULONG>(mechs.size());
        return CKR_BUFFER_TOO_SMALL;
    }
    for (std::size_t i = 0; i < mechs.size(); ++i)
        pMechanismList[i] = static_cast<CK_MECHANISM_TYPE>(mechs[i]);
    *pulCount = static_cast<CK_ULONG>(mechs.size());
    return CKR_OK;
}

CK_RV PKCS11Library::getMechanismInfo(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo)
{
    if (pInfo == nullptr)
        return CKR_ARGUMENTS_BAD;
    auto slot = findSlot(static_cast<unsigned long>(slotID));
    if (!slot)
        return CKR_SLOT_ID_INVALID;
    if (type != CKM_RSA_PKCS && type != CKM_ECDSA && !isCombinedHashMechanism(type) && !isPSSMechanism(type))
        return CKR_MECHANISM_INVALID;

    std::memset(pInfo, 0, sizeof(CK_MECHANISM_INFO));
    if (type == CKM_ECDSA) {
        pInfo->ulMinKeySize = 256;
        pInfo->ulMaxKeySize = 521;
        pInfo->flags = CKF_SIGN | CKF_HW;
        return CKR_OK;
    }

    // RSA: derive the key-size range from the slot's enumerated keys.
    // Materialise the cache lazily; if enumeration has not yet run we
    // fall back to a permissive range matching the legacy behaviour.
    ensureSlotObjectsLoaded(slotID, *slot);

    CK_ULONG minBits = 0, maxBits = 0;
    {
        std::scoped_lock lk(slotCacheMutex);
        auto cit = slotCache.find(slotID);
        if (cit != slotCache.end()) {
            for (auto& oe : cit->second.objects) {
                if (oe.info->objectClass == kCkoPrivateKey && !oe.info->modulus.empty()) {
                    auto bits = static_cast<CK_ULONG>(oe.info->modulus.size() * 8);
                    if (minBits == 0 || bits < minBits)
                        minBits = bits;
                    if (bits > maxBits)
                        maxBits = bits;
                }
            }
        }
    }
    if (minBits == 0) {
        minBits = 1024;
        maxBits = 8192;
    }
    pInfo->ulMinKeySize = minBits;
    pInfo->ulMaxKeySize = maxBits;
    pInfo->flags = CKF_SIGN | CKF_HW;
    return CKR_OK;
}
