// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

/// @file
/// @brief PKCS#11 v2.40 library facade. Routes every C entry point
///        through the @ref LibreSCRS::Pkcs11::Internal Card+Slot model.
///
/// Registered providers conform to
/// @ref LibreSCRS::Pkcs11::Internal::PKCS11CardProvider and surface
/// @ref LibreSCRS::Pkcs11::Internal::PKCS11Slot instances through the
/// snapshot/probe-outside/commit pattern documented at
/// @ref PKCS11Library::getSlotList.

#include "pkcs11_platform.h"

#include <atomic>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace LibreSCRS::Pkcs11::Internal {
class PKCS11Card;
class PKCS11Slot;
class PKCS11CardProvider;
struct PKCS11ObjectInfo;
} // namespace LibreSCRS::Pkcs11::Internal

/// @brief Per-session find-cursor for @c C_FindObjects continuation.
struct FindState
{
    std::vector<CK_OBJECT_HANDLE> matchedHandles;
    std::size_t cursor = 0;
};

/// @brief Per-session sign state established by @c C_SignInit.
struct SignState
{
    CK_OBJECT_HANDLE keyHandle;
    CK_MECHANISM_TYPE mechanism;
    std::vector<std::uint8_t> buffer; ///< Multi-part accumulator.
    bool multiPart = false;
};

/// @brief Per-session bookkeeping.
struct SessionEntry
{
    CK_SLOT_ID slotID;
    CK_FLAGS flags;
    std::optional<FindState> findState;
    std::optional<SignState> signState;
    bool busy = false;
};

class PKCS11Library
{
public:
    /// @brief Construct an empty library; providers are registered via
    ///        @ref registerProvider before any @c C_GetSlotList call.
    PKCS11Library();
    ~PKCS11Library();

    PKCS11Library(const PKCS11Library&) = delete;
    PKCS11Library& operator=(const PKCS11Library&) = delete;

    // -------- General-purpose ----------------------------------------

    CK_RV getInfo(CK_INFO_PTR pInfo) const;

    // -------- Slot / token -------------------------------------------

    /// @brief Marshal slot IDs into the PKCS#11 ABI format.
    /// @par Implementation
    /// Routes through @ref enumerateSlotIds (snapshot/probe-outside/commit).
    /// @c tokenPresent is currently advisory: the new path only commits
    /// slots once a provider's @c probe() succeeds, so all surfaced IDs
    /// already have a token.
    CK_RV getSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount);
    CK_RV getSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo);
    CK_RV getTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo);

    CK_RV getMechanismList(CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG_PTR pulCount);
    CK_RV getMechanismInfo(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo);

    // -------- Sessions -----------------------------------------------

    CK_RV openSession(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, CK_NOTIFY Notify,
                      CK_SESSION_HANDLE_PTR phSession);
    CK_RV closeSession(CK_SESSION_HANDLE hSession);
    CK_RV closeAllSessions(CK_SLOT_ID slotID);
    CK_RV getSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo);
    CK_RV login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen);
    CK_RV logout(CK_SESSION_HANDLE hSession);

    // -------- Objects ------------------------------------------------

    CK_RV findObjectsInit(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
    CK_RV findObjects(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject, CK_ULONG ulMaxObjectCount,
                      CK_ULONG_PTR pulObjectCount);
    CK_RV findObjectsFinal(CK_SESSION_HANDLE hSession);
    CK_RV getAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate,
                            CK_ULONG ulCount);

    // -------- Sign --------------------------------------------------

    CK_RV signInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
    CK_RV sign(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
               CK_ULONG_PTR pulSignatureLen);
    CK_RV signUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen);
    CK_RV signFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen);

    // -------- Provider registration ---------------------------------

    /// @brief Append @p provider to the Card+Slot provider list.
    /// @par Thread-safety
    /// Internally synchronised on @c cardSlotLibMutex. Intended to be
    /// called once at @c C_Initialize time.
    void registerProvider(std::shared_ptr<LibreSCRS::Pkcs11::Internal::PKCS11CardProvider> provider);

    /// @brief Lookup a previously committed slot by stable ID.
    /// @return Shared @ref PKCS11Slot or @c nullptr.
    [[nodiscard]] std::shared_ptr<LibreSCRS::Pkcs11::Internal::PKCS11Slot> findSlot(unsigned long slotId) const;

    /// @brief Trigger probe of registered providers across the current
    ///        PC/SC reader list and return the resulting stable slot IDs.
    /// @par Lock discipline
    /// Snapshot reader list + provider list under @c cardSlotLibMutex,
    /// run @c probe() OUTSIDE the lock (PC/SC I/O), commit cardMap /
    /// slotMap entries under the lock again. Per-reader probing is
    /// exactly-once-per-card-insertion via @c std::call_once; the flag
    /// is reset by @ref notifyCardRemoved so a hot-swap triggers a
    /// fresh probe.
    [[nodiscard]] std::vector<unsigned long> enumerateSlotIds();

    /// @brief Invalidate cached state for @p readerName so the next
    ///        @ref enumerateSlotIds reprobes.
    ///
    /// Drops the cardMap entry for the reader, removes every slot
    /// that card owned from slotMap, drops their object caches, and
    /// resets the per-reader once-flag. Hot-swap of a different card
    /// in the same reader otherwise leaves the old card's slots
    /// surfaced indefinitely (the once-flag was permanently latched
    /// after the first successful probe).
    /// @param readerName PC/SC reader the card was removed from.
    /// @par Thread-safety
    /// Internally synchronised on @c cardSlotLibMutex,
    /// @c slotCacheMutex, and @c sessionMutex. Safe to call from a
    /// MonitorService poll thread.
    /// @since 4.1
    void notifyCardRemoved(const std::string& readerName);

private:
    // -------- Card+Slot state ---------------------------------------
    mutable std::mutex cardSlotLibMutex;
    std::vector<std::shared_ptr<LibreSCRS::Pkcs11::Internal::PKCS11CardProvider>> cardSlotProviders;
    std::map<std::string, std::shared_ptr<LibreSCRS::Pkcs11::Internal::PKCS11Card>> cardMap;
    std::map<unsigned long, std::shared_ptr<LibreSCRS::Pkcs11::Internal::PKCS11Slot>> slotMap;
    std::map<std::string, std::shared_ptr<std::once_flag>> readerProbeFlags;

    // -------- Per-slot object cache ---------------------------------
    /// @brief Per-slot object handle entry.
    struct ObjectEntry
    {
        CK_SLOT_ID slotID;
        CK_OBJECT_HANDLE handle;
        std::shared_ptr<LibreSCRS::Pkcs11::Internal::PKCS11ObjectInfo> info;
    };

    /// @brief Per-slot enumeration cache. Populated lazily by
    ///        @ref ensureSlotObjectsLoaded; invalidated on login,
    ///        logout, and reset recovery.
    struct SlotCacheEntry
    {
        bool loaded = false;
        std::vector<ObjectEntry> objects;
    };

    /// @brief Per-slot guard for the object cache. Decoupled from the
    ///        @c slotMap container so accessors hold one slot's mutex
    ///        without serialising sibling slots.
    mutable std::mutex slotCacheMutex;
    std::map<CK_SLOT_ID, SlotCacheEntry> slotCache;

    /// @brief Global object handle table (handle → slot+entry).
    /// @guarded_by sessionMutex (write at FindObjectsInit time, also
    /// taken in getAttributeValue / signInit lookups).
    std::map<CK_OBJECT_HANDLE, ObjectEntry> objectHandleMap;
    std::atomic<CK_OBJECT_HANDLE> nextObjectHandle{1};

    // -------- Sessions ----------------------------------------------
    mutable std::mutex sessionMutex;
    CK_SESSION_HANDLE nextSessionHandle = 1;
    std::map<CK_SESSION_HANDLE, SessionEntry> sessions;

    // -------- Helpers -----------------------------------------------

    /// @brief Snapshot of currently visible PC/SC readers.
    [[nodiscard]] static std::vector<std::string> snapshotPcscReaders();

    /// @brief Probe @p readers with all registered providers exactly
    ///        once each, committing successful results to cardMap /
    ///        slotMap.
    void probeReadersOnce(const std::vector<std::string>& readers);

    /// @brief Populate this slot's cache via @c slot->enumerateObjects()
    ///        if not already loaded.
    /// @par Thread-safety
    /// Caller must NOT hold @c slotCacheMutex; this method takes it.
    void ensureSlotObjectsLoaded(CK_SLOT_ID slotID, LibreSCRS::Pkcs11::Internal::PKCS11Slot& slot);

    /// @brief Drop the cached object table for @p slotID and remove
    ///        every handle attributed to it from @ref objectHandleMap.
    void invalidateSlotObjects(CK_SLOT_ID slotID);

    /// @brief Match a single object against a PKCS#11 attribute template.
    [[nodiscard]] bool matchesTemplate(const LibreSCRS::Pkcs11::Internal::PKCS11ObjectInfo& obj,
                                       CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount) const;
};
