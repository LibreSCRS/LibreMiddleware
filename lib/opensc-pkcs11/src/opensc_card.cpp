// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

/// @file
/// @brief @ref LibreSCRS::OpenSc::Pkcs11::OpenScCard implementation —
///        wraps the vendored libopensc surface (sc_context / sc_card /
///        sc_pkcs15_card) under the project's PKCS11Card abstraction.

#include "opensc_card.h"

#include "opensc_slot.h"

#include <internal/Crv.h>
#include <internal/PKCS11TokenInfo.h>
#include <internal/SlotIdHash.h>
#include <internal/SlotKindClassifier.h>

#include <libopensc/errors.h>
#include <libopensc/opensc.h>
#include <libopensc/pkcs15.h>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <string>
#include <utility>

namespace LibreSCRS::OpenSc::Pkcs11 {

namespace {

/// @brief PKCS#11 v2.40 token-flag bits used in @ref PKCS11TokenInfo.
/// Raw values intentionally avoid pulling pkcs11t.h into this TU.
constexpr unsigned long kCkfTokenInitialized = 0x00000400UL;
constexpr unsigned long kCkfLoginRequired = 0x00000004UL;
constexpr unsigned long kCkfUserPinInitialized = 0x00000008UL;

/// @brief Filter for AODF PIN objects: drop the PUK / unblocking entries
///        (we surface only user-auth slots; OpenSC's auth_info conveys
///        the role via the @c SC_PKCS15_PIN_FLAG_UNBLOCKING_PIN bit).
[[nodiscard]] bool isUserPin(const sc_pkcs15_auth_info_t* auth) noexcept
{
    if (!auth)
        return false;
    if (auth->auth_type != SC_PKCS15_PIN_AUTH_TYPE_PIN)
        return false;
    if (auth->attrs.pin.flags & SC_PKCS15_PIN_FLAG_UNBLOCKING_PIN)
        return false;
    if (auth->attrs.pin.flags & SC_PKCS15_PIN_FLAG_SO_PIN)
        return false;
    return true;
}

/// @brief PIN-label → @ref SlotKind via the shared classifier so the
///        FNV-1a stable slot ID stays consistent with the in-tree
///        custom Pkcs15 provider when both can see the same card.
[[nodiscard]] LibreSCRS::Pkcs11::Internal::SlotKind deriveSlotKind(const char* labelCstr) noexcept
{
    if (!labelCstr)
        return LibreSCRS::Pkcs11::Internal::SlotKind::Generic;
    std::string label(labelCstr);
    std::transform(label.begin(), label.end(), label.begin(), [](unsigned char c) { return std::tolower(c); });
    return LibreSCRS::Pkcs11::Internal::classifyFromLabel(label);
}

/// @brief Maximum number of PKCS#15 objects fetched per @c sc_pkcs15_get_objects
///        call. Realistic AODFs stay well under this; we still warn if a
///        card hits the ceiling so silent truncation cannot mask a
///        regression on future high-cardinality cards.
constexpr std::size_t kMaxObjsLimit = 32;

/// @brief Emit a one-shot stderr warning when @c sc_pkcs15_get_objects
///        returned exactly the buffer ceiling (likely truncated). Gated
///        by @c LIBRESCRS_OPENSC_DEBUG to keep production output clean.
void warnIfBufferFull(int returned, std::size_t limit, const char* what) noexcept
{
    if (returned < 0 || static_cast<std::size_t>(returned) < limit)
        return;
    static const bool enabled = (std::getenv("LIBRESCRS_OPENSC_DEBUG") != nullptr);
    if (!enabled)
        return;
    std::fprintf(stderr,
                 "[opensc-pkcs11] WARNING: %s returned %d (== buffer ceiling %zu); "
                 "AODF may have more entries that were silently truncated\n",
                 what, returned, limit);
}

/// @brief Convert an @c sc_pkcs15_id to a @c std::vector<u8>.
[[nodiscard]] std::vector<std::uint8_t> idToVec(const sc_pkcs15_id& id)
{
    if (id.len == 0)
        return {};
    return std::vector<std::uint8_t>(id.value, id.value + id.len);
}

} // namespace

OpenScCard::OpenScCard() = default;

OpenScCard::~OpenScCard()
{
    // Slots are declared LAST in the base; they are destroyed before us.
    // Any OpenScSlot held on to a borrowed sc_pkcs15_object_t* — those
    // pointers are about to become invalid here, but the slots have
    // already released theirs by the time this dtor runs.
    releaseOpenSc();
}

void OpenScCard::releaseOpenSc() noexcept
{
    // Order matters: PKCS#15 binding holds references into the underlying
    // sc_card; the card must be disconnected before releasing the context.
    if (p15) {
        sc_pkcs15_unbind(p15);
        p15 = nullptr;
    }
    if (card) {
        sc_disconnect_card(card);
        card = nullptr;
    }
    reader = nullptr; // borrowed; owned by ctx.
    if (ctx) {
        sc_release_context(ctx);
        ctx = nullptr;
    }
}

unsigned long OpenScCard::bind(const std::string& readerNameIn)
{
    using namespace LibreSCRS::Pkcs11::Internal;

    std::scoped_lock lock(cardMutex);

    readerName = readerNameIn;
    needsPace = false; // OpenSC owns PACE internally where applicable.

    int rc = sc_establish_context(&ctx, "librescrs-opensc-pkcs11");
    if (rc < 0 || !ctx) {
        releaseOpenSc();
        return Crv::DeviceError;
    }

    reader = sc_ctx_get_reader_by_name(ctx, readerName.c_str());
    if (!reader) {
        releaseOpenSc();
        return Crv::TokenNotPresent;
    }

    rc = sc_connect_card(reader, &card);
    if (rc < 0 || !card) {
        releaseOpenSc();
        return Crv::TokenNotPresent;
    }

    rc = sc_pkcs15_bind(card, nullptr, &p15);
    if (rc < 0 || !p15) {
        // SC_ERROR_INVALID_CARD / SC_ERROR_PKCS15_APP_NOT_FOUND / etc.:
        // the card is not PKCS#15-shaped under any OpenSC driver. Let the
        // next provider try.
        releaseOpenSc();
        return Crv::TokenNotPresent;
    }

    if (auto crv = populateSlotsFromAodf(); crv != Crv::Ok) {
        releaseOpenSc();
        return crv;
    }

    return completeBind();
}

unsigned long OpenScCard::populateSlotsFromAodf()
{
    using namespace LibreSCRS::Pkcs11::Internal;

    if (!p15)
        return Crv::FunctionFailed;

    sc_pkcs15_object_t* pinObjs[kMaxObjsLimit];
    int pinCount = sc_pkcs15_get_objects(p15, SC_PKCS15_TYPE_AUTH_PIN, pinObjs, kMaxObjsLimit);
    if (pinCount < 0)
        return Crv::FunctionFailed;
    warnIfBufferFull(pinCount, kMaxObjsLimit, "sc_pkcs15_get_objects(AUTH_PIN)");

    // Fetch all PrKey + Cert objects up-front; per-PIN filtering is by
    // auth_id matching below.
    sc_pkcs15_object_t* prKeyObjs[kMaxObjsLimit];
    int prKeyRsaCount = sc_pkcs15_get_objects(p15, SC_PKCS15_TYPE_PRKEY_RSA, prKeyObjs, kMaxObjsLimit);
    warnIfBufferFull(prKeyRsaCount, kMaxObjsLimit, "sc_pkcs15_get_objects(PRKEY_RSA)");
    std::vector<sc_pkcs15_object_t*> allKeys;
    if (prKeyRsaCount > 0)
        allKeys.insert(allKeys.end(), prKeyObjs, prKeyObjs + prKeyRsaCount);

    sc_pkcs15_object_t* prKeyEcObjs[kMaxObjsLimit];
    int prKeyEcCount = sc_pkcs15_get_objects(p15, SC_PKCS15_TYPE_PRKEY_EC, prKeyEcObjs, kMaxObjsLimit);
    warnIfBufferFull(prKeyEcCount, kMaxObjsLimit, "sc_pkcs15_get_objects(PRKEY_EC)");
    if (prKeyEcCount > 0)
        allKeys.insert(allKeys.end(), prKeyEcObjs, prKeyEcObjs + prKeyEcCount);

    sc_pkcs15_object_t* certObjs[kMaxObjsLimit];
    int certCount = sc_pkcs15_get_objects(p15, SC_PKCS15_TYPE_CERT_X509, certObjs, kMaxObjsLimit);
    warnIfBufferFull(certCount, kMaxObjsLimit, "sc_pkcs15_get_objects(CERT_X509)");
    std::vector<sc_pkcs15_object_t*> allCerts;
    if (certCount > 0)
        allCerts.insert(allCerts.end(), certObjs, certObjs + certCount);

    auto* tokenInfo = p15->tokeninfo;
    const char* tiLabel = (tokenInfo && tokenInfo->label) ? tokenInfo->label : "";
    const char* tiManu = (tokenInfo && tokenInfo->manufacturer_id) ? tokenInfo->manufacturer_id : "";
    const char* tiSerial = (tokenInfo && tokenInfo->serial_number) ? tokenInfo->serial_number : "";

    bool anyPublished = false;
    for (int i = 0; i < pinCount; ++i) {
        auto* pinObj = pinObjs[i];
        if (!pinObj || !pinObj->data)
            continue;
        auto* authInfo = static_cast<sc_pkcs15_auth_info_t*>(pinObj->data);
        if (!isUserPin(authInfo))
            continue;

        const auto& pinAuthId = authInfo->auth_id;
        std::vector<std::uint8_t> pinIdBytes = idToVec(pinAuthId);

        // Filter keys whose auth_id matches this PIN. If a key has an
        // empty auth_id (older / single-PIN cards), attribute it to the
        // first user PIN we publish — mirrors the custom Pkcs15 path.
        std::vector<sc_pkcs15_object_t*> keys;
        for (auto* k : allKeys) {
            if (!k)
                continue;
            const auto& kAuthId = k->auth_id;
            const bool authMatches =
                (kAuthId.len == pinAuthId.len) &&
                (kAuthId.len == 0 || std::memcmp(kAuthId.value, pinAuthId.value, kAuthId.len) == 0);
            const bool authEmptyAndFirstSlot = (kAuthId.len == 0) && !anyPublished;
            if (authMatches || authEmptyAndFirstSlot)
                keys.push_back(k);
        }

        // Pair certs with retained keys by PKCS#15 id (CKA_ID).
        std::vector<sc_pkcs15_object_t*> certs;
        for (auto* c : allCerts) {
            if (!c || !c->data)
                continue;
            auto* certInfo = static_cast<sc_pkcs15_cert_info_t*>(c->data);
            for (auto* k : keys) {
                if (!k || !k->data)
                    continue;
                auto* keyInfo = static_cast<sc_pkcs15_prkey_info_t*>(k->data);
                if (certInfo->id.len == keyInfo->id.len &&
                    std::memcmp(certInfo->id.value, keyInfo->id.value, certInfo->id.len) == 0) {
                    certs.push_back(c);
                    break;
                }
            }
        }

        std::string pinLabel = pinObj->label[0] ? std::string(pinObj->label) : std::string("PIN");
        auto kind = deriveSlotKind(pinObj->label);
        unsigned long slotId = static_cast<unsigned long>(computeSlotId(readerName, pinIdBytes, kind));

        PKCS11TokenInfo info;
        info.label = tiLabel[0] ? std::string(tiLabel) : pinLabel;
        info.manufacturerId = tiManu;
        info.model = "OpenSC PKCS#15";
        info.serialNumber = tiSerial[0] ? std::string(tiSerial) : std::string("0000000000000000");
        info.pinLabel = pinLabel;
        info.flags = kCkfTokenInitialized | kCkfLoginRequired | kCkfUserPinInitialized;
        info.minPinLen = static_cast<unsigned long>(authInfo->attrs.pin.min_length);
        info.maxPinLen = authInfo->attrs.pin.max_length > 0
                             ? static_cast<unsigned long>(authInfo->attrs.pin.max_length)
                             : static_cast<unsigned long>(authInfo->attrs.pin.stored_length);

        slots.push_back(std::make_shared<OpenScSlot>(weak_from_this(), std::move(pinIdBytes), pinLabel, pinObj,
                                                     std::move(keys), std::move(certs), std::move(info), slotId));
        anyPublished = true;
    }

    return Crv::Ok;
}

unsigned long OpenScCard::completeBind()
{
    return LibreSCRS::Pkcs11::Internal::Crv::Ok;
}

unsigned long OpenScCard::establishPACE()
{
    // OpenSC owns PACE internally for the cards / drivers that need it
    // (e.g. the bundled srbeid driver). The CAN-in-PIN slot path is the
    // custom Pkcs15PKCS11Provider's responsibility; this provider does
    // not surface that mechanism.
    return LibreSCRS::Pkcs11::Internal::Crv::FunctionFailed;
}

unsigned long OpenScCard::reconnectInline()
{
    using namespace LibreSCRS::Pkcs11::Internal;

    // Caller (PKCS11Card::handleReset) already holds cardMutex.
    if (!ctx)
        return Crv::DeviceError;

    // Tear down the bound state, but keep the context to look the reader
    // up again (sc_disconnect_card is required before reconnect anyway).
    if (p15) {
        sc_pkcs15_unbind(p15);
        p15 = nullptr;
    }
    if (card) {
        sc_disconnect_card(card);
        card = nullptr;
    }

    // Reader handle remains valid across card removal / re-insert in the
    // OpenSC model; refresh by name to be safe in case PC/SC renumbered.
    reader = sc_ctx_get_reader_by_name(ctx, readerName.c_str());
    if (!reader)
        return Crv::TokenNotPresent;

    int rc = sc_connect_card(reader, &card);
    if (rc < 0 || !card)
        return Crv::TokenNotPresent;

    rc = sc_pkcs15_bind(card, nullptr, &p15);
    if (rc < 0 || !p15) {
        if (card) {
            sc_disconnect_card(card);
            card = nullptr;
        }
        return Crv::DeviceError;
    }

    // Slots cache borrowed sc_pkcs15_object_t* pointers from the previous
    // bind; sc_pkcs15_unbind freed them. The slot vector itself is
    // immutable (PKCS11Card invariant: populated once at bind), so we
    // refresh the borrowed pointers in place — matching by stored
    // PKCS#15 IDs — and keep the slot identities stable.
    if (!slots.empty()) {
        if (auto crv = rebindSlotObjects(); crv != Crv::Ok)
            return crv;
    }

    return Crv::Ok;
}

unsigned long OpenScCard::rebindSlotObjects()
{
    using namespace LibreSCRS::Pkcs11::Internal;

    if (!p15)
        return Crv::FunctionFailed;

    // Fetch all PIN / PrKey / Cert objects from the freshly bound
    // PKCS#15 card, then resolve each slot's borrowed pointers by ID.
    sc_pkcs15_object_t* pinObjs[kMaxObjsLimit];
    int pinCount = sc_pkcs15_get_objects(p15, SC_PKCS15_TYPE_AUTH_PIN, pinObjs, kMaxObjsLimit);
    if (pinCount < 0)
        return Crv::FunctionFailed;
    warnIfBufferFull(pinCount, kMaxObjsLimit, "sc_pkcs15_get_objects(AUTH_PIN) [rebind]");

    sc_pkcs15_object_t* prKeyRsaObjs[kMaxObjsLimit];
    int prKeyRsaCount = sc_pkcs15_get_objects(p15, SC_PKCS15_TYPE_PRKEY_RSA, prKeyRsaObjs, kMaxObjsLimit);
    warnIfBufferFull(prKeyRsaCount, kMaxObjsLimit, "sc_pkcs15_get_objects(PRKEY_RSA) [rebind]");
    std::vector<sc_pkcs15_object_t*> allKeys;
    if (prKeyRsaCount > 0)
        allKeys.insert(allKeys.end(), prKeyRsaObjs, prKeyRsaObjs + prKeyRsaCount);

    sc_pkcs15_object_t* prKeyEcObjs[kMaxObjsLimit];
    int prKeyEcCount = sc_pkcs15_get_objects(p15, SC_PKCS15_TYPE_PRKEY_EC, prKeyEcObjs, kMaxObjsLimit);
    warnIfBufferFull(prKeyEcCount, kMaxObjsLimit, "sc_pkcs15_get_objects(PRKEY_EC) [rebind]");
    if (prKeyEcCount > 0)
        allKeys.insert(allKeys.end(), prKeyEcObjs, prKeyEcObjs + prKeyEcCount);

    sc_pkcs15_object_t* certObjs[kMaxObjsLimit];
    int certCount = sc_pkcs15_get_objects(p15, SC_PKCS15_TYPE_CERT_X509, certObjs, kMaxObjsLimit);
    warnIfBufferFull(certCount, kMaxObjsLimit, "sc_pkcs15_get_objects(CERT_X509) [rebind]");
    std::vector<sc_pkcs15_object_t*> allCerts;
    if (certCount > 0)
        allCerts.insert(allCerts.end(), certObjs, certObjs + certCount);

    auto matchById = [](const sc_pkcs15_id& id, std::span<const std::uint8_t> wanted) noexcept {
        return id.len == wanted.size() && (id.len == 0 || std::memcmp(id.value, wanted.data(), id.len) == 0);
    };

    for (auto& slotBase : slots) {
        auto* slot = dynamic_cast<OpenScSlot*>(slotBase.get());
        if (!slot)
            continue; // defensive: vector populated only from OpenScSlot.

        // Resolve fresh AUTH PIN by stored pinId (auth_id).
        sc_pkcs15_object_t* freshPin = nullptr;
        const auto& wantedPinId = slot->pinIdBytes();
        for (int i = 0; i < pinCount; ++i) {
            auto* p = pinObjs[i];
            if (!p || !p->data)
                continue;
            auto* auth = static_cast<sc_pkcs15_auth_info_t*>(p->data);
            if (matchById(auth->auth_id, wantedPinId)) {
                freshPin = p;
                break;
            }
        }
        if (!freshPin)
            return Crv::DeviceError; // AODF shape changed across reconnect.

        // Resolve fresh PrKey pointers by stored CKA_ID.
        std::vector<sc_pkcs15_object_t*> freshKeys;
        freshKeys.reserve(slot->keyIds().size());
        for (const auto& wantedKeyId : slot->keyIds()) {
            sc_pkcs15_object_t* found = nullptr;
            for (auto* k : allKeys) {
                if (!k || !k->data)
                    continue;
                auto* keyInfo = static_cast<sc_pkcs15_prkey_info_t*>(k->data);
                if (matchById(keyInfo->id, wantedKeyId)) {
                    found = k;
                    break;
                }
            }
            if (!found)
                return Crv::DeviceError;
            freshKeys.push_back(found);
        }

        // Resolve fresh Cert pointers by stored CKA_ID.
        std::vector<sc_pkcs15_object_t*> freshCerts;
        freshCerts.reserve(slot->certIds().size());
        for (const auto& wantedCertId : slot->certIds()) {
            sc_pkcs15_object_t* found = nullptr;
            for (auto* c : allCerts) {
                if (!c || !c->data)
                    continue;
                auto* certInfo = static_cast<sc_pkcs15_cert_info_t*>(c->data);
                if (matchById(certInfo->id, wantedCertId)) {
                    found = c;
                    break;
                }
            }
            if (!found)
                return Crv::DeviceError;
            freshCerts.push_back(found);
        }

        slot->rebindObjects(freshPin, std::move(freshKeys), std::move(freshCerts));
    }

    return Crv::Ok;
}

} // namespace LibreSCRS::OpenSc::Pkcs11
