// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

/// @file
/// @brief @ref LibreSCRS::OpenSc::Pkcs11::OpenScSlot implementation —
///        per-PIN view of an OpenSC-bound card.

#include "opensc_slot.h"

#include "opensc_card.h"

#include <internal/Crv.h>
#include <internal/PKCS11Card.h>

#include <libopensc/errors.h>
#include <libopensc/opensc.h>
#include <libopensc/pkcs15.h>

#include <openssl/crypto.h>

#include <algorithm>
#include <cstring>
#include <mutex>
#include <utility>

namespace LibreSCRS::OpenSc::Pkcs11 {

namespace {

/// @brief PKCS#11 v2.40 raw mechanism numeric values.
constexpr unsigned long kCkmRsaPkcs = 0x00000001UL;
constexpr unsigned long kCkmRsaPkcsSha256 = 0x00000040UL;
constexpr unsigned long kCkmRsaPkcsSha384 = 0x00000041UL;
constexpr unsigned long kCkmRsaPkcsSha512 = 0x00000042UL;
constexpr unsigned long kCkmRsaPssSha256 = 0x00000043UL;
constexpr unsigned long kCkmRsaPssSha384 = 0x00000044UL;
constexpr unsigned long kCkmRsaPssSha512 = 0x00000045UL;
constexpr unsigned long kCkmEcdsa = 0x00001041UL;
constexpr unsigned long kCkmEcdsaSha256 = 0x00001044UL;
constexpr unsigned long kCkmEcdsaSha384 = 0x00001045UL;
constexpr unsigned long kCkmEcdsaSha512 = 0x00001046UL;

/// @brief PKCS#11 object class constants (CKO_*).
constexpr unsigned long kCkoCertificate = 1UL;
constexpr unsigned long kCkoPrivateKey = 3UL;

/// @brief PKCS#11 key type constants (CKK_*).
constexpr unsigned long kCkkRsa = 0UL;
constexpr unsigned long kCkkEc = 3UL;

/// @brief Translate a PKCS#11 mechanism + on-card key type into the
///        @c sc_pkcs15_compute_signature flags expected by libopensc.
/// @return @c std::optional empty when the mechanism is not supported.
[[nodiscard]] std::optional<unsigned long> mechanismToScFlags(unsigned long mechanism, bool isEc) noexcept
{
    if (isEc) {
        switch (mechanism) {
        case kCkmEcdsa:
            return SC_ALGORITHM_ECDSA_RAW | SC_ALGORITHM_ECDSA_HASH_NONE;
        case kCkmEcdsaSha256:
            return SC_ALGORITHM_ECDSA_RAW | SC_ALGORITHM_ECDSA_HASH_SHA256;
        case kCkmEcdsaSha384:
            return SC_ALGORITHM_ECDSA_RAW | SC_ALGORITHM_ECDSA_HASH_SHA384;
        case kCkmEcdsaSha512:
            return SC_ALGORITHM_ECDSA_RAW | SC_ALGORITHM_ECDSA_HASH_SHA512;
        default:
            return std::nullopt;
        }
    }
    switch (mechanism) {
    case kCkmRsaPkcs:
        return SC_ALGORITHM_RSA_PAD_PKCS1 | SC_ALGORITHM_RSA_HASH_NONE;
    case kCkmRsaPkcsSha256:
        return SC_ALGORITHM_RSA_PAD_PKCS1 | SC_ALGORITHM_RSA_HASH_SHA256;
    case kCkmRsaPkcsSha384:
        return SC_ALGORITHM_RSA_PAD_PKCS1 | SC_ALGORITHM_RSA_HASH_SHA384;
    case kCkmRsaPkcsSha512:
        return SC_ALGORITHM_RSA_PAD_PKCS1 | SC_ALGORITHM_RSA_HASH_SHA512;
    case kCkmRsaPssSha256:
        return SC_ALGORITHM_RSA_PAD_PSS | SC_ALGORITHM_RSA_HASH_SHA256;
    case kCkmRsaPssSha384:
        return SC_ALGORITHM_RSA_PAD_PSS | SC_ALGORITHM_RSA_HASH_SHA384;
    case kCkmRsaPssSha512:
        return SC_ALGORITHM_RSA_PAD_PSS | SC_ALGORITHM_RSA_HASH_SHA512;
    default:
        return std::nullopt;
    }
}

/// @brief libresign-style DER OCTET STRING wrap for CKA_EC_POINT. Mirrors
///        the helper in the custom Pkcs15 slot so consumers handle
///        ec_point identically across providers.
[[nodiscard]] std::vector<std::uint8_t> derOctetStringWrap(std::span<const std::uint8_t> raw)
{
    std::vector<std::uint8_t> out;
    out.reserve(raw.size() + 4);
    out.push_back(0x04); // OCTET STRING tag.
    if (raw.size() < 0x80) {
        out.push_back(static_cast<std::uint8_t>(raw.size()));
    } else if (raw.size() <= 0xFF) {
        out.push_back(0x81);
        out.push_back(static_cast<std::uint8_t>(raw.size()));
    } else {
        out.push_back(0x82);
        out.push_back(static_cast<std::uint8_t>((raw.size() >> 8) & 0xFF));
        out.push_back(static_cast<std::uint8_t>(raw.size() & 0xFF));
    }
    out.insert(out.end(), raw.begin(), raw.end());
    return out;
}

[[nodiscard]] bool isEcKey(const sc_pkcs15_object_t* keyObj) noexcept
{
    return keyObj && (keyObj->type == SC_PKCS15_TYPE_PRKEY_EC);
}

[[nodiscard]] bool keyMatchesId(const sc_pkcs15_object_t* keyObj, std::span<const std::uint8_t> keyId) noexcept
{
    if (!keyObj || !keyObj->data)
        return false;
    auto* info = static_cast<const sc_pkcs15_prkey_info_t*>(keyObj->data);
    if (info->id.len != keyId.size())
        return false;
    if (info->id.len == 0)
        return keyId.empty();
    return std::memcmp(info->id.value, keyId.data(), info->id.len) == 0;
}

} // namespace

OpenScSlot::OpenScSlot(std::weak_ptr<LibreSCRS::Pkcs11::Internal::PKCS11Card> parent, std::vector<std::uint8_t> pinId,
                       std::string pinLabel, sc_pkcs15_object_t* pinObject, std::vector<sc_pkcs15_object_t*> keyObjects,
                       std::vector<sc_pkcs15_object_t*> certObjects,
                       LibreSCRS::Pkcs11::Internal::PKCS11TokenInfo tokenInfo, unsigned long slotId)
    : LibreSCRS::Pkcs11::Internal::PKCS11Slot(std::move(parent), std::move(pinId), std::move(pinLabel)),
      pinObject(pinObject), keyObjects(std::move(keyObjects)), certObjects(std::move(certObjects))
{
    cachedTokenInfo = std::move(tokenInfo);
    stableSlotId = slotId;

    // Capture PKCS#15 IDs for rebindObjects() (reconnect path). The
    // pointers held above are borrowed from the parent's bound
    // sc_pkcs15_card_t; after sc_pkcs15_unbind() they go stale, but the
    // ID identity persists on the rebound card.
    keyIdsCache.reserve(this->keyObjects.size());
    for (auto* k : this->keyObjects) {
        if (!k || !k->data) {
            keyIdsCache.emplace_back();
            continue;
        }
        auto* keyInfo = static_cast<sc_pkcs15_prkey_info_t*>(k->data);
        keyIdsCache.emplace_back(keyInfo->id.value, keyInfo->id.value + keyInfo->id.len);
    }
    certIdsCache.reserve(this->certObjects.size());
    for (auto* c : this->certObjects) {
        if (!c || !c->data) {
            certIdsCache.emplace_back();
            continue;
        }
        auto* certInfo = static_cast<sc_pkcs15_cert_info_t*>(c->data);
        certIdsCache.emplace_back(certInfo->id.value, certInfo->id.value + certInfo->id.len);
    }
}

OpenScSlot::~OpenScSlot() = default;

void OpenScSlot::rebindObjects(sc_pkcs15_object_t* freshPinObject, std::vector<sc_pkcs15_object_t*> freshKeyObjects,
                               std::vector<sc_pkcs15_object_t*> freshCertObjects) noexcept
{
    // No slotMutex acquisition here: per the documented contract of
    // PKCS11Card::handleReset, the caller holds cardMutex and no
    // concurrent slot operation may be in flight (lock order:
    // slotMutex → cardMutex; reconnect is the moment we exclude all
    // slot work).
    pinObject = freshPinObject;
    keyObjects = std::move(freshKeyObjects);
    certObjects = std::move(freshCertObjects);
}

std::vector<unsigned long> OpenScSlot::mechanisms() const
{
    std::scoped_lock lock(slotMutex);
    bool hasRsa = false;
    bool hasEc = false;
    for (auto* k : keyObjects) {
        if (isEcKey(k))
            hasEc = true;
        else if (k && k->type == SC_PKCS15_TYPE_PRKEY_RSA)
            hasRsa = true;
    }

    std::vector<unsigned long> out;
    if (hasRsa) {
        out.push_back(kCkmRsaPkcs);
        out.push_back(kCkmRsaPkcsSha256);
        out.push_back(kCkmRsaPkcsSha384);
        out.push_back(kCkmRsaPkcsSha512);
        out.push_back(kCkmRsaPssSha256);
        out.push_back(kCkmRsaPssSha384);
        out.push_back(kCkmRsaPssSha512);
    }
    if (hasEc) {
        out.push_back(kCkmEcdsa);
        out.push_back(kCkmEcdsaSha256);
        out.push_back(kCkmEcdsaSha384);
        out.push_back(kCkmEcdsaSha512);
    }
    return out;
}

std::vector<LibreSCRS::Pkcs11::Internal::PKCS11ObjectInfo> OpenScSlot::enumerateObjects()
{
    using namespace LibreSCRS::Pkcs11::Internal;

    std::vector<PKCS11ObjectInfo> objects;

    auto parentBase = parentCard.lock();
    if (!parentBase)
        return objects;
    auto* parent = static_cast<OpenScCard*>(parentBase.get());

    std::scoped_lock slotLock(slotMutex);
    std::scoped_lock cardLock(parentTransportMutex(*parent));

    auto* p15 = parent->p15Card();
    if (!p15)
        return objects;

    for (auto* certObj : certObjects) {
        if (!certObj || !certObj->data)
            continue;
        auto* certInfo = static_cast<sc_pkcs15_cert_info_t*>(certObj->data);

        // Locate the paired key (in this slot's filtered set) by id.
        sc_pkcs15_object_t* matchedKey = nullptr;
        for (auto* k : keyObjects) {
            if (!k || !k->data)
                continue;
            auto* kInfo = static_cast<const sc_pkcs15_prkey_info_t*>(k->data);
            if (kInfo->id.len == certInfo->id.len && kInfo->id.len > 0 &&
                std::memcmp(kInfo->id.value, certInfo->id.value, kInfo->id.len) == 0) {
                matchedKey = k;
                break;
            }
        }

        sc_pkcs15_cert_t* cert = nullptr;
        int rc = sc_pkcs15_read_certificate(p15, certInfo, /*private_obj=*/0, &cert);
        if (rc < 0 || !cert)
            continue;

        std::vector<std::uint8_t> ckaId(certInfo->id.value, certInfo->id.value + certInfo->id.len);
        std::vector<std::uint8_t> derBytes(cert->data.value, cert->data.value + cert->data.len);

        PKCS11ObjectInfo certPkcs;
        certPkcs.objectClass = kCkoCertificate;
        certPkcs.label = certObj->label;
        certPkcs.id = ckaId;
        certPkcs.value = derBytes;
        if (cert->subject_len > 0)
            certPkcs.subject.assign(cert->subject, cert->subject + cert->subject_len);
        certPkcs.token = true;
        certPkcs.privateObj = false;
        objects.push_back(std::move(certPkcs));

        if (matchedKey && matchedKey->data) {
            auto* kInfo = static_cast<const sc_pkcs15_prkey_info_t*>(matchedKey->data);
            const bool ec = isEcKey(matchedKey);

            PKCS11ObjectInfo keyPkcs;
            keyPkcs.objectClass = kCkoPrivateKey;
            keyPkcs.label = certObj->label;
            keyPkcs.id = ckaId;
            keyPkcs.keyType = ec ? kCkkEc : kCkkRsa;
            keyPkcs.token = true;
            keyPkcs.privateObj = true;
            keyPkcs.sensitive = true;
            keyPkcs.extractable = false;
            keyPkcs.keyReference = static_cast<std::uint8_t>(kInfo->key_reference & 0xFF);

            // Populate modulus / exponent or ec_params / ec_point from the
            // certificate's parsed pubkey when available.
            if (cert->key) {
                if (!ec && cert->key->algorithm == SC_ALGORITHM_RSA) {
                    const auto& mod = cert->key->u.rsa.modulus;
                    const auto& exp = cert->key->u.rsa.exponent;
                    if (mod.data && mod.len > 0)
                        keyPkcs.modulus.assign(mod.data, mod.data + mod.len);
                    if (exp.data && exp.len > 0)
                        keyPkcs.publicExponent.assign(exp.data, exp.data + exp.len);
                } else if (ec && cert->key->algorithm == SC_ALGORITHM_EC) {
                    const auto& params = cert->key->u.ec.params;
                    const auto& point = cert->key->u.ec.ecpointQ;
                    if (params.der.value && params.der.len > 0)
                        keyPkcs.ecParams.assign(params.der.value, params.der.value + params.der.len);
                    if (point.value && point.len > 0)
                        keyPkcs.ecPoint = derOctetStringWrap(std::span<const std::uint8_t>{point.value, point.len});
                }
            }

            objects.push_back(std::move(keyPkcs));
        }

        sc_pkcs15_free_certificate(cert);
    }

    return objects;
}

unsigned long OpenScSlot::login(unsigned long userType, std::span<const std::uint8_t> pin)
{
    using namespace LibreSCRS::Pkcs11::Internal;

    if (userType != 1UL) // CKU_USER
        return Crv::ArgumentsBad;
    if (!pinObject)
        return Crv::FunctionFailed;

    auto parentBase = parentCard.lock();
    if (!parentBase)
        return Crv::DeviceError;
    auto* parent = static_cast<OpenScCard*>(parentBase.get());

    std::scoped_lock slotLock(slotMutex);
    std::scoped_lock cardLock(parentTransportMutex(*parent));

    auto* p15 = parent->p15Card();
    if (!p15)
        return Crv::DeviceError;

    int rc = sc_pkcs15_verify_pin(p15, pinObject, pin.data(), pin.size());

    if (rc == SC_SUCCESS) {
        // Cache the PIN in a cleansing buffer for downstream sign paths
        // (mirroring the Pkcs15 provider's contract; OpenSC drivers may
        // re-prompt for verification on subsequent operations).
        cachedPin = LibreSCRS::Secure::String{std::string_view{reinterpret_cast<const char*>(pin.data()), pin.size()}};
        loggedIn = true;
        return Crv::Ok;
    }

    if (rc == SC_ERROR_PIN_CODE_INCORRECT)
        return Crv::PinIncorrect;
    if (rc == SC_ERROR_AUTH_METHOD_BLOCKED)
        return Crv::PinLocked;
    if (rc == SC_ERROR_INVALID_PIN_LENGTH)
        return Crv::PinLenRange;
    return Crv::DeviceError;
}

unsigned long OpenScSlot::logout()
{
    std::scoped_lock lock(slotMutex);
    cachedPin.clear();
    loggedIn = false;
    return LibreSCRS::Pkcs11::Internal::Crv::Ok;
}

std::vector<std::uint8_t> OpenScSlot::signData(std::span<const std::uint8_t> data, unsigned long mechanism,
                                               std::span<const std::uint8_t> keyId)
{
    using namespace LibreSCRS::Pkcs11::Internal;

    auto parentBase = parentCard.lock();
    if (!parentBase)
        return {};
    auto* parent = static_cast<OpenScCard*>(parentBase.get());

    std::scoped_lock slotLock(slotMutex);
    std::scoped_lock cardLock(parentTransportMutex(*parent));

    if (!loggedIn)
        return {};

    auto* p15 = parent->p15Card();
    if (!p15)
        return {};

    sc_pkcs15_object_t* targetKey = nullptr;
    for (auto* k : keyObjects) {
        if (keyMatchesId(k, keyId)) {
            targetKey = k;
            break;
        }
    }
    if (!targetKey || !targetKey->data)
        return {};

    auto flags = mechanismToScFlags(mechanism, isEcKey(targetKey));
    if (!flags)
        return {};

    auto* keyInfo = static_cast<const sc_pkcs15_prkey_info_t*>(targetKey->data);
    std::size_t outSize = 0;
    if (isEcKey(targetKey)) {
        const std::size_t fieldBytes = (keyInfo->field_length + 7u) / 8u;
        // ECDSA: r||s plus DER-wrap headroom.
        outSize = 2u * fieldBytes + 8u;
        if (outSize == 0)
            outSize = 256u;
    } else {
        outSize = (keyInfo->modulus_length + 7u) / 8u;
        if (outSize == 0)
            outSize = 512u;
    }

    std::vector<std::uint8_t> out(outSize);
    int rc = sc_pkcs15_compute_signature(p15, targetKey, *flags, data.data(), data.size(), out.data(), out.size(),
                                         /*pMechanism=*/nullptr);
    if (rc < 0)
        return {};
    out.resize(static_cast<std::size_t>(rc));
    return out;
}

std::vector<std::uint8_t> OpenScSlot::signWithDigestInfo(std::span<const std::uint8_t> digestInfo,
                                                         std::span<const std::uint8_t> rawData, unsigned long mechanism,
                                                         std::span<const std::uint8_t> keyId)
{
    // CardEdge / srbeid applets do NOT hash on-card. The path that works
    // reliably is: caller hashes + prepends DigestInfo (the library does
    // this in pkcs11_library.cpp::sign before calling us), then we pass
    // the pre-built DigestInfo to libopensc with SC_ALGORITHM_RSA_HASH_NONE.
    // Empirically, asking libopensc to hash on-host via SC_ALGORITHM_RSA_
    // HASH_SHA256 fails on srbeid (sc_pkcs15_compute_signature → CKR_DEVICE_ERROR)
    // because the algorithm-table match for combined-hash variants does
    // not surface on the cardEdge driver.
    //
    // PSS variants are different: libopensc handles PSS padding from the
    // raw hash; we keep the rawData + mechanism path for those.
    constexpr unsigned long kCkmSha1RsaPkcs = 0x0006UL;
    constexpr unsigned long kCkmSha256RsaPkcs = 0x0040UL;
    constexpr unsigned long kCkmSha384RsaPkcs = 0x0041UL;
    constexpr unsigned long kCkmSha512RsaPkcs = 0x0042UL;
    constexpr unsigned long kCkmRsaPkcs = 0x0001UL;

    const bool isCombinedHashRsaPkcs1 = (mechanism == kCkmSha1RsaPkcs || mechanism == kCkmSha256RsaPkcs ||
                                         mechanism == kCkmSha384RsaPkcs || mechanism == kCkmSha512RsaPkcs);
    if (isCombinedHashRsaPkcs1 && !digestInfo.empty()) {
        // Reroute to raw RSA-PKCS path: library has already prepended
        // DigestInfo; HASH_NONE flag matches the srbeid card surface.
        return signData(digestInfo, kCkmRsaPkcs, keyId);
    }
    // PSS combined-hash + everything else: pass rawData with the original
    // mechanism (libopensc PSS dispatch handles the hash internally).
    if (!digestInfo.empty())
        return signData(digestInfo, mechanism, keyId);
    return signData(rawData, mechanism, keyId);
}

std::size_t OpenScSlot::signatureSize(std::span<const std::uint8_t> keyId) const
{
    // Lock-free; keys vector immutable post-construction.
    for (auto* k : keyObjects) {
        if (!keyMatchesId(k, keyId))
            continue;
        auto* keyInfo = static_cast<const sc_pkcs15_prkey_info_t*>(k->data);
        if (isEcKey(k)) {
            const std::size_t fieldBytes = (keyInfo->field_length + 7u) / 8u;
            if (fieldBytes == 0)
                return 0;
            return 2u * fieldBytes + 8u;
        }
        const std::size_t modBytes = (keyInfo->modulus_length + 7u) / 8u;
        return modBytes;
    }
    return 0;
}

} // namespace LibreSCRS::OpenSc::Pkcs11
