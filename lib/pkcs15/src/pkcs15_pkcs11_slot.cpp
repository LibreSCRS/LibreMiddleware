// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

/// @file
/// @brief Concrete @ref LibreSCRS::Pkcs15::Pkcs11::Pkcs15Slot
///        implementation. Provides per-slot semantics (login + sign +
///        enumerateObjects) reduced to a single PIN's view of the card.
///
/// Each public method follows the same shape: lock slotMutex + cardMutex,
/// acquire a per-operation @c ActiveChannelHolder through the parent
/// @c Pkcs15Card, build a local @c pkcs15::PKCS15Card from
/// @c LibreSCRS::SmartCard::Internal::HolderChannelAccessor::channel(holder), perform one APDU exchange, and release.
/// The holder also drives applet SELECT and — on PACE-gated cards — keeps the SM channel warm in the session's
/// per-process cache so successive holders fast-path through the same-applet path without re-handshaking.

#include "pkcs15_pkcs11_slot.h"

#include "pkcs15_card.h"
#include "pkcs15_pkcs11_card.h"
#include "pkcs15_parser.h"
#include "pkcs15_types.h"

#include "probe_trace.h"

#include <cstdio>
#include <cstdlib>

#include <internal/Crv.h>
#include <internal/DerWrap.h>
#include <internal/MechanismConstants.h>
#include <internal/PKCS11Card.h>
#include <internal/PinClassification.h>

#include <LibreSCRS_internal/SecureChannel/ISecureChannel.h>
#include <LibreSCRS/SmartCard/ActiveChannelHolder.h>
#include <LibreSCRS_internal/SmartCard/ActiveChannelHolderInternal.h>
#include <smartcard/pcsc_connection.h>

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

#include <iomanip>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <utility>

namespace LibreSCRS::Pkcs15::Pkcs11 {

using LibreSCRS::Pkcs15::Internal::isUserPin;

namespace {

/// @brief Translate a PKCS#11 mechanism to the @ref pkcs15::SignScheme
///        consumed by @ref pkcs15::PKCS15Card::sign.
///
/// RSA/EC mismatch is signalled via thrown @c std::runtime_error so the
/// surrounding library layer can translate it to @c CKR_MECHANISM_INVALID.
[[nodiscard]] ::pkcs15::SignScheme mechanismToScheme(unsigned long mechanism, ::pkcs15::KeyType keyType)
{
    bool isEcMechanism = (mechanism >= 0x1040 && mechanism <= 0x1049);
    if (keyType == ::pkcs15::KeyType::Ec && !isEcMechanism)
        throw std::runtime_error("Pkcs15Slot: RSA mechanism used with EC key");
    if (keyType == ::pkcs15::KeyType::Rsa && isEcMechanism)
        throw std::runtime_error("Pkcs15Slot: EC mechanism used with RSA key");

    switch (mechanism) {
    case 0x0001:
        return ::pkcs15::SignScheme::RsaPkcs1;
    case 0x0006:
        return ::pkcs15::SignScheme::RsaSha1Pkcs1;
    case 0x0040:
        return ::pkcs15::SignScheme::RsaSha256Pkcs1;
    case 0x0041:
        return ::pkcs15::SignScheme::RsaSha384Pkcs1;
    case 0x0042:
        return ::pkcs15::SignScheme::RsaSha512Pkcs1;
    case 0x0043:
        return ::pkcs15::SignScheme::RsaPssSha256;
    case 0x0044:
        return ::pkcs15::SignScheme::RsaPssSha384;
    case 0x0045:
        return ::pkcs15::SignScheme::RsaPssSha512;
    case 0x1041:
        return ::pkcs15::SignScheme::EcdsaRaw;
    default: {
        std::ostringstream oss;
        oss << "Pkcs15Slot: unsupported mechanism 0x" << std::hex << std::setfill('0') << std::setw(4) << mechanism;
        throw std::runtime_error(oss.str());
    }
    }
}

using LibreSCRS::Pkcs11::Internal::kCkkEc;
using LibreSCRS::Pkcs11::Internal::kCkkRsa;
using LibreSCRS::Pkcs11::Internal::kCkmEcdsa;
using LibreSCRS::Pkcs11::Internal::kCkmRsaPkcs;
using LibreSCRS::Pkcs11::Internal::kCkmRsaPkcsSha256;
using LibreSCRS::Pkcs11::Internal::kCkmRsaPkcsSha384;
using LibreSCRS::Pkcs11::Internal::kCkmRsaPkcsSha512;
using LibreSCRS::Pkcs11::Internal::kCkmRsaPssSha256;
using LibreSCRS::Pkcs11::Internal::kCkmRsaPssSha384;
using LibreSCRS::Pkcs11::Internal::kCkmRsaPssSha512;
using LibreSCRS::Pkcs11::Internal::kCkoCertificate;
using LibreSCRS::Pkcs11::Internal::kCkoPrivateKey;

} // namespace

Pkcs15Slot::Pkcs15Slot(std::weak_ptr<LibreSCRS::Pkcs11::Internal::PKCS11Card> parent, std::vector<std::uint8_t> pinId,
                       std::string pinLabel, ::pkcs15::PinInfo pinInfo, std::vector<::pkcs15::PrivateKeyInfo> keys,
                       std::vector<::pkcs15::CertificateInfo> certs,
                       LibreSCRS::Pkcs11::Internal::PKCS11TokenInfo tokenInfo, unsigned long slotId)
    : LibreSCRS::Pkcs11::Internal::PKCS11Slot(std::move(parent), std::move(pinId), std::move(pinLabel)),
      pinInfo(std::move(pinInfo)), keys(std::move(keys)), certs(std::move(certs))
{
    // Populate base-class protected state directly. We are the subclass
    // so this is the regular protected-member access path; the parent
    // card's bind() path holds cardMutex while constructing us, and no
    // other thread can observe the slot until bind() publishes through
    // PKCS11Card::slots — so no slotMutex acquisition is required here.
    cachedTokenInfo = std::move(tokenInfo);
    stableSlotId = slotId;
}

Pkcs15Slot::Pkcs15Slot(std::weak_ptr<LibreSCRS::Pkcs11::Internal::PKCS11Card> parent, std::string placeholderLabel,
                       LibreSCRS::Pkcs11::Internal::PKCS11TokenInfo placeholderTokenInfo, unsigned long slotId)
    : LibreSCRS::Pkcs11::Internal::PKCS11Slot(std::move(parent), std::vector<std::uint8_t>{},
                                              std::move(placeholderLabel)),
      deferredProfile(true)
{
    // Deferred-profile mode for applets that refuse PKCS#15 directory
    // reads pre-login. pinInfo / keys / certs are populated lazily inside
    // login() after PIN verification succeeds.
    cachedTokenInfo = std::move(placeholderTokenInfo);
    stableSlotId = slotId;
}

Pkcs15Slot::~Pkcs15Slot() = default;

const ::pkcs15::PKCS15Profile* Pkcs15Slot::parentProfile(LibreSCRS::Pkcs11::Internal::PKCS11Card& parentBase) noexcept
{
    auto* parent = static_cast<Pkcs15Card*>(&parentBase);
    return parent->profile.get();
}

std::vector<unsigned long> Pkcs15Slot::mechanisms() const
{
    // Mirrors the implicit set advertised by Pkcs15PKCS11Provider via its
    // mechanismToScheme switch (pkcs15_pkcs11_provider.cpp:29-64). We
    // return the union of mechanisms valid for the slot's keys; if the
    // slot has only RSA keys we drop ECDSA, and vice versa.
    std::scoped_lock lock(slotMutex);
    bool hasRsa = false;
    bool hasEc = false;
    for (const auto& k : keys) {
        if (k.keyType == ::pkcs15::KeyType::Ec)
            hasEc = true;
        else
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
    if (hasEc)
        out.push_back(kCkmEcdsa);
    return out;
}

std::vector<LibreSCRS::Pkcs11::Internal::PKCS11ObjectInfo> Pkcs15Slot::enumerateObjects()
{
    using namespace LibreSCRS::Pkcs11::Internal;
    std::vector<PKCS11ObjectInfo> objects;

    auto parent = parentCard.lock();
    if (!parent)
        return objects;
    auto& parentP15 = static_cast<Pkcs15Card&>(*parent);

    std::scoped_lock locks(slotMutex, parentTransportMutex(*parent));

    if (deferredProfile)
        return objects; // Pre-login deferred-profile slot: nothing enumerated yet.

    auto holderResult = parentP15.acquireChannel();
    if (!holderResult)
        return objects;
    auto holder = std::move(*holderResult);
    auto* channel = LibreSCRS::SmartCard::Internal::HolderChannelAccessor::channel(holder);
    if (channel == nullptr)
        return objects;
    ::pkcs15::PKCS15Card apdu(*channel);

    try {
        for (const auto& certInfo : certs) {
            std::vector<std::uint8_t> derBytes;
            try {
                derBytes = apdu.readCertificate(certInfo);
            } catch (...) {
                continue; // Skip unreadable certs, continue with the rest.
            }

            // Find paired private key by PKCS#15 id.
            const ::pkcs15::PrivateKeyInfo* matchedKey = nullptr;
            for (const auto& k : keys) {
                if (k.id == certInfo.id) {
                    matchedKey = &k;
                    break;
                }
            }
            bool hasKey = (matchedKey != nullptr);

            // Stable CKA_ID: use the PKCS#15 id directly (no per-slot
            // counter; multi-slot world means callers must not assume
            // 0x01-monotonic IDs across slots).
            std::vector<std::uint8_t> ckaId = certInfo.id;

            // Parse the certificate's SubjectPublicKeyInfo so paired
            // private-key entries can carry CKA_MODULUS / CKA_PUBLIC_EXPONENT
            // (RSA) or CKA_EC_PARAMS / CKA_EC_POINT (ECC). Mirrors the
            // legacy library's post-loop populate in pkcs11_library.cpp
            // so the new slot surface stays informationally equivalent.
            std::vector<std::uint8_t> rsaModulus;
            std::vector<std::uint8_t> rsaExponent;
            std::vector<std::uint8_t> ecParamsDer;
            std::vector<std::uint8_t> ecPointDer;
            if (hasKey && !derBytes.empty()) {
                const unsigned char* dp = derBytes.data();
                X509* x509 = d2i_X509(nullptr, &dp, static_cast<long>(derBytes.size()));
                if (x509) {
                    EVP_PKEY* pkey = X509_get_pubkey(x509);
                    if (pkey) {
                        const int baseId = EVP_PKEY_base_id(pkey);
                        if (baseId == EVP_PKEY_RSA) {
                            BIGNUM* n = nullptr;
                            if (EVP_PKEY_get_bn_param(pkey, "n", &n) == 1 && n) {
                                rsaModulus.resize(static_cast<std::size_t>(BN_num_bytes(n)));
                                BN_bn2bin(n, rsaModulus.data());
                                BN_free(n);
                            }
                            BIGNUM* e = nullptr;
                            if (EVP_PKEY_get_bn_param(pkey, "e", &e) == 1 && e) {
                                rsaExponent.resize(static_cast<std::size_t>(BN_num_bytes(e)));
                                BN_bn2bin(e, rsaExponent.data());
                                BN_free(e);
                            }
                        } else if (baseId == EVP_PKEY_EC) {
                            unsigned char* paramsDer = nullptr;
                            const int pLen = i2d_KeyParams(pkey, &paramsDer);
                            if (pLen > 0 && paramsDer) {
                                ecParamsDer.assign(paramsDer, paramsDer + pLen);
                                OPENSSL_free(paramsDer);
                            }
                            std::size_t pointLen = 0;
                            if (EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, nullptr, 0,
                                                                &pointLen) == 1 &&
                                pointLen > 0) {
                                std::vector<std::uint8_t> rawPoint(pointLen);
                                EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY,
                                                                rawPoint.data(), pointLen, &pointLen);
                                ecPointDer = LibreSCRS::Pkcs11::Internal::derOctetStringWrap(rawPoint);
                            }
                        }
                        EVP_PKEY_free(pkey);
                    }
                    X509_free(x509);
                }
            }

            PKCS11ObjectInfo certObj;
            certObj.objectClass = kCkoCertificate;
            certObj.label = certInfo.label;
            certObj.id = ckaId;
            certObj.value = derBytes;
            certObj.token = true;
            certObj.privateObj = false;
            objects.push_back(std::move(certObj));

            if (hasKey) {
                PKCS11ObjectInfo keyObj;
                keyObj.objectClass = kCkoPrivateKey;
                keyObj.label = certInfo.label;
                keyObj.id = ckaId;
                keyObj.keyType = (matchedKey->keyType == ::pkcs15::KeyType::Ec) ? kCkkEc : kCkkRsa;
                keyObj.token = true;
                keyObj.privateObj = true;
                keyObj.sensitive = true;
                keyObj.extractable = false;
                keyObj.modulus = std::move(rsaModulus);
                keyObj.publicExponent = std::move(rsaExponent);
                keyObj.ecParams = std::move(ecParamsDer);
                keyObj.ecPoint = std::move(ecPointDer);
                keyObj.keyReference = matchedKey->keyReference;
                objects.push_back(std::move(keyObj));
            }
        }
    } catch (...) {
        // Defensive: never propagate APDU exceptions through the slot
        // boundary. Empty / partial enumeration is the safe fallback.
    }

    return objects;
}

unsigned long Pkcs15Slot::login(unsigned long userType, std::span<const std::uint8_t> pin)
{
    using namespace LibreSCRS::Pkcs11::Internal;

    if (userType != 1UL) // CKU_USER
        return Crv::ArgumentsBad;

    auto parent = parentCard.lock();
    if (!parent)
        return Crv::DeviceError;
    auto& parentP15 = static_cast<Pkcs15Card&>(*parent);

    std::scoped_lock locks(slotMutex, parentTransportMutex(*parent));

    try {
        // Stage the PIN bytes in a scrubbing std::string; if the parent
        // needs PACE we split CAN-in-PIN at the first ':'.
        std::string pinStr(pin.begin(), pin.end());
        ::LibreSCRS::SmartCard::Internal::PinStringScrubber pinScrub{pinStr};

        if (std::getenv("LIBRESCRS_SIGN_TRACE")) {
            const auto* p = parentProfile(*parent);
            std::fprintf(stderr,
                         "[PKCS15Slot] login entry: placeholder=%d needsPace=%d canEmpty=%d "
                         "deferredProfile=%d pinInfo=%s parentProfile=%s pinLen=%zu\n",
                         parentPlaceholderState(*parent) ? 1 : 0, parentNeedsPace(*parent) ? 1 : 0,
                         parentCanIsEmpty(*parent) ? 1 : 0, deferredProfile ? 1 : 0, pinInfo ? "set" : "null",
                         p ? "set" : "null", pin.size());
        }

        // Branch 1 — PACE placeholder-slot self-transform. Distinct from
        // the deferred-profile path (Branch 3): that path PIN-verifies
        // against an applet that refuses pre-login directory reads; this
        // path drives the parent's resumeBind() to perform PACE + applet
        // select + readProfile after the CAN is supplied. After
        // resumeBind succeeds the slot adopts the parent's freshly-read
        // profile in place, keeping its CK_SLOT_ID stable so any session
        // opened against the placeholder slot remains valid.
        if (parentPlaceholderState(*parent)) {
            // CAN-in-PIN. Pure-PACE cards (no second PIN) accept a bare
            // CAN; cards that combine PACE with a card-side PIN accept
            // "CAN:PIN". Either form is parsed here. The local
            // `can` and `realPin` std::strings carry secret bytes across
            // non-noexcept calls (parentCacheCan, parentResumeBind,
            // parentP15.acquireChannel, apdu.verifyPIN); wrap each in a
            // PinStringScrubber so an exception still zeroises the
            // intermediate before the std::string allocator releases it.
            std::string can;
            ::LibreSCRS::SmartCard::Internal::PinStringScrubber canScrub{can};
            std::string realPin;
            ::LibreSCRS::SmartCard::Internal::PinStringScrubber realPinScrub{realPin};
            auto colon = pinStr.find(':');
            if (colon == std::string::npos) {
                can = pinStr;
            } else {
                can = pinStr.substr(0, colon);
                realPin = pinStr.substr(colon + 1);
            }
            OPENSSL_cleanse(pinStr.data(), pinStr.size());

            if (can.empty()) {
                OPENSSL_cleanse(realPin.data(), realPin.size());
                return Crv::PinInvalid;
            }

            parentCacheCan(*parent, LibreSCRS::Secure::String{std::move(can)});

            auto rc = parentResumeBind(*parent);
            if (rc != Crv::Ok) {
                OPENSSL_cleanse(realPin.data(), realPin.size());
                parentClearCan(*parent);
                return rc;
            }

            // resumeBind has populated parent's profile (best-effort).
            // Adopt the user PIN view in place; the slot's CK_SLOT_ID
            // stays anchored on the placeholder-derived stableSlotId.
            const auto* profile = parentProfile(*parent);
            ::pkcs15::PinInfo* selectedPin = nullptr;
            ::pkcs15::PKCS15Profile profileCopy;
            if (profile) {
                profileCopy = *profile;
                if (std::getenv("LIBRESCRS_SIGN_TRACE")) {
                    std::fprintf(stderr, "[PKCS15Slot] AODF dump: %zu PINs, %zu keys, %zu certs\n",
                                 profileCopy.pins.size(), profileCopy.privateKeys.size(),
                                 profileCopy.certificates.size());
                    for (const auto& p : profileCopy.pins) {
                        std::string idHex;
                        for (auto b : p.id) {
                            char buf[4];
                            std::snprintf(buf, sizeof(buf), "%02X", b);
                            idHex += buf;
                        }
                        std::fprintf(stderr,
                                     "[PKCS15Slot]   PIN: ref=0x%02X id=%s label=\"%s\" unblocking=%d isUser=%d\n",
                                     p.pinReference, idHex.c_str(), p.label.c_str(), p.unblockingPin ? 1 : 0,
                                     isUserPin(p) ? 1 : 0);
                    }
                    for (const auto& k : profileCopy.privateKeys) {
                        std::string idHex, authIdHex;
                        for (auto b : k.id) {
                            char buf[4];
                            std::snprintf(buf, sizeof(buf), "%02X", b);
                            idHex += buf;
                        }
                        for (auto b : k.authId) {
                            char buf[4];
                            std::snprintf(buf, sizeof(buf), "%02X", b);
                            authIdHex += buf;
                        }
                        std::fprintf(stderr, "[PKCS15Slot]   KEY: id=%s authId=%s ref=0x%02X label=\"%s\"\n",
                                     idHex.c_str(), authIdHex.c_str(), k.keyReference, k.label.c_str());
                    }
                }
                // Single source of user-PIN truth: defer to isUserPin,
                // matching the eager-bind code path (one slot per user
                // PIN) so placeholder self-transform never selects a SO
                // PIN, PUK, or CAN entry as the slot's owning PIN.
                for (auto& p : profileCopy.pins) {
                    if (isUserPin(p)) {
                        selectedPin = &p;
                        break;
                    }
                }
                if (!selectedPin && !profileCopy.pins.empty())
                    selectedPin = &profileCopy.pins.front();

                if (selectedPin) {
                    pinId = selectedPin->id;
                    pinLabel = selectedPin->label;
                    pinInfo = *selectedPin;

                    // Mirror Pkcs15Card::completeBind cert/key pairing.
                    // Keys attributed to this PIN (matching authId), or
                    // to any PIN when the AODF lacks per-key authId
                    // (single-PIN cards in scope here).
                    for (const auto& key : profileCopy.privateKeys) {
                        if (key.authId == selectedPin->id || key.authId.empty())
                            keys.push_back(key);
                    }
                    // Strict id-match between cert and retained key. We
                    // do NOT keep an orphan cert as a fallback: that
                    // surfaces CA-chain entries (or the wrong cert when
                    // multiple unattributed certs exist) as the slot's
                    // identity, diverging from completeBind's semantics.
                    for (const auto& cert : profileCopy.certificates) {
                        for (const auto& key : keys) {
                            if (cert.id == key.id) {
                                certs.push_back(cert);
                                break;
                            }
                        }
                    }

                    if (!profileCopy.tokenInfo.label.empty())
                        cachedTokenInfo.label = profileCopy.tokenInfo.label;
                    else
                        cachedTokenInfo.label = parent->reader();
                    if (!profileCopy.tokenInfo.manufacturer.empty())
                        cachedTokenInfo.manufacturerId = profileCopy.tokenInfo.manufacturer;
                    if (!profileCopy.tokenInfo.serialNumber.empty())
                        cachedTokenInfo.serialNumber = profileCopy.tokenInfo.serialNumber;
                    cachedTokenInfo.pinLabel = selectedPin->label;
                }
            }

            // The slot leaves placeholder mode regardless of profile
            // shape — but if the post-resume profile yielded zero keys
            // AND zero certs the slot has no signable objects, so the
            // happy-path login would surface as CKR_OK on C_Login
            // followed by CKR_KEY_HANDLE_INVALID on C_Sign. Fail the
            // login explicitly so the consumer gets a single accurate
            // error rather than a misleading two-step.
            deferredProfile = false;

            if (keys.empty() && certs.empty()) {
                OPENSSL_cleanse(realPin.data(), realPin.size());
                parentClearCan(*parent);
                return Crv::DeviceError;
            }

            if (!realPin.empty() && selectedPin) {
                // Optional PIN verify for PACE+PIN combo cards.
                // Pure-PACE cards reach this branch with realPin empty
                // and skip verify entirely — PACE alone authenticates.
                auto holderResult = parentP15.acquireChannel();
                if (!holderResult) {
                    OPENSSL_cleanse(realPin.data(), realPin.size());
                    return Crv::DeviceError;
                }
                auto holder = std::move(*holderResult);
                auto* channel = LibreSCRS::SmartCard::Internal::HolderChannelAccessor::channel(holder);
                if (channel == nullptr) {
                    OPENSSL_cleanse(realPin.data(), realPin.size());
                    return Crv::DeviceError;
                }
                ::pkcs15::PKCS15Card apdu(*channel);
                auto result = apdu.verifyPIN(*selectedPin, realPin);
                if (!result.success) {
                    OPENSSL_cleanse(realPin.data(), realPin.size());
                    if (result.blocked)
                        return Crv::PinLocked;
                    return Crv::PinIncorrect;
                }
                cachedPin = LibreSCRS::Secure::String{std::move(realPin)};
            } else {
                OPENSSL_cleanse(realPin.data(), realPin.size());
            }

            loggedIn = true;
            return Crv::Ok;
        }

        // Branch 2 — PACE eager-bind without yet-cached CAN. Parse
        // CAN-in-PIN, deposit, validate via establishPACE, fall through
        // with realPin held in pinStr for verifyPIN below.
        if (parentNeedsPace(*parent) && parentCanIsEmpty(*parent)) {
            auto colon = pinStr.find(':');
            if (colon == std::string::npos)
                return Crv::PinInvalid;
            // Same rationale as Branch 1: the local `can` and `realPin`
            // std::strings are alive across non-noexcept calls
            // (parentCacheCan, parentEstablishPACE). The scrubbers fire
            // on every exit path including exception unwind.
            std::string can;
            ::LibreSCRS::SmartCard::Internal::PinStringScrubber canScrub{can};
            std::string realPin;
            ::LibreSCRS::SmartCard::Internal::PinStringScrubber realPinScrub{realPin};
            can = pinStr.substr(0, colon);
            realPin = pinStr.substr(colon + 1);
            OPENSSL_cleanse(pinStr.data(), pinStr.size());

            // Cache CAN on the parent (under cardMutex, already held).
            // The hook forwards the secret to the session's PACE cache.
            parentCacheCan(*parent, LibreSCRS::Secure::String{std::move(can)});

            // Trigger PACE (validates the deposited CAN); on failure
            // cleanse and bail.
            auto rc = parentEstablishPACE(*parent);
            if (rc != Crv::Ok) {
                OPENSSL_cleanse(realPin.data(), realPin.size());
                parentClearCan(*parent);
                return rc;
            }

            pinStr = std::move(realPin);
        }

        // Branch 3 — Deferred-profile and standard eager-bind both reach
        // here. Build a PinInfo to verify against, acquire a holder, run
        // the verify; deferred-profile additionally reads the post-verify
        // AODF to populate this slot.
        //
        // Source-of-truth order for the PinInfo:
        //   1. The slot's own cached pinInfo, if populated (eager-bind).
        //   2. The parent card's profile (read post-display for PACE-
        //      gated cards — supplies the card's real PIN reference,
        //      stored length, pad char, and applet path).
        //   3. Vendor AODF defaults — true deferred profile where the
        //      AODF cannot be read until the User PIN is verified.
        ::pkcs15::PinInfo pinInfoForVerify;
        if (pinInfo) {
            pinInfoForVerify = *pinInfo;
        } else if (deferredProfile) {
            const auto* parentP = parentProfile(*parent);
            const ::pkcs15::PinInfo* userPinFromProfile = nullptr;
            if (parentP) {
                for (const auto& p : parentP->pins) {
                    if (isUserPin(p)) {
                        userPinFromProfile = &p;
                        break;
                    }
                }
                if (!userPinFromProfile && !parentP->pins.empty())
                    userPinFromProfile = &parentP->pins.front();
            }
            if (userPinFromProfile) {
                pinInfoForVerify = *userPinFromProfile;
            } else {
                // Vendor AODF defaults: the User PIN sits at reference
                // kSafeSignDefaultUserPinRef (SO PIN at
                // kSafeSignDefaultSoPinRef), ASCII encoding, 15-byte
                // fixed stored length, NUL-padded, minimum 4 digits.
                pinInfoForVerify.id = {::pkcs15::kSafeSignDefaultUserPinRef};
                pinInfoForVerify.label = pinLabel;
                pinInfoForVerify.pinReference = ::pkcs15::kSafeSignDefaultUserPinRef;
                pinInfoForVerify.pinType = ::pkcs15::PinType::Ascii;
                pinInfoForVerify.padChar = 0x00;
                pinInfoForVerify.minLength = 4;
                pinInfoForVerify.storedLength = 15;
                pinInfoForVerify.maxLength = 0;
                pinInfoForVerify.hasMaxLength = false;
                pinInfoForVerify.path = {};
            }
        } else {
            return Crv::DeviceError;
        }
        if (std::getenv("LIBRESCRS_SIGN_TRACE"))
            std::fprintf(stderr,
                         "[PKCS15Slot] Branch3 verify PinInfo ref=0x%02X label=\"%s\" stored=%d padChar=0x%02X "
                         "source=%s\n",
                         pinInfoForVerify.pinReference, pinInfoForVerify.label.c_str(), pinInfoForVerify.storedLength,
                         static_cast<unsigned>(pinInfoForVerify.padChar) & 0xFF,
                         pinInfo ? "slot-pinInfo" : (parentProfile(*parent) ? "parent-profile" : "safesign-defaults"));

        auto holderResult = parentP15.acquireChannel();
        if (!holderResult)
            return Crv::DeviceError;
        auto holder = std::move(*holderResult);
        auto* channel = LibreSCRS::SmartCard::Internal::HolderChannelAccessor::channel(holder);
        if (channel == nullptr)
            return Crv::DeviceError;
        ::pkcs15::PKCS15Card apdu(*channel);

        auto result = apdu.verifyPIN(pinInfoForVerify, pinStr);
        if (!result.success) {
            OPENSSL_cleanse(pinStr.data(), pinStr.size());
            if (result.blocked)
                return Crv::PinLocked;
            return Crv::PinIncorrect;
        }

        // PIN verified. If we entered in deferred-profile mode, read the
        // real PKCS#15 profile now and finalise this slot's state. The
        // holder (which carries the post-verify auth context) is still
        // alive, so readProfile rides the same channel that just won the
        // verify — no risk of the SM session collapsing between the two.
        if (deferredProfile) {
            try {
                LibreSCRS::Internal::probeTrace("PROBE-READPROFILE call=slot-deferred");
                auto profile = apdu.readProfile();
                ::pkcs15::PinInfo* selectedPin = nullptr;
                for (auto& p : profile.pins) {
                    if (isUserPin(p)) {
                        selectedPin = &p;
                        break;
                    }
                }
                if (!selectedPin && !profile.pins.empty())
                    selectedPin = &profile.pins.front();

                if (selectedPin) {
                    pinId = selectedPin->id;
                    pinLabel = selectedPin->label;
                    pinInfo = *selectedPin;

                    for (const auto& key : profile.privateKeys) {
                        if (key.authId == selectedPin->id || key.authId.empty())
                            keys.push_back(key);
                    }
                    for (const auto& cert : profile.certificates) {
                        for (const auto& key : keys) {
                            if (cert.id == key.id) {
                                certs.push_back(cert);
                                break;
                            }
                        }
                    }

                    if (!profile.tokenInfo.label.empty())
                        cachedTokenInfo.label = profile.tokenInfo.label;
                    if (!profile.tokenInfo.manufacturer.empty())
                        cachedTokenInfo.manufacturerId = profile.tokenInfo.manufacturer;
                    if (!profile.tokenInfo.serialNumber.empty())
                        cachedTokenInfo.serialNumber = profile.tokenInfo.serialNumber;
                    cachedTokenInfo.pinLabel = selectedPin->label;
                }
                deferredProfile = false;
            } catch (...) {
                // PIN verify succeeded but the post-verify profile read
                // failed (transient APDU error, std::bad_alloc, malformed
                // AODF, etc.). The card retry counter has already been
                // consumed by the verify; falling through to loggedIn=true
                // with empty keys/certs would surface as a silent zero-byte
                // signature at signData(). Surface the failure to the
                // consumer so they get a clean CKR_DEVICE_ERROR rather
                // than CKR_FUNCTION_FAILED with no diagnostic.
                OPENSSL_cleanse(pinStr.data(), pinStr.size());
                return Crv::DeviceError;
            }
        }

        cachedPin = LibreSCRS::Secure::String{std::move(pinStr)};
        loggedIn = true;
        return Crv::Ok;
    } catch (...) {
        return Crv::DeviceError;
    }
}

unsigned long Pkcs15Slot::logout()
{
    std::scoped_lock lock(slotMutex);
    cachedPin.clear();
    loggedIn = false;
    return LibreSCRS::Pkcs11::Internal::Crv::Ok;
}

std::vector<std::uint8_t> Pkcs15Slot::signData(std::span<const std::uint8_t> data, unsigned long mechanism,
                                               std::span<const std::uint8_t> keyId)
{
    using namespace LibreSCRS::Pkcs11::Internal;

    auto parent = parentCard.lock();
    if (!parent)
        return {};
    auto& parentP15 = static_cast<Pkcs15Card&>(*parent);

    std::scoped_lock locks(slotMutex, parentTransportMutex(*parent));

    if (!loggedIn || !cachedPin)
        return {};

    // Find the key by PKCS#15 id.
    const ::pkcs15::PrivateKeyInfo* matched = nullptr;
    for (const auto& k : keys) {
        if (std::equal(k.id.begin(), k.id.end(), keyId.begin(), keyId.end())) {
            matched = &k;
            break;
        }
    }
    if (!matched || !pinInfo)
        return {};

    try {
        auto scheme = mechanismToScheme(mechanism, matched->keyType);

        // Materialise PIN as cleansing std::string (SSO-safe; PinStringScrubber
        // covers the exception path even before sign() returns).
        auto canView = cachedPin.view();
        std::string pinStr(canView.begin(), canView.end());
        ::LibreSCRS::SmartCard::Internal::PinStringScrubber pinScrub{pinStr};

        auto holderResult = parentP15.acquireChannel();
        if (!holderResult)
            return {};
        auto holder = std::move(*holderResult);
        auto* channel = LibreSCRS::SmartCard::Internal::HolderChannelAccessor::channel(holder);
        if (channel == nullptr)
            return {};
        ::pkcs15::PKCS15Card apdu(*channel);

        std::vector<std::uint8_t> dataVec(data.begin(), data.end());
        return apdu.sign(*matched, pinStr, *pinInfo, dataVec, dataVec, scheme);
    } catch (...) {
        return {};
    }
}

std::vector<std::uint8_t> Pkcs15Slot::signWithDigestInfo(std::span<const std::uint8_t> digestInfo,
                                                         std::span<const std::uint8_t> rawData, unsigned long mechanism,
                                                         std::span<const std::uint8_t> keyId)
{
    using namespace LibreSCRS::Pkcs11::Internal;

    // The underlying @c PKCS15Card::sign already takes both DigestInfo
    // and raw data, so dual-buffer dispatch lives in the lower layer;
    // this method is a thin Slot-API wrapper.
    auto parent = parentCard.lock();
    if (!parent)
        return {};
    auto& parentP15 = static_cast<Pkcs15Card&>(*parent);

    std::scoped_lock locks(slotMutex, parentTransportMutex(*parent));

    if (!loggedIn || !cachedPin)
        return {};

    const ::pkcs15::PrivateKeyInfo* matched = nullptr;
    for (const auto& k : keys) {
        if (std::equal(k.id.begin(), k.id.end(), keyId.begin(), keyId.end())) {
            matched = &k;
            break;
        }
    }
    if (!matched || !pinInfo)
        return {};

    try {
        auto scheme = mechanismToScheme(mechanism, matched->keyType);

        auto canView = cachedPin.view();
        std::string pinStr(canView.begin(), canView.end());
        ::LibreSCRS::SmartCard::Internal::PinStringScrubber pinScrub{pinStr};

        auto holderResult = parentP15.acquireChannel();
        if (!holderResult)
            return {};
        auto holder = std::move(*holderResult);
        auto* channel = LibreSCRS::SmartCard::Internal::HolderChannelAccessor::channel(holder);
        if (channel == nullptr)
            return {};
        ::pkcs15::PKCS15Card apdu(*channel);

        std::vector<std::uint8_t> digestVec(digestInfo.begin(), digestInfo.end());
        std::vector<std::uint8_t> rawVec(rawData.begin(), rawData.end());
        return apdu.sign(*matched, pinStr, *pinInfo, digestVec, rawVec, scheme);
    } catch (const std::exception& e) {
        if (std::getenv("LIBRESCRS_SIGN_TRACE"))
            std::fprintf(stderr, "[Pkcs15Slot::signData] exception: %s\n", e.what());
        return {};
    } catch (...) {
        if (std::getenv("LIBRESCRS_SIGN_TRACE"))
            std::fprintf(stderr, "[Pkcs15Slot::signData] unknown exception\n");
        return {};
    }
}

std::size_t Pkcs15Slot::signatureSize(std::span<const std::uint8_t> keyId) const
{
    // Pre-IO size derivation. `keys` may be populated lazily under the
    // deferred-profile path (login() mutates it after a successful
    // applet open), so the read must serialise under slotMutex with
    // the writers. RSA path uses the PrKDF-reported keySizeBits / 8;
    // ECDSA derives from the curve length implied by the keySizeBits
    // field (PKCS#15 surfaces the bit length of the field, e.g. 256
    // for P-256).
    std::scoped_lock lock(slotMutex);
    for (const auto& k : keys) {
        if (k.id.size() != keyId.size())
            continue;
        if (!std::equal(k.id.begin(), k.id.end(), keyId.begin(), keyId.end()))
            continue;
        const std::size_t bits = static_cast<std::size_t>(k.keySizeBits);
        if (bits == 0)
            return 0;
        if (k.keyType == ::pkcs15::KeyType::Ec) {
            // ECDSA signature: r || s, each ceil(fieldBits / 8). Add a
            // small DER-wrapping headroom so callers querying the size
            // before C_Sign get a buffer large enough for the actual
            // ASN.1 SEQUENCE returned by the card (mirrors the
            // pkcs11_library.cpp +8 fallback for unknown curves).
            const std::size_t fieldBytes = (bits + 7u) / 8u;
            return 2u * fieldBytes + 8u;
        }
        return (bits + 7u) / 8u;
    }
    return 0u;
}

} // namespace LibreSCRS::Pkcs15::Pkcs11
