// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

/// @file
/// @brief Concrete @ref LibreSCRS::Pkcs15::Pkcs11::Pkcs15Slot
///        implementation. Provides per-slot semantics (login + sign +
///        enumerateObjects) reduced to a single PIN's view of the card.

#include "pkcs15_pkcs11_slot.h"

#include "pkcs15_card.h"
#include "pkcs15_pkcs11_card.h"
#include "pkcs15_parser.h"
#include "pkcs15_types.h"

#include "probe_trace.h"

#include <internal/Crv.h>
#include <internal/DerWrap.h>
#include <internal/MechanismConstants.h>
#include <internal/PKCS11Card.h>

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
                       std::string pinLabel, ::pkcs15::PKCS15Card* apdu, ::pkcs15::PinInfo pinInfo,
                       std::vector<::pkcs15::PrivateKeyInfo> keys, std::vector<::pkcs15::CertificateInfo> certs,
                       LibreSCRS::Pkcs11::Internal::PKCS11TokenInfo tokenInfo, unsigned long slotId)
    : LibreSCRS::Pkcs11::Internal::PKCS11Slot(std::move(parent), std::move(pinId), std::move(pinLabel)), apdu(apdu),
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
    // Deferred-profile mode for AET SafeSign / Posta Srbija eID style cards
    // that refuse PKCS#15 directory reads pre-login. apdu / pinInfo / keys /
    // certs are populated lazily inside login() after PIN verification
    // succeeds. The placeholder pinId is empty until the AODF is read.
    cachedTokenInfo = std::move(placeholderTokenInfo);
    stableSlotId = slotId;
}

Pkcs15Slot::~Pkcs15Slot() = default;

void Pkcs15Slot::onCardReset() noexcept
{
    // RESET drops the card-side auth context AND invalidates our borrowed
    // apdu pointer because Pkcs15Card::reconnectInline rebuilt the
    // parent's std::unique_ptr<pkcs15::PKCS15Card> from scratch. The
    // previous generation's raw apdu* held by every slot is now dangling;
    // refresh it from the parent under slotMutex before any subsequent
    // signData / enumerateObjects can dereference the old pointer.
    //
    // Lock order (slotMutex → cardMutex) is preserved by the caller:
    // PKCS11Card::handleReset releases cardMutex before walking the
    // slot list. We can therefore safely re-take cardMutex briefly to
    // publish-read the parent's freshly-rebuilt apdu pointer.
    auto parent = parentCard.lock();

    std::scoped_lock slotLock(slotMutex);
    cachedPin.clear();
    loggedIn = false;

    if (parent) {
        std::scoped_lock cardLock(parentTransportMutex(*parent));
        // For deferred-profile slots that have not yet logged in,
        // parent->apdu may still be null; mirror that here. Otherwise
        // pick up the freshly-rebuilt helper.
        apdu = parentApduHelper(*parent);
    } else {
        // Parent gone — slot is effectively orphaned; clearing the
        // borrow keeps subsequent calls from touching freed memory.
        apdu = nullptr;
    }
}

::pkcs15::PKCS15Card* Pkcs15Slot::parentApduHelper(LibreSCRS::Pkcs11::Internal::PKCS11Card& parentBase) noexcept
{
    auto* parent = static_cast<Pkcs15Card*>(&parentBase);
    return parent->apdu.get();
}

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
    // For every certificate paired with a key in this slot's filtered
    // set, surface a (cert, private-key) pair. Slot-private object scope
    // means we do NOT see keys from sibling slots (one PIN ⇒ one set).
    std::vector<PKCS11ObjectInfo> objects;

    // Acquire cardMutex through the parent because readCertificate()
    // issues APDUs. slotMutex is not required for keys/certs (immutable
    // post-construction), but enumerateObjects() can race with login()
    // on the same slot, so we still take it for ordering.
    auto parent = parentCard.lock();
    if (!parent)
        return objects;
    std::scoped_lock slotLock(slotMutex);
    std::scoped_lock cardLock(parentTransportMutex(*parent));

    if (!apdu)
        return objects; // Deferred-profile mode pre-login: nothing enumerated.

    try {
        if (!apdu->selectApplet()) {
            // Same recovery path as Pkcs15Slot::login — re-probe (EF.DIR
            // fallback) when cached state from CardMap is stale relative
            // to the current connection's SM state.
            if (!(apdu->probe() && apdu->selectApplet()))
                return objects;
        }

        for (const auto& certInfo : certs) {
            std::vector<std::uint8_t> derBytes;
            try {
                derBytes = apdu->readCertificate(certInfo);
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

    std::scoped_lock slotLock(slotMutex);
    std::scoped_lock cardLock(parentTransportMutex(*parent));

    try {
        // Stage the PIN bytes in a scrubbing std::string; if the parent
        // needs PACE we split CAN-in-PIN at the first ':'.
        std::string pinStr(pin.begin(), pin.end());
        ::LibreSCRS::SmartCard::Internal::PinStringScrubber pinScrub{pinStr};

        // PACE placeholder-slot self-transform path. Distinct from the
        // OLD-AET deferred-profile path below: that path PIN-verifies
        // against an applet that refuses pre-login directory reads;
        // this path drives the parent's resumeBind() to perform PACE +
        // applet select + readProfile after the CAN is supplied. After
        // resumeBind succeeds the slot adopts the parent's freshly-read
        // profile in place, keeping its CK_SLOT_ID stable so any
        // session opened against the placeholder slot remains valid.
        if (parentPlaceholderState(*parent)) {
            // CAN-in-PIN. NAM CL (pure-PACE, no second PIN) accepts a
            // bare CAN; cards that combine PACE with a card-side PIN
            // accept "CAN:PIN". Either form is parsed here.
            std::string can;
            std::string realPin;
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

            // resumeBind has populated parent's apdu and (best-effort)
            // profile. Borrow the apdu and transform self from profile.
            apdu = parentApduHelper(*parent);
            if (!apdu) {
                OPENSSL_cleanse(realPin.data(), realPin.size());
                // Cleanse the cached CAN: leaving it would let a future
                // login on this placeholder slot skip PACE while the
                // parent has no APDU helper, deadlocking the slot in a
                // permanent DeviceError loop without retry recovery.
                parentClearCan(*parent);
                return Crv::DeviceError;
            }

            const auto* profile = parentProfile(*parent);
            ::pkcs15::PinInfo* selectedPin = nullptr;
            ::pkcs15::PKCS15Profile profileCopy;
            if (profile) {
                profileCopy = *profile;
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
                // Optional PIN verify for PACE+PIN combo cards. NAM CL
                // (pure-PACE) reaches this branch with realPin empty
                // and skips verify entirely — PACE alone authenticates.
                auto result = apdu->verifyPIN(*selectedPin, realPin);
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

        if (parentNeedsPace(*parent)) {
            // CAN-in-PIN format. If the parent already has a cachedCan
            // (login earlier in this session, or pre-seeded) we accept a
            // bare PIN; otherwise we require "CAN:PIN".
            if (parentCanIsEmpty(*parent)) {
                auto colon = pinStr.find(':');
                if (colon == std::string::npos)
                    return Crv::PinInvalid;
                std::string can = pinStr.substr(0, colon);
                std::string realPin = pinStr.substr(colon + 1);
                OPENSSL_cleanse(pinStr.data(), pinStr.size());

                // Cache CAN on the parent (under cardMutex, already held).
                parentCacheCan(*parent, LibreSCRS::Secure::String{std::move(can)});

                // Trigger PACE; on failure cleanse and bail.
                auto rc = parentEstablishPACE(*parent);
                if (rc != Crv::Ok) {
                    OPENSSL_cleanse(realPin.data(), realPin.size());
                    parentClearCan(*parent);
                    return rc;
                }

                pinStr = std::move(realPin);
            }
        }

        // Deferred-profile mode (AET SafeSign / Posta Srbija):
        // The applet refuses PKCS#15 directory reads pre-login. Borrow the
        // parent card's APDU helper, run a single PIN verify with a
        // generic PinInfo (reference 0x01, ASCII, padded with 0xFF — the
        // SafeSign default), and on success read the AODF / PrKDF / CDF
        // to populate this slot's pinInfo / keys / certs. Single-shot:
        // we never retry a failed PIN inside one login() call so the
        // card retry counter consumes at most one attempt per consumer
        // C_Login invocation.
        if (deferredProfile && !apdu) {
            auto* parentApdu = parentApduHelper(*parent);
            if (!parentApdu)
                return Crv::DeviceError;
            apdu = parentApdu;
        }

        if (!apdu)
            return Crv::DeviceError;

        if (!apdu->selectApplet()) {
            // Cached state may be stale relative to the post-PACE SM
            // tunnel (path / P2 probed pre-SM no longer accepted under
            // SM, or vice versa). Re-run probe with EF.DIR fallback
            // and retry — the CardMap consumed at bind() is the
            // happy path; this is the recovery path.
            if (!(apdu->probe() && apdu->selectApplet()))
                return Crv::DeviceError;
        }

        // For deferred-profile mode build a generic PinInfo defaulting to
        // SafeSign conventions. After successful verify we read the real
        // AODF and replace this with the on-card PinInfo.
        ::pkcs15::PinInfo pinInfoForVerify;
        if (deferredProfile && !pinInfo) {
            // SafeSign IC AODF defaults documented in the vendor token
            // manual: the User PIN sits at reference kSafeSignDefaultUserPinRef
            // (SO PIN at kSafeSignDefaultSoPinRef), ASCII encoding, 15-byte
            // fixed stored length, NUL-padded, minimum 4 digits. JCOP21
            // and Infineon SLE hardware variants share these AODF defaults.
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
        } else if (pinInfo) {
            pinInfoForVerify = *pinInfo;
        } else {
            return Crv::DeviceError;
        }

        auto result = apdu->verifyPIN(pinInfoForVerify, pinStr);
        if (!result.success) {
            OPENSSL_cleanse(pinStr.data(), pinStr.size());
            if (result.blocked)
                return Crv::PinLocked;
            return Crv::PinIncorrect;
        }

        // PIN verified. If we entered in deferred-profile mode, read the
        // real PKCS#15 profile now and finalise this slot's state.
        if (deferredProfile) {
            try {
                LibreSCRS::Internal::probeTrace("PROBE-READPROFILE call=slot-deferred");
                auto profile = apdu->readProfile();
                ::pkcs15::PinInfo* selectedPin = nullptr;
                for (auto& p : profile.pins) {
                    // Single source of user-PIN truth: defer to isUserPin
                    // so SO PIN / admin entries on AET SafeSign are not
                    // selected as the slot's owning PIN.
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

                    // Filter keys + certs by matching authId (or accept all
                    // when the AODF lacks per-key authId attribution —
                    // single-PIN AET cards in scope here).
                    for (const auto& key : profile.privateKeys) {
                        if (key.authId == selectedPin->id || key.authId.empty())
                            keys.push_back(key);
                    }
                    // Strict id-match between cert and retained key. We
                    // do NOT keep an orphan cert as a fallback: that
                    // surfaces CA-chain entries (or the wrong cert when
                    // multiple unattributed certs exist) as the slot's
                    // identity, diverging from completeBind's semantics.
                    for (const auto& cert : profile.certificates) {
                        for (const auto& key : keys) {
                            if (cert.id == key.id) {
                                certs.push_back(cert);
                                break;
                            }
                        }
                    }

                    // Update cachedTokenInfo with real profile values.
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
                // consumer instead — caller sees CKR_DEVICE_ERROR rather
                // than CKR_FUNCTION_FAILED with no diagnostic. Wipe the
                // already-consumed PIN buffer to avoid leaving it in
                // process memory, leave deferredProfile=true so a future
                // (post-recovery) login can still retry once the
                // underlying readProfile failure is resolved.
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

    std::scoped_lock slotLock(slotMutex);
    std::scoped_lock cardLock(parentTransportMutex(*parent));

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
    if (!matched)
        return {};

    try {
        auto scheme = mechanismToScheme(mechanism, matched->keyType);

        // Materialise PIN as cleansing std::string (SSO-safe; PinStringScrubber
        // covers the exception path even before sign() returns).
        auto canView = cachedPin.view();
        std::string pinStr(canView.begin(), canView.end());
        ::LibreSCRS::SmartCard::Internal::PinStringScrubber pinScrub{pinStr};

        if (!apdu || !pinInfo)
            return {};

        std::vector<std::uint8_t> dataVec(data.begin(), data.end());
        return apdu->sign(*matched, pinStr, *pinInfo, dataVec, dataVec, scheme);
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

    std::scoped_lock slotLock(slotMutex);
    std::scoped_lock cardLock(parentTransportMutex(*parent));

    if (!loggedIn || !cachedPin)
        return {};

    const ::pkcs15::PrivateKeyInfo* matched = nullptr;
    for (const auto& k : keys) {
        if (std::equal(k.id.begin(), k.id.end(), keyId.begin(), keyId.end())) {
            matched = &k;
            break;
        }
    }
    if (!matched)
        return {};

    try {
        auto scheme = mechanismToScheme(mechanism, matched->keyType);

        auto canView = cachedPin.view();
        std::string pinStr(canView.begin(), canView.end());
        ::LibreSCRS::SmartCard::Internal::PinStringScrubber pinScrub{pinStr};

        if (!apdu || !pinInfo)
            return {};

        std::vector<std::uint8_t> digestVec(digestInfo.begin(), digestInfo.end());
        std::vector<std::uint8_t> rawVec(rawData.begin(), rawData.end());
        return apdu->sign(*matched, pinStr, *pinInfo, digestVec, rawVec, scheme);
    } catch (...) {
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
