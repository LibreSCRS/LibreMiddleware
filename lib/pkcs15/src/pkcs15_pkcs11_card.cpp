// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

/// @file
/// @brief Concrete @ref LibreSCRS::Pkcs15::Pkcs11::Pkcs15Card backed by
///        the existing @ref pkcs15::PKCS15Card APDU helper.
///
/// Implements PACE / probe / bind by reusing the existing PKCS#15 APDU
/// helper and distributes the per-PIN view across owned @ref Pkcs15Slot
/// instances. Single-PIN path is exercised today (eID, NAM); multi-PIN
/// path is real-card validated in Phase D.

#include "pkcs15_pkcs11_card.h"

#include "pkcs15_card.h"
#include "pkcs15_pkcs11_slot.h"
#include "pkcs15_types.h"

#include <internal/Crv.h>
#include <internal/PKCS11TokenInfo.h>
#include <internal/SlotIdHash.h>

#include <pace.h>
#include <secure_messaging.h>
#include <smartcard/pcsc_connection.h>

#include <openssl/crypto.h>

#include <algorithm>
#include <cctype>
#include <optional>
#include <utility>

namespace LibreSCRS::Pkcs15::Pkcs11 {

namespace {

/// @brief PKCS#11 v2.40 token-flag bits used in @ref PKCS11TokenInfo.
/// Raw values intentionally avoid pulling pkcs11t.h into this TU.
constexpr unsigned long kCkfTokenInitialized = 0x00000400UL;
constexpr unsigned long kCkfLoginRequired = 0x00000004UL;
constexpr unsigned long kCkfUserPinInitialized = 0x00000008UL;

/// @brief Filter PKCS#15 PINs down to user-auth PINs (drop PUK / CAN /
///        PACE / SO entries).
[[nodiscard]] bool isUserPin(const ::pkcs15::PinInfo& pin)
{
    if (pin.unblockingPin)
        return false;
    auto label = pin.label;
    std::transform(label.begin(), label.end(), label.begin(), [](unsigned char c) { return std::tolower(c); });
    if (label.find("puk") != std::string::npos)
        return false;
    if (label.find("can") != std::string::npos || label.find("pace") != std::string::npos)
        return false;
    // Security Officer (admin) PIN — present on AET SafeSign cards as
    // "SO Pin" alongside "User Pin". PKCS#11 consumers should never
    // surface SO PINs as login slots; they are vendor-personalisation
    // credentials and surfacing them as a duplicate slot causes user
    // confusion + accidental retry-counter exhaustion if user picks the
    // wrong slot for daily sign.
    if (label == "so pin" || label.starts_with("so ") || label.find("security officer") != std::string::npos ||
        label.find("admin") != std::string::npos)
        return false;
    return true;
}

/// @brief Heuristic PKCS#15-PIN-label → @ref SlotKind classifier.
///
/// PKCS#15 does not encode a slot-kind concept; we infer it from the
/// PIN label so the FNV-1a slot ID is stable across reconnects. Unknown
/// labels default to @ref SlotKind::Generic.
[[nodiscard]] LibreSCRS::Pkcs11::Internal::SlotKind deriveSlotKind(const ::pkcs15::PinInfo& pin)
{
    auto label = pin.label;
    std::transform(label.begin(), label.end(), label.begin(), [](unsigned char c) { return std::tolower(c); });
    if (label.find("sign") != std::string::npos || label.find("qscd") != std::string::npos ||
        label.find("nonrep") != std::string::npos)
        return LibreSCRS::Pkcs11::Internal::SlotKind::Sign;
    if (label.find("auth") != std::string::npos)
        return LibreSCRS::Pkcs11::Internal::SlotKind::Auth;
    if (label.find("enc") != std::string::npos || label.find("dec") != std::string::npos)
        return LibreSCRS::Pkcs11::Internal::SlotKind::Enc;
    return LibreSCRS::Pkcs11::Internal::SlotKind::Generic;
}

} // namespace

Pkcs15Card::Pkcs15Card(std::shared_ptr<LibreSCRS::SmartCard::CardMap> cm) : cardMap(std::move(cm)) {}

Pkcs15Card::~Pkcs15Card() = default;

namespace {

/// @brief Build the @c CardMap::Key for this physical card.
///
/// @c reader / @c atrHex are stable across operations; @c serial is
/// empty until the PKCS#15 profile is read, so the first probe uses
/// (reader, atrHex, "") and the entry survives subsequent lookups
/// even when the serial is later resolved.
LibreSCRS::SmartCard::CardMap::Key makeCardMapKey(const std::string& reader, const std::vector<std::uint8_t>& atr)
{
    std::string atrHex;
    atrHex.reserve(atr.size() * 2);
    static constexpr char kHex[] = "0123456789ABCDEF";
    for (auto b : atr) {
        atrHex.push_back(kHex[(b >> 4) & 0x0F]);
        atrHex.push_back(kHex[b & 0x0F]);
    }
    return {reader, std::move(atrHex), std::string{}};
}

} // namespace

bool Pkcs15Card::probeForPace()
{
    // Replicates Pkcs15PKCS11Provider::probeForPace. Reads EF.CardAccess
    // from MF (available without authentication) and parses PACE OIDs.
    if (!conn)
        return false;

    auto r1 = conn->transmit(LibreSCRS::SmartCard::Internal::selectByFileId(0x3F, 0x00, 0x0C));
    if (!r1.isSuccess())
        r1 = conn->transmit(LibreSCRS::SmartCard::Internal::selectByFileId(0x3F, 0x00));
    if (!r1.isSuccess())
        return false;

    auto r2 = conn->transmit(LibreSCRS::SmartCard::Internal::selectByFileId(0x01, 0x1C, 0x0C));
    if (!r2.isSuccess())
        r2 = conn->transmit(LibreSCRS::SmartCard::Internal::selectByFileId(0x01, 0x1C));
    if (r2.sw1 != 0x90 && r2.sw1 != 0x62)
        return false;

    auto r3 = conn->transmit(LibreSCRS::SmartCard::Internal::APDUCommand{0x00, 0xB0, 0x00, 0x00, {}, 0, true});
    if (r3.data.empty())
        return false;

    auto entries = emrtd::crypto::parseCardAccessWithParams(r3.data);
    if (entries.empty())
        return false;

    cardAccessData = r3.data;
    return true;
}

void Pkcs15Card::installSmFilter()
{
    if (!conn || !sm)
        return;

    auto* smPtr = sm.get();
    auto* connPtr = conn.get();
    conn->setTransmitFilter([smPtr, connPtr](const LibreSCRS::SmartCard::Internal::APDUCommand& cmd)
                                -> LibreSCRS::SmartCard::Internal::APDUResponse {
        auto cmdBytes = cmd.toBytes();
        auto protectedApdu = smPtr->protect(cmdBytes);
        if (protectedApdu.size() < 5)
            return {{}, 0x69, 0x82};

        auto resp = connPtr->transmitRaw(protectedApdu.data(), static_cast<DWORD>(protectedApdu.size()));

        // SM 61XX response chaining (RSA-3072 sig > short Le max).
        while (resp.sw1 == 0x61) {
            std::uint8_t getResponseApdu[] = {0x00, 0xC0, 0x00, 0x00, resp.sw2};
            auto grResp = connPtr->transmitRaw(getResponseApdu, sizeof(getResponseApdu));
            resp.data.insert(resp.data.end(), grResp.data.begin(), grResp.data.end());
            resp.sw1 = grResp.sw1;
            resp.sw2 = grResp.sw2;
        }

        std::vector<std::uint8_t> respBytes = resp.data;
        respBytes.push_back(resp.sw1);
        respBytes.push_back(resp.sw2);

        auto result = smPtr->unprotectWithSW(respBytes);
        if (!result)
            return {{}, 0x69, 0x82};

        return {std::move(result->data), result->sw1, result->sw2};
    });
}

unsigned long Pkcs15Card::bind(const std::string& reader)
{
    using namespace LibreSCRS::Pkcs11::Internal;

    std::scoped_lock lock(cardMutex);

    readerName = reader;

    try {
        conn = std::make_unique<LibreSCRS::SmartCard::Internal::PCSCConnection>(reader);
    } catch (...) {
        return Crv::TokenNotPresent;
    }

    // Probe AID first; if security-blocked (6982) try EF.CardAccess for PACE.
    std::vector<std::uint8_t> aid(::pkcs15::kPkcs15Aid.begin(), ::pkcs15::kPkcs15Aid.end());
    auto aidResp = conn->transmit(LibreSCRS::SmartCard::Internal::selectByAID(aid, 0x0C));
    bool aidOk = aidResp.isSuccess();
    bool securityBlocked = (aidResp.sw1 == 0x69 && aidResp.sw2 == 0x82);

    if (!aidOk && !securityBlocked) {
        // Try EF.DIR fallback via temporary helper (no SM needed).
        ::pkcs15::PKCS15Card temp(*conn);
        if (!temp.probe())
            return Crv::TokenNotPresent;
        // EF.DIR worked — direct path, no PACE.
    } else if (securityBlocked) {
        if (!probeForPace())
            return Crv::TokenNotPresent;
        needsPace = true;
    }

    if (needsPace && cachedCan.empty()) {
        // Defer applet-select until login() supplies CAN-in-PIN. No
        // slots are published yet; PKCS#11 layer surfaces an empty
        // token list until login completes the bind. Phase D real-card
        // validation will exercise this branch end-to-end.
        return Crv::Ok;
    }

    if (needsPace) {
        if (auto rc = establishPACE(); rc != Crv::Ok)
            return rc;
    }

    apdu = std::make_unique<::pkcs15::PKCS15Card>(*conn);

    // CardMap fast-path: if this physical card has been probed earlier
    // in the process (same reader + ATR), seed the freshly-constructed
    // helper with the cached path/P2 so post-PACE SELECT picks up the
    // EF.DIR fallback without re-running the probe under the SM
    // tunnel — the secondary blocker called out in Phase D.2 findings.
    if (cardMap) {
        const auto key = makeCardMapKey(reader, conn->getATR());
        if (auto entry = cardMap->get(key)) {
            apdu->seedDiscoveredState(entry->pkcs15Path, entry->fileSelectP2);
        }
    }

    if (!apdu->selectApplet()) {
        // Post-PACE the cached state may be stale (SM-protected SELECT
        // could fail on a path that worked pre-PACE). Re-probe and try
        // again so this path remains valid for cards that change
        // SELECT semantics under SM.
        if (apdu->probe() && apdu->selectApplet()) {
            // fall through to caching below
        } else {
            return Crv::FunctionFailed;
        }
    }

    // Cache discovered state for subsequent operations against the
    // same physical card (e.g., re-probe after transient reconnect,
    // or a sibling plugin / provider touching the card).
    if (cardMap) {
        const auto key = makeCardMapKey(reader, conn->getATR());
        LibreSCRS::SmartCard::CardMapEntry entry;
        entry.pkcs15Path = apdu->pkcs15PathView();
        entry.fileSelectP2 = apdu->fileSelectP2View();
        cardMap->put(key, std::move(entry));
    }

    try {
        profile = std::make_unique<::pkcs15::PKCS15Profile>(apdu->readProfile());
        if (profile->pins.empty() && profile->privateKeys.empty() && profile->certificates.empty()) {
            // Empty profile suggests the applet refuses directory reads
            // pre-login (AET SafeSign / Posta Srbija eID style). Fall
            // through to deferred-profile mode.
            profile.reset();
            needsDeferredProfile = true;
        }
    } catch (...) {
        // readProfile threw — treat as deferred-profile mode rather than
        // a hard failure. AET SafeSign returns non-PKCS#15 payloads
        // (literal text "please authenticate yourself") for every
        // structural read, which surfaces as parser exceptions here.
        profile.reset();
        needsDeferredProfile = true;
    }

    return completeBind();
}

unsigned long Pkcs15Card::establishPACE()
{
    using namespace LibreSCRS::Pkcs11::Internal;

    if (!conn || cardAccessData.empty())
        return Crv::FunctionFailed;
    if (cachedCan.empty())
        return Crv::PinIncorrect; // CAN must be cached before PACE.

    auto entries = emrtd::crypto::parseCardAccessWithParams(cardAccessData);
    if (entries.empty())
        return Crv::FunctionFailed;

    auto canView = cachedCan.view();
    std::optional<emrtd::crypto::SessionKeys> session;
    for (const auto& [oid, paramId] : entries) {
        emrtd::crypto::PACEParams params;
        params.oid = oid;
        params.passwordType = emrtd::crypto::PACEPasswordType::CAN;
        params.password = std::vector<std::uint8_t>(canView.begin(), canView.end());
        params.paramId = paramId;
        session = emrtd::crypto::performPACE(*conn, params);
        // Cleanse the temporary password buffer; CRYPTO_memzero-equivalent
        // via OPENSSL_cleanse to avoid leaking CAN bytes through the heap.
        if (!params.password.empty())
            OPENSSL_cleanse(params.password.data(), params.password.size());
        if (session)
            break;
    }

    if (!session)
        return Crv::PinIncorrect;

    auto smAlgo = emrtd::crypto::paceOIDToSMAlgorithm(entries.front().first);
    sm = std::make_unique<emrtd::crypto::SecureMessaging>(*session, smAlgo);
    installSmFilter();

    return Crv::Ok;
}

unsigned long Pkcs15Card::completeBind()
{
    using namespace LibreSCRS::Pkcs11::Internal;

    if (!apdu)
        return Crv::FunctionFailed;

    // Deferred-profile path: applet refuses PKCS#15 directory reads
    // pre-login. Publish a single placeholder slot whose pinInfo / keys /
    // certs are populated lazily inside Pkcs15Slot::login after PIN
    // verification succeeds (see Pkcs15Slot deferred-profile ctor).
    if (needsDeferredProfile || !profile) {
        PKCS11TokenInfo placeholder;
        placeholder.label = "PKCS#15 (deferred)";
        placeholder.manufacturerId = "";
        placeholder.model = "PKCS#15";
        placeholder.serialNumber = "0000000000000000";
        placeholder.pinLabel = "Authentication PIN";
        placeholder.flags = kCkfTokenInitialized | kCkfLoginRequired | kCkfUserPinInitialized;
        placeholder.minPinLen = 4;
        placeholder.maxPinLen = 16;

        // Use empty pinId for the placeholder; the FNV-1a stable id is
        // derived from (reader, {}, Generic) and remains consistent
        // across reloads of the same card on the same reader. Post-login
        // the slot's pinId is updated to the real AODF id, but the
        // stableSlotId stays anchored to the placeholder hash so
        // existing CK_SLOT_ID consumers are not invalidated mid-session.
        std::vector<std::uint8_t> placeholderPinId{};
        unsigned long slotId =
            static_cast<unsigned long>(computeSlotId(readerName, placeholderPinId, SlotKind::Generic));

        slots.push_back(
            std::make_shared<Pkcs15Slot>(weak_from_this(), "Authentication PIN", std::move(placeholder), slotId));
        return Crv::Ok;
    }

    // Iterate AODF user PINs; one Pkcs15Slot per PIN.
    for (const auto& pin : profile->pins) {
        if (!isUserPin(pin))
            continue;

        // Filter keys by authId == pin.id; if the AODF lacks per-key
        // authId attribution (older cards), keys with empty authId are
        // attributed to the first user PIN (single-PIN cards).
        std::vector<::pkcs15::PrivateKeyInfo> keys;
        for (const auto& key : profile->privateKeys) {
            if (key.authId == pin.id || (key.authId.empty() && slots.empty()))
                keys.push_back(key);
        }

        // Pair certs with keys by matching CKA_ID; carry every cert that
        // corresponds to a retained key plus any cert whose id matches
        // pin.id directly (some cards encode the auth-id on the cert).
        std::vector<::pkcs15::CertificateInfo> certs;
        for (const auto& cert : profile->certificates) {
            for (const auto& key : keys) {
                if (cert.id == key.id) {
                    certs.push_back(cert);
                    break;
                }
            }
        }

        auto kind = deriveSlotKind(pin);
        unsigned long slotId = static_cast<unsigned long>(computeSlotId(readerName, pin.id, kind));

        PKCS11TokenInfo info;
        info.label = profile->tokenInfo.label;
        info.manufacturerId = profile->tokenInfo.manufacturer;
        info.model = "PKCS#15";
        info.serialNumber =
            profile->tokenInfo.serialNumber.empty() ? "0000000000000000" : profile->tokenInfo.serialNumber;
        info.pinLabel = pin.label;
        info.flags = kCkfTokenInitialized | kCkfLoginRequired | kCkfUserPinInitialized;
        info.minPinLen = static_cast<unsigned long>(pin.minLength);
        info.maxPinLen =
            pin.hasMaxLength ? static_cast<unsigned long>(pin.maxLength) : static_cast<unsigned long>(pin.storedLength);

        slots.push_back(std::make_shared<Pkcs15Slot>(weak_from_this(), pin.id, pin.label, apdu.get(), pin,
                                                     std::move(keys), std::move(certs), std::move(info), slotId));
    }

    return Crv::Ok;
}

unsigned long Pkcs15Card::reconnectInline()
{
    using namespace LibreSCRS::Pkcs11::Internal;

    if (!conn)
        return Crv::DeviceError;

    try {
        conn->reconnect();
    } catch (...) {
        return Crv::DeviceError;
    }

    if (needsPace) {
        // Re-probe EF.CardAccess (post-reset state lost) and re-establish
        // PACE if cachedCan is still populated. If CAN was cleared the
        // caller will need to re-login to repopulate it.
        if (!probeForPace())
            return Crv::DeviceError;
        if (cachedCan.empty())
            return Crv::UserNotLoggedIn;
        if (auto rc = establishPACE(); rc != Crv::Ok)
            return rc;
    }

    apdu = std::make_unique<::pkcs15::PKCS15Card>(*conn);

    // Same CardMap fast-path as in bind(): consume any cached state for
    // this physical card before SELECT so reconnect-after-PACE picks
    // the right path/P2 without re-probing under the SM tunnel.
    if (cardMap) {
        const auto key = makeCardMapKey(readerName, conn->getATR());
        if (auto entry = cardMap->get(key)) {
            apdu->seedDiscoveredState(entry->pkcs15Path, entry->fileSelectP2);
        }
    }

    if (!apdu->selectApplet()) {
        if (!(apdu->probe() && apdu->selectApplet()))
            return Crv::FunctionFailed;
    }

    if (cardMap) {
        const auto key = makeCardMapKey(readerName, conn->getATR());
        LibreSCRS::SmartCard::CardMapEntry entry;
        entry.pkcs15Path = apdu->pkcs15PathView();
        entry.fileSelectP2 = apdu->fileSelectP2View();
        cardMap->put(key, std::move(entry));
    }

    return Crv::Ok;
}

Pkcs15PKCS11Provider::Pkcs15PKCS11Provider(std::shared_ptr<LibreSCRS::SmartCard::CardMap> cm) noexcept
    : cardMap(std::move(cm))
{}

std::shared_ptr<LibreSCRS::Pkcs11::Internal::PKCS11Card> Pkcs15PKCS11Provider::probe(const std::string& readerName)
{
    using namespace LibreSCRS::Pkcs11::Internal;

    auto card = std::make_shared<Pkcs15Card>(cardMap);
    if (auto rc = card->bind(readerName); rc != Crv::Ok)
        return nullptr;
    return card;
}

} // namespace LibreSCRS::Pkcs15::Pkcs11
