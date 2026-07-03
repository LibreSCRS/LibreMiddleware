// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

/// @file
/// @brief Concrete @ref LibreSCRS::Pkcs15::Pkcs11::Pkcs15Card backed by
///        the existing @ref pkcs15::PKCS15Card APDU helper.
///
/// Transport ownership lives on the owned @c CardSession that emits
/// per-operation @c ActiveChannelHolder instances; this class never
/// holds a raw @c PCSCConnection. PACE handshakes ride the session's
/// per-process credential cache; SM wrap/unwrap lives inside the
/// holder's @c PaceChannel rather than in a transmit-filter lambda
/// installed on the raw connection.

#include "pkcs15_pkcs11_card.h"

#include "pkcs15_card.h"
#include "pkcs15_pkcs11_slot.h"
#include "pkcs15_types.h"

#include "probe_trace.h"

#include <internal/Crv.h>
#include <internal/PKCS11TokenInfo.h>
#include <internal/PinClassification.h>
#include <internal/SlotIdHash.h>
#include <internal/SlotKindClassifier.h>

#include <LibreSCRS/Auth/PaceSecretKind.h>
#include <LibreSCRS/Secure/String.h>
#include <LibreSCRS_internal/SecureChannel/ISecureChannel.h>
#include <LibreSCRS_internal/SmartCard/SessionPresence.h>
#include <LibreSCRS_internal/SmartCard/SmartCardServices.h>
#include <LibreSCRS/SmartCard/AppletAid.h>
#include <LibreSCRS/SmartCard/CardSession.h>
#include <LibreSCRS/SmartCard/SmProtocolRequest.h>
#include <LibreSCRS/SmartCard/detail/Unwrap.h>
#include <LibreSCRS_internal/SmartCard/ActiveChannelHolderInternal.h>
#include <pcsc_connection.h>

#include <algorithm>
#include <cctype>
#include <utility>

namespace LibreSCRS::Pkcs15::Pkcs11 {

namespace {

/// @brief PKCS#11 v2.40 token-flag bits used in @ref PKCS11TokenInfo.
/// Raw values intentionally avoid pulling pkcs11t.h into this TU.
constexpr unsigned long kCkfTokenInitialized = 0x00000400UL;
constexpr unsigned long kCkfLoginRequired = 0x00000004UL;
constexpr unsigned long kCkfUserPinInitialized = 0x00000008UL;

/// @brief PKCS#15-PIN-label → @ref SlotKind via the shared classifier.
///        PKCS#15 does not encode a slot-kind concept; we infer it from
///        the PIN label so the FNV-1a slot ID is stable across reconnects.
[[nodiscard]] LibreSCRS::Pkcs11::Internal::SlotKind deriveSlotKind(const ::pkcs15::PinInfo& pin)
{
    auto label = pin.label;
    std::transform(label.begin(), label.end(), label.begin(), [](unsigned char c) { return std::tolower(c); });
    return LibreSCRS::Pkcs11::Internal::classifyFromLabel(label);
}

/// @brief Cheap reachability probe: can the card SELECT the standard
///        PKCS#15 AID without authentication? Mirrors the
///        @c pkcs15-plugin probeApplet helper.
enum class ProbeResult : std::uint8_t {
    Ok,         ///< Plain SELECT succeeded — no SM needed for this card.
    NeedsPace,  ///< Card returned 6982 — PACE must be run first.
    Unreachable ///< Other failure; treat as not-PKCS#15.
};

[[nodiscard]] ProbeResult probeApplet(LibreSCRS::SmartCard::Internal::PCSCConnection& conn)
{
    std::vector<std::uint8_t> aid(::pkcs15::kPkcs15Aid.begin(), ::pkcs15::kPkcs15Aid.end());
    auto aidResp = conn.transmit(LibreSCRS::SmartCard::Internal::selectByAID(aid, 0x0C));
    if (aidResp.isSuccess())
        return ProbeResult::Ok;
    if (aidResp.sw1 == 0x69 && aidResp.sw2 == 0x82)
        return ProbeResult::NeedsPace;
    return ProbeResult::Unreachable;
}

/// @brief Translate a channel-activation failure to a PKCS#11
///        @c CKR_* code on the @ref Crv numeric domain. PACE-secret
///        failures map to @c PinIncorrect / @c PinLocked so the
///        consumer's normal "wrong PIN, try again" flow handles them
///        without divergence from non-PACE cards.
[[nodiscard]] unsigned long mapHolderErrorToCrv(LibreSCRS::SecureChannel::ChannelActivationError err) noexcept
{
    using namespace LibreSCRS::Pkcs11::Internal;
    using Err = LibreSCRS::SecureChannel::ChannelActivationError;
    switch (err) {
    case Err::WrongSecret:
    case Err::CredentialsRequired:
        return Crv::PinIncorrect;
    case Err::PacePinBlocked:
        return Crv::PinLocked;
    case Err::CardRemoved:
        return Crv::TokenNotPresent;
    case Err::Cancelled:
    case Err::UserCancelled:
        return Crv::Cancel;
    case Err::SelectAppletFailed:
    case Err::PaceUnsupported:
    case Err::ProtocolFailure:
    case Err::ReaderError:
    case Err::Internal:
    case Err::ReentrantAccess:
    case Err::None:
    default:
        return Crv::DeviceError;
    }
}

[[nodiscard]] LibreSCRS::SmartCard::AppletAid pkcs15AppletAid()
{
    return LibreSCRS::SmartCard::AppletAid::fromBytes(
        std::span<const std::uint8_t>{::pkcs15::kPkcs15Aid.data(), ::pkcs15::kPkcs15Aid.size()});
}

} // namespace

using LibreSCRS::Pkcs15::Internal::isUserPin;

Pkcs15Card::Pkcs15Card(std::shared_ptr<LibreSCRS::SmartCard::CardMap> cm) : cardMap(std::move(cm)) {}

Pkcs15Card::~Pkcs15Card() = default;

void Pkcs15Card::onCachedCanChanged() noexcept
{
    if (!session)
        return;
    if (cachedCan.empty()) {
        // Wipe both the legacy field (already cleared by parentClearCan
        // before this hook fires) and the session-owned cache so the
        // next acquireChannel does not race a stale secret.
        session->clearCachedPaceCredentials();
        return;
    }
    // Mirror the cleansing-string contract: take a fresh copy that the
    // session will own (it cleanses on slot replacement). Hot-path; never
    // log the value and never widen the borrow beyond this stack frame.
    session->setPaceSecret(LibreSCRS::Auth::PaceSecretKind::Can, LibreSCRS::Secure::String{cachedCan.view()});
}

std::expected<LibreSCRS::SmartCard::ActiveChannelHolder, LibreSCRS::SecureChannel::ChannelActivationError>
Pkcs15Card::acquireChannel(LibreSCRS::CancelToken token)
{
    if (!session)
        return std::unexpected(LibreSCRS::SecureChannel::ChannelActivationError::Internal);
    auto aid = pkcs15AppletAid();
    if (needsPace) {
        return session->activateChannelWithSm(
            aid, LibreSCRS::SmartCard::PaceRequest{LibreSCRS::Auth::PaceSecretKind::Can}, std::move(token));
    }
    return session->activateChannelFor(aid, std::move(token));
}

unsigned long Pkcs15Card::readProfileAndComplete(LibreSCRS::SmartCard::ActiveChannelHolder& holder)
{
    using namespace LibreSCRS::Pkcs11::Internal;

    auto* channel = LibreSCRS::SmartCard::Internal::HolderChannelAccessor::channel(holder);
    if (channel == nullptr)
        return Crv::DeviceError;

    ::pkcs15::PKCS15Card apdu(*channel);
    try {
        LibreSCRS::Internal::probeTrace("PROBE-READPROFILE call=pkcs11-card-init");
        profile = std::make_unique<::pkcs15::PKCS15Profile>(apdu.readProfile());
        if (std::getenv("LIBRESCRS_SIGN_TRACE"))
            std::fprintf(stderr, "[PKCS15Card::readProfileAndComplete] pins=%zu keys=%zu certs=%zu\n",
                         profile->pins.size(), profile->privateKeys.size(), profile->certificates.size());
        if (profile->pins.empty() && profile->privateKeys.empty() && profile->certificates.empty()) {
            // Empty profile means the applet refuses directory reads
            // pre-login. Fall through to deferred-profile mode so the
            // first authenticated operation can populate slot state.
            if (std::getenv("LIBRESCRS_SIGN_TRACE"))
                std::fprintf(stderr, "[PKCS15Card::readProfileAndComplete] empty profile -> deferred fallback\n");
            profile.reset();
            needsDeferredProfile = true;
        }
    } catch (const std::exception& e) {
        if (std::getenv("LIBRESCRS_SIGN_TRACE"))
            std::fprintf(stderr, "[PKCS15Card::readProfileAndComplete] readProfile threw: %s\n", e.what());
        // readProfile threw — treat as deferred-profile mode rather than
        // a hard failure. Some applets return non-PKCS#15 payloads
        // (e.g. a literal authenticate-first prompt) for every structural
        // read, which surfaces as a parser exception here.
        profile.reset();
        needsDeferredProfile = true;
    } catch (...) {
        if (std::getenv("LIBRESCRS_SIGN_TRACE"))
            std::fprintf(stderr, "[PKCS15Card::readProfileAndComplete] readProfile threw non-std exception\n");
        profile.reset();
        needsDeferredProfile = true;
    }

    return completeBind();
}

unsigned long Pkcs15Card::bind(const std::string& reader)
{
    using namespace LibreSCRS::Pkcs11::Internal;

    std::scoped_lock lock(cardMutex);

    readerName = reader;

    auto sessionResult = LibreSCRS::SmartCard::CardSession::open(reader);
    if (!sessionResult)
        return Crv::TokenNotPresent;
    session = std::make_shared<LibreSCRS::SmartCard::CardSession>(std::move(*sessionResult));
    // Re-deposit any pre-bind cachedCan into the freshly-opened session
    // (e.g. when bind is invoked after setCredentials seeded the field).
    onCachedCanChanged();

    // Cheap reachability probe over the borrowed connection: SELECT-AID
    // tells us non-PACE-OK / PACE-required / not-PKCS#15 in one shot.
    // Holders are the long-term transport but the probe is one-shot, so
    // a transient untransacted SELECT is normally fine here.
    //
    // The plain-SELECT path is, however, illegal when the session already
    // carries a live SM channel: PACE SM is session-scoped per BSI
    // TR-03110 §3, so a non-wrapped APDU resets the card-side PACE SM
    // context, breaking the next wrapped APDU with 6987/6988 and forcing
    // a full rehandshake. A PACE channel once established MUST NOT be
    // torn down by plain APDUs. Skip the probe and assume the SM-required
    // disposition; the subsequent acquireChannel() will reuse the live
    // channel.
    ProbeResult state;
    if (session->hasLiveSecureChannel()) {
        state = ProbeResult::NeedsPace;
    } else {
        auto& conn = LibreSCRS::SmartCard::detail::unwrap(*session);
        state = probeApplet(conn);
    }
    if (state == ProbeResult::Unreachable)
        return Crv::TokenNotPresent;
    if (state == ProbeResult::NeedsPace)
        needsPace = true;

    // PACE-required card without cached CAN: publish a single placeholder
    // slot with CKF_LOGIN_REQUIRED so PKCS#11 consumers see the card
    // before the user enters their CAN. The slot's first
    // Pkcs15Slot::login parses CAN-in-PIN, calls resumeBind() to drive
    // PACE + applet select + readProfile, then populates its own keys /
    // certs from the resulting profile. The slot self-transforms (no
    // slot-vector swap) so any CK_SLOT_ID already published to the
    // consumer stays valid across login.
    if (needsPace && cachedCan.empty()) {
        PKCS11TokenInfo placeholder;
        placeholder.label = "PACE access required";
        placeholder.manufacturerId = "";
        placeholder.model = "PKCS#15";
        placeholder.serialNumber = "0000000000000000";
        placeholder.pinLabel = "CAN";
        // No CKF_USER_PIN_INITIALIZED: the placeholder slot has no user
        // PIN — only awaits a CAN. PKCS#11 v2.40 §3.2 reserves that flag
        // for tokens with an initialised user PIN; consumers filtering on
        // it must not see the placeholder as ready-to-sign.
        placeholder.flags = kCkfTokenInitialized | kCkfLoginRequired;
        placeholder.minPinLen = 4;
        placeholder.maxPinLen = 32;

        std::vector<std::uint8_t> placeholderPinId{};
        unsigned long slotId =
            static_cast<unsigned long>(computeSlotId(readerName, placeholderPinId, SlotKind::Generic));

        slots.push_back(
            std::make_shared<Pkcs15Slot>(weak_from_this(), std::string{"CAN"}, std::move(placeholder), slotId));
        placeholderState = true;
        return Crv::Ok;
    }

    // Eager bind: acquire a holder, read the profile under its scope, and
    // hand off to completeBind(). The holder destroys at scope exit; the
    // session retains derived PACE keys for future per-op acquisitions.
    auto holderResult = acquireChannel();
    if (!holderResult)
        return mapHolderErrorToCrv(holderResult.error());
    auto holder = std::move(*holderResult);
    return readProfileAndComplete(holder);
}

unsigned long Pkcs15Card::bindFromInjectedSession(const std::string& reader,
                                                  std::shared_ptr<LibreSCRS::SmartCard::CardSession> injected)
{
    using namespace LibreSCRS::Pkcs11::Internal;

    if (!injected)
        return Crv::ArgumentsBad;

    std::scoped_lock lock(cardMutex);

    readerName = reader;
    session = std::move(injected);

    // Adopt the host's existing CardSession rather than opening a parallel
    // PC/SC handle. The injected session may already carry a live PACE SM
    // context from the host's display flow; activateChannelWithSm's fast
    // paths (same applet / wrapped SELECT) preserve that tunnel without
    // emitting any plain APDU on the wire. Plain SELECT on a card with
    // live SM card-side returns 6984 on the next wrapped APDU.
    //
    // SM-first probe order: activateChannelWithSm hits the fast path for
    // an adopted session with a live PaceChannel; for a session with a
    // warm PACE cache but no live channel, it runs the full handshake;
    // for a non-PACE card or one without deposited credentials, the
    // preflight returns CredentialsRequired cheaply and we fall through.
    {
        auto holderResult = session->activateChannelWithSm(
            pkcs15AppletAid(), LibreSCRS::SmartCard::PaceRequest{LibreSCRS::Auth::PaceSecretKind::Can},
            LibreSCRS::CancelToken{});
        if (holderResult) {
            needsPace = true;
            // Mirror "CAN cached somewhere" into cachedCan so Pkcs15Slot::login
            // does not require the CAN-in-PIN colon syntax at C_Login. The
            // marker is intentionally not the real CAN — direct field
            // assignment bypasses parentCacheCan so the onCachedCanChanged
            // hook does not fire and overwrite the session's authoritative
            // copy. Slot dispatch only checks emptiness, never reads value.
            cachedCan = LibreSCRS::Secure::String{"\x01"};
            return readProfileAndComplete(*holderResult);
        }
        if (holderResult.error() != LibreSCRS::SecureChannel::ChannelActivationError::CredentialsRequired)
            return mapHolderErrorToCrv(holderResult.error());
    }

    // Fall-through: plain activation. Reaches the fast path when the
    // injected session has a live PlainChannel on the target applet
    // (no wire I/O). On 6982 from the card (PACE-required), surface as
    // PinIncorrect so the consumer re-prompts.
    auto holderResult = session->activateChannelFor(pkcs15AppletAid(), LibreSCRS::CancelToken{});
    if (holderResult) {
        return readProfileAndComplete(*holderResult);
    }
    if (holderResult.error() == LibreSCRS::SecureChannel::ChannelActivationError::SelectAppletFailed) {
        needsPace = true;
        return Crv::PinIncorrect;
    }
    return mapHolderErrorToCrv(holderResult.error());
}

unsigned long Pkcs15Card::resumePostCan()
{
    return resumeBind();
}

unsigned long Pkcs15Card::resumeBind()
{
    using namespace LibreSCRS::Pkcs11::Internal;

    // Caller (Pkcs15Slot::login on a placeholder slot) holds cardMutex.
    if (!session)
        return Crv::DeviceError;

    auto onFailure = [this](unsigned long rc) -> unsigned long {
        // Cleanse the cached CAN: leaving it would let a future login on
        // this placeholder slot skip CAN-in-PIN parsing while the session
        // has wiped its PACE cache, deadlocking the slot in a permanent
        // DeviceError loop. The session-side mirror is updated through the
        // onCachedCanChanged hook fired by parentClearCan; we trigger it
        // explicitly here because resumeBind callers already hold
        // cardMutex but did not route through parentClearCan.
        cachedCan.clear();
        onCachedCanChanged();
        return rc;
    };

    auto holderResult = acquireChannel();
    if (!holderResult)
        return onFailure(mapHolderErrorToCrv(holderResult.error()));
    auto holder = std::move(*holderResult);
    auto* channel = LibreSCRS::SmartCard::Internal::HolderChannelAccessor::channel(holder);
    if (channel == nullptr)
        return onFailure(Crv::DeviceError);

    ::pkcs15::PKCS15Card apdu(*channel);
    try {
        LibreSCRS::Internal::probeTrace("PROBE-READPROFILE call=pkcs11-card-rebind");
        profile = std::make_unique<::pkcs15::PKCS15Profile>(apdu.readProfile());
        if (profile->pins.empty() && profile->privateKeys.empty() && profile->certificates.empty()) {
            // Same fallback as bind(): treat empty profile as
            // deferred-profile mode. Distinct from placeholderState.
            profile.reset();
            needsDeferredProfile = true;
        }
    } catch (...) {
        // readProfile fallback to deferred-profile mode is correct, not a
        // hard failure — keep PACE secrets warm so the subsequent
        // deferred-profile PIN verify rides the same channel.
        profile.reset();
        needsDeferredProfile = true;
    }

    // Sentinel reset: subsequent login()s on the same placeholder slot
    // skip the CAN-parsing branch. The slot vector is NOT modified —
    // the placeholder slot self-transforms inside Pkcs15Slot::login.
    placeholderState = false;
    return Crv::Ok;
}

unsigned long Pkcs15Card::establishPACE()
{
    using namespace LibreSCRS::Pkcs11::Internal;

    if (!session || cachedCan.empty())
        return Crv::FunctionFailed;

    // Validate the deposited CAN by attempting a holder acquisition.
    // The session caches the derived SM keys on success so subsequent
    // per-op holders fast-path through the same-applet / wrapped-SELECT
    // path rather than re-running the PACE handshake.
    auto holderResult = acquireChannel();
    if (!holderResult)
        return mapHolderErrorToCrv(holderResult.error());
    return Crv::Ok;
}

unsigned long Pkcs15Card::completeBind()
{
    using namespace LibreSCRS::Pkcs11::Internal;

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

        slots.push_back(std::make_shared<Pkcs15Slot>(weak_from_this(), pin.id, pin.label, pin, std::move(keys),
                                                     std::move(certs), std::move(info), slotId));
    }

    return Crv::Ok;
}

unsigned long Pkcs15Card::reconnectInline()
{
    using namespace LibreSCRS::Pkcs11::Internal;

    // Tear down the session (releases the PC/SC handle, drops the PACE
    // cache) and reopen against the same reader. The card-side context
    // was lost on RESET so any prior SM keys are useless anyway.
    session.reset();

    auto sessionResult = LibreSCRS::SmartCard::CardSession::open(readerName);
    if (!sessionResult)
        return Crv::DeviceError;
    session = std::make_shared<LibreSCRS::SmartCard::CardSession>(std::move(*sessionResult));

    // Re-deposit cachedCan into the fresh session so PACE-gated cards
    // can re-PACE on the next per-op acquireChannel.
    onCachedCanChanged();

    if (needsPace) {
        if (cachedCan.empty())
            return Crv::UserNotLoggedIn;
        // Validate that PACE works on the freshly-opened session; the
        // derived SM keys land in the session's cache for subsequent ops.
        auto holderResult = acquireChannel();
        if (!holderResult)
            return mapHolderErrorToCrv(holderResult.error());
    }

    return Crv::Ok;
}

Pkcs15PKCS11Provider::Pkcs15PKCS11Provider(std::shared_ptr<LibreSCRS::SmartCard::CardMap> cm,
                                           LibreSCRS::SmartCard::Internal::SessionPresence& sp) noexcept
    : cardMap(std::move(cm)), sessionPresence(sp)
{}

std::shared_ptr<LibreSCRS::Pkcs11::Internal::PKCS11Card> Pkcs15PKCS11Provider::probe(const std::string& readerName)
{
    using namespace LibreSCRS::Pkcs11::Internal;

    // Adopt-or-bind: if SessionPresence has a live CardSession for this
    // reader (the host's display flow established PACE there), adopt it
    // via bindFromInjectedSession so the sign path reuses the existing
    // SM tunnel rather than opening a parallel PC/SC handle (which would
    // tear down the card-side SM context — BSI TR-03110 §3, session-
    // scoped SM). Fresh bind runs only when no presence entry exists.
    //
    // The registry is the ctor-injected `sessionPresence` (not the global
    // accessor): the caller owns its lifecycle (ensureSessionPresenceInitialised)
    // so this peek-before-bind contract is unit-testable with a local instance.
    auto card = std::make_shared<Pkcs15Card>(cardMap);

    if (auto existing = sessionPresence.peek(readerName)) {
        if (auto rc = card->bindFromInjectedSession(readerName, std::move(existing)); rc != Crv::Ok)
            return nullptr;
        return card;
    }
    if (auto rc = card->bind(readerName); rc != Crv::Ok)
        return nullptr;
    return card;
}

} // namespace LibreSCRS::Pkcs15::Pkcs11
