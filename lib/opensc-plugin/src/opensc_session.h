// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware (opensc-plugin)."
#endif

#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>

#include <LibreSCRS/CancelToken.h>
#include <LibreSCRS/Plugin/PluginTypes.h>
#include <LibreSCRS/Plugin/ReadResult.h>
#include <LibreSCRS/Secure/String.h>
#include <LibreSCRS/SecureChannel/ChannelErrors.h>

#include <libopensc/opensc.h>
#include <libopensc/pkcs15.h>

#include "opensc_reader_bridge.h"
#include "opensc_user_consent.h"
#include "pin_family_quirks.h" // FamilyId

namespace LibreSCRS::SmartCard {
class CardSession;
}

namespace LibreSCRS::SecureChannel {
class ISecureChannel;
}

namespace LibreSCRS::SmartCard::Internal {
struct APDUCommand;
struct APDUResponse;
} // namespace LibreSCRS::SmartCard::Internal

namespace LibreSCRS::OpenSc {

/// Per-session OpenSC binding state. Held in the plugin's session map as
/// @c std::shared_ptr<OpenSCSession>: an operation pins the pointer under the
/// plugin's map mutex and releases that mutex BEFORE any I/O or activation, so
/// a concurrent probe/clearCredentials erase only removes the map entry — the
/// LAST shared_ptr owner (possibly the in-flight operation) runs the teardown.
///
/// Non-copyable and non-movable: after @c sc_connect_card the libopensc card
/// holds @c card->reader = &bridge->reader, and the per-session @ref opMutex
/// must never change address while an operation may be blocked on it.
struct OpenSCSession
{
    OpenSCSession() = default;
    ~OpenSCSession() noexcept
    {
        release();
    }

    OpenSCSession(const OpenSCSession&) = delete;
    OpenSCSession& operator=(const OpenSCSession&) = delete;
    OpenSCSession(OpenSCSession&&) = delete;
    OpenSCSession& operator=(OpenSCSession&&) = delete;

    sc_context_t* ctx = nullptr;
    sc_card_t* card = nullptr;
    sc_pkcs15_card_t* p15card = nullptr;
    std::string readerName;
    bool hasPKI = false;

    /// True when the probe deferred the bind behind a PACE gate: every
    /// operation then activates a secure channel through CardSession first
    /// and binds (once) UNDER the active holder.
    bool requiresPace = false;

    /// True while @ref card / @ref p15card are live. The raw (CardEdge) path
    /// binds at probe time; the deferred-PACE path binds inside
    /// @ref runUnderChannel.
    bool bound = false;

    /// Serialises libopensc calls against THIS session. Non-recursive by
    /// design: a credential-provider callback must never synchronously invoke
    /// another plugin operation on the same session (see the debug assert in
    /// @ref runUnderChannel).
    std::mutex opMutex;

    /// The PIN a host deposited with CardPlugin::setCredentials("pin") for the
    /// next key operation on this session. Presented to the card inside that
    /// operation's own card transaction (verifyThenRun), never in a separate
    /// call. Empty when none is deposited.
    /// @guarded_by opMutex
    LibreSCRS::Secure::String operationPin;

    /// Single-session bridge: owns the librescrs-bridge sc_reader + its
    /// private data at a stable heap address. Holds no PC/SC connection of
    /// its own — it routes libopensc through the LM PCSCConnection (raw
    /// branch) or through a live secure channel (tunnel branch).
    std::unique_ptr<LibreSCRS::OpenSc::Bridge::OpenScBridge> bridge;

    /// Partial teardown: tears down ONLY @ref p15card (unbind) and @ref card
    /// (disconnect through the bridge — zero PC/SC calls); @ref ctx and
    /// @ref bridge SURVIVE, so the next operation re-activates and re-binds
    /// over the same context — @c sc_establish_context is never called in an
    /// operation or in recovery.
    void resetCardState() noexcept;

private:
    /// Full teardown (destructor): partial teardown, then context + bridge.
    void release() noexcept;
};

/// Walk @c ctx->card_drivers for a driver whose @c short_name equals
/// @p shortName. Deferred-PACE claims are gated on the srbeid2 driver being
/// present — otherwise the claim would consume a CAN prompt only for the
/// bind to fail without a driver.
[[nodiscard]] bool driverPresent(const sc_context_t* ctx, std::string_view shortName) noexcept;

/// Resolve the on-card key object addressed by @p keyReference among the
/// enumerated PRKEY objects, restricted to @p keyType (the PKCS#15 object
/// type matching the requested mechanism family — e.g.
/// @c SC_PKCS15_TYPE_PRKEY_RSA for RSA_PKCS, @c SC_PKCS15_TYPE_PRKEY_EC for
/// the ECDSA mechanisms). Key references are only unique WITHIN a key
/// family on some cards, so an unfiltered reference lookup could address an
/// RSA key with an ECDSA request (or vice versa) when the references
/// collide.
[[nodiscard]] sc_pkcs15_object_t* selectKeyByReferenceAndType(sc_pkcs15_object_t* const* keyObjs, int keyCount,
                                                              std::uint16_t keyReference,
                                                              unsigned int keyType) noexcept;

/// Advertised key size: RSA reports @c modulus_length, EC reports
/// @c field_length; exactly one of the two is non-zero on a parsed PrKDF
/// entry.
[[nodiscard]] std::uint16_t keySizeBitsFromKeyInfo(const sc_pkcs15_prkey_info_t& keyInfo) noexcept;

/// ECDSA signature buffer length for a key over a @p fieldLengthBits-bit
/// field: EXACTLY 2*ceil(field/8) bytes (96 for P-384). libopensc's
/// sc_asn1_sig_value_sequence_to_rs zeroes the WHOLE buffer and
/// right-aligns r and s into its halves, so the buffer must never be sized
/// from an RSA idiom (modulus_length/8) nor resized from the driver's
/// return count — the output is the canonical fixed-width r||s.
[[nodiscard]] std::size_t ecdsaSignatureLength(std::size_t fieldLengthBits) noexcept;

/// sc_pkcs15_bind with OpenSC's own PIN cache switched off. OpenSC keeps
/// every PIN a successful sc_pkcs15_verify_pin presented and replays it when
/// the card later wants it again; a PIN given to this plugin -- deposited for
/// one operation, or passed to verifyPIN -- is used for that call only and
/// must not outlive it inside OpenSC.
/// @return The sc_pkcs15_bind result.
[[nodiscard]] int bindWithoutPinCache(sc_card_t* card, sc_pkcs15_card_t** p15card) noexcept;

/// The order every key operation keeps inside runUnderChannel: VERIFY the
/// deposited per-operation @p pin, then @p operation -- in ONE card
/// transaction, because runUnderChannel holds it across the whole callback.
/// A key that wants its PIN per operation (PIV 9C) loses the verified state
/// across two calls; inside one transaction there is nothing between them.
/// @param pin          Deposited PIN; empty = nothing to present.
/// @param perOperation  The key wants its PIN for every operation (see
///                      requiresPerOperationAuth). Without a deposited PIN such
///                      a key's operation does not run: nothing reaches the
///                      card. Any other key runs as it always has.
/// @param verify        Presents the PIN; returns an OpenSC code (SC_SUCCESS = verified).
/// @param operation     The card operation; runs only after a successful VERIFY.
/// @return SC_SUCCESS when the operation ran; SC_ERROR_SECURITY_STATUS_NOT_SATISFIED
///         when a per-operation key had no PIN; otherwise the code @p verify
///         returned. In both failure cases the operation did not run.
template <typename Verify, typename Operation>
[[nodiscard]] int verifyThenRun(const LibreSCRS::Secure::String& pin, bool perOperation, Verify&& verify,
                                Operation&& operation)
{
    if (!pin.empty()) {
        const int rc = verify(pin);
        if (rc != SC_SUCCESS)
            return rc;
    } else if (perOperation) {
        return SC_ERROR_SECURITY_STATUS_NOT_SATISFIED;
    }
    operation();
    return SC_SUCCESS;
}

/// A key operation that did not run because of its PIN: the card's answer to
/// VERIFY of the deposited PIN, or SC_ERROR_SECURITY_STATUS_NOT_SATISFIED when
/// a per-operation key had none.
struct RefusedPin
{
    int rc = SC_SUCCESS;
};

/// Present the PIN deposited on @p session to the PIN object guarding
/// @p key, then run @p operation -- both inside the caller's
/// runUnderChannel callback, so in one card transaction. With no PIN
/// deposited, @p operation runs unchanged for an ordinary key and not at all
/// for a key the card wants the PIN for per operation. A key no PIN guards
/// (an empty auth_id: the PIV Card Authentication key, 9E; a PrKDF entry
/// without an authId) runs without a VERIFY whether or not a PIN is
/// deposited -- there is no PIN object to present it to, and OpenSC's own
/// C_Sign presents none. The deposit stays where the host put it, for its
/// next operation with a guarded key.
/// @return std::nullopt when @p operation ran; otherwise why it did not.
template <typename Operation>
[[nodiscard]] std::optional<RefusedPin> verifyDepositedPinThenRun(OpenSCSession& session, const sc_pkcs15_object_t& key,
                                                                  Operation&& operation)
{
    if (key.auth_id.len == 0 && !requiresPerOperationAuth(key)) {
        // No PIN object guards this key: a lookup by its empty auth_id finds
        // none, so a VERIFY here could only refuse an operation the card
        // runs without one.
        operation();
        return std::nullopt;
    }
    sc_pkcs15_object_t* pinObject = nullptr;
    auto verify = [&](const LibreSCRS::Secure::String& pin) {
        if (sc_pkcs15_find_pin_by_auth_id(session.p15card, &key.auth_id, &pinObject) != SC_SUCCESS ||
            pinObject == nullptr)
            return SC_ERROR_OBJECT_NOT_FOUND;
        const auto view = pin.view();
        return sc_pkcs15_verify_pin(session.p15card, pinObject, reinterpret_cast<const unsigned char*>(view.data()),
                                    view.size());
    };
    const int rc = verifyThenRun(session.operationPin, requiresPerOperationAuth(key), verify, operation);
    if (rc == SC_SUCCESS)
        return std::nullopt;
    return RefusedPin{rc};
}

/// The outcome a key operation reports when VERIFY of its deposited PIN
/// failed with @p rc. The card's verdict on the PIN is
/// read exactly as the OpenSC PKCS#11 slot reads it: a wrong PIN is
/// PinIncorrect, a blocked one PinBlocked, and every failure the PIN did not
/// cause stays PluginError.
[[nodiscard]] LibreSCRS::Plugin::SignResultOutcome signOutcomeForRefusedPin(int rc) noexcept;
/// @copydoc signOutcomeForRefusedPin
[[nodiscard]] LibreSCRS::Plugin::DecipherResultOutcome decipherOutcomeForRefusedPin(int rc) noexcept;

/// Maps libopensc's resolved card-driver identity to a quirk-table family.
/// Uses only the driver short_name that sc_connect_card already resolved —
/// no ATR probing or new detection; unrecognised drivers stay Unknown.
[[nodiscard]] LibreSCRS::Plugin::Internal::FamilyId familyFromDriverShortName(const char* shortName) noexcept;

/// EF.DIR content gate for the deferred-PACE claim: SELECT MF → SELECT
/// EF.DIR → READ BINARY to EOF (SW 6282 counts as success; chunks are
/// CONCATENATED before the search), all through @p transmit (wrapped or
/// raw — both probe paths share this shape; every SELECT is P2=0C without
/// Le). Returns true iff EF.DIR was readable AND advertises the
/// AppletSuiteGen2 AID prefix @c F3 81 00 00 02. An unreadable EF.DIR
/// declines conservatively — the generic pkcs15 plugin stays the fallback.
[[nodiscard]] bool efDirAdvertisesAppletSuiteGen2(const std::function<LibreSCRS::SmartCard::Internal::APDUResponse(
                                                      const LibreSCRS::SmartCard::Internal::APDUCommand&)>& transmit);

/// What @ref runUnderChannel observed. The operation combines this with its
/// own completion flag to produce the typed per-operation outcome; the
/// channel-run itself never invents operation results.
struct ChannelRunReport
{
    /// Channel activation failed; @ref activationError holds the reason.
    /// The session state is untouched (no resetCardState — nothing leaked;
    /// a still-bound session stays bound and the next operation simply
    /// re-activates over the same ctx/bridge).
    bool activationFailed = false;
    LibreSCRS::SecureChannel::ChannelActivationError activationError =
        LibreSCRS::SecureChannel::ChannelActivationError::None;

    /// Deferred bind (sc_connect_card + sc_pkcs15_bind) failed;
    /// @ref OpenSCSession::resetCardState already ran.
    bool bindFailed = false;

    /// The operation token was cancelled by the time the run finished. A
    /// COMPLETED operation still reports its real result; the caller maps
    /// cancellation to a typed Cancelled outcome only when the operation did
    /// not complete.
    bool cancelled = false;

    /// The secure channel left ChannelState::Open during the run (judged by
    /// STATE, never by SW pattern); @ref OpenSCSession::resetCardState
    /// already ran and the next operation re-activates (re-PACE) + re-binds.
    bool channelFatal = false;

    /// @c fn was invoked (activation and bind both succeeded).
    bool ran = false;
};

/// Run @p fn with the session's bridge routed through the channel this
/// session requires (live/PACE secure channel when @ref
/// OpenSCSession::requiresPace, raw branch otherwise), performing the
/// deferred bind under the active holder when needed. Serialises on
/// @ref OpenSCSession::opMutex. Activation goes through
/// @c CardSession::activateChannelWithSm (riding the live protocol when one
/// exists, PACE-CAN otherwise); the acquired holder spans the whole
/// libopensc call and the post-activation phase is @ref runWithChannelPtr.
[[nodiscard]] ChannelRunReport runUnderChannel(LibreSCRS::SmartCard::CardSession& cardSession, OpenSCSession& s,
                                               LibreSCRS::CancelToken token,
                                               const std::function<void(OpenSCSession&)>& fn);

/// Post-activation phase of @ref runUnderChannel, split out (ChangePinFn
/// seam precedent) so the bind/verdict/teardown mechanism is drivable with a
/// scripted channel double and no live PACE handshake: installs @p channel
/// (may be nullptr — the raw branch) plus @p token on the bridge, performs
/// the deferred bind when the session is not bound, invokes @p fn, then in
/// this exact order: reads the cancel token, judges fatality BY CHANNEL
/// STATE (never by SW pattern), clears the bridge channel/token, calls
/// @p releaseChannel (the production holder's RAII release), and finally
/// runs the partial teardown when the channel died or the bind failed.
/// Callers own the @ref OpenSCSession::opMutex serialisation.
[[nodiscard]] ChannelRunReport runWithChannelPtr(OpenSCSession& s, LibreSCRS::SecureChannel::ISecureChannel* channel,
                                                 LibreSCRS::CancelToken token,
                                                 const std::function<void(OpenSCSession&)>& fn,
                                                 const std::function<void()>& releaseChannel);

// Activation-error vocabulary, bound per operation-result type to the
// EXISTING LM outcome values (no new types). PIN and cancel outcomes are
// never collapsed into a generic plugin error: cancellation stays a typed
// cancelled outcome on every surface that has one, and PIN classification
// (InvalidPin/Blocked) is produced only by the card verbs themselves.

/// read-operation surface (doReadCard). Cancelled/UserCancelled →
/// ReadResult::cancelled(); CredentialsRequired / PaceWrongSecret →
/// authenticationFailed; transport-class errors → communicationError.
[[nodiscard]] LibreSCRS::Plugin::ReadResult
mapActivationErrorToReadResult(LibreSCRS::SecureChannel::ChannelActivationError err, const char* what);

/// PIN-operation surface (verifyPIN/changePIN). Cancelled/UserCancelled →
/// UserCancelled; CredentialsRequired → MissingFields (the required
/// credential was absent); everything else → PluginError.
[[nodiscard]] LibreSCRS::Plugin::PINResultOutcome
mapActivationErrorToPinOutcome(LibreSCRS::SecureChannel::ChannelActivationError err) noexcept;

/// Signing surface (doSign). Cancelled/UserCancelled → Cancelled;
/// everything else → PluginError.
[[nodiscard]] LibreSCRS::Plugin::SignResultOutcome
mapActivationErrorToSignOutcome(LibreSCRS::SecureChannel::ChannelActivationError err) noexcept;

/// Decipher surface (doDecipher). Cancelled/UserCancelled → Cancelled;
/// everything else → PluginError.
[[nodiscard]] LibreSCRS::Plugin::DecipherResultOutcome
mapActivationErrorToDecipherOutcome(LibreSCRS::SecureChannel::ChannelActivationError err) noexcept;

} // namespace LibreSCRS::OpenSc
