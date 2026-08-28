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
#include <string>
#include <string_view>

#include <LibreSCRS/CancelToken.h>
#include <LibreSCRS/Plugin/PluginTypes.h>
#include <LibreSCRS/Plugin/ReadResult.h>
#include <LibreSCRS/SecureChannel/ChannelErrors.h>

#include <libopensc/opensc.h>
#include <libopensc/pkcs15.h>

#include "opensc_reader_bridge.h"
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
