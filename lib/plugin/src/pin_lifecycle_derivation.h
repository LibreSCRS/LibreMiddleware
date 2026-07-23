// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware."
#endif

#pragma once

/// @file
/// @brief Credential-lifecycle derivation engine: combines per-object card
///        evidence with the static family quirk table into a fully
///        populated @ref LibreSCRS::Plugin::PinStatusEntry.
///
/// Precedence is quirks → evidence → conservative defaults, and the result
/// can only narrow, never overclaim: a capability (unblock, change,
/// activation) is advertised only when the evidence supports it AND the
/// family row carries verified knowledge of the command form.
///
/// LIBRESCRS_INTERNAL: not part of public API.

#include <LibreSCRS/Plugin/PinStatusEntry.h>

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace LibreSCRS::Plugin::Internal {

struct FamilyQuirks; // defined in pin_family_quirks.h

/// @brief Evidence extracted from PKCS#15 AODF (or driver equivalents) for
///        ONE auth object.
///
/// Plugin-agnostic: both pkcs15-plugin and opensc-plugin fill it from
/// their own parsed structures.
///
/// @par Chain-resolution contract
/// The CALLER resolves the AODF authId protection chain while filling the
/// evidence set: when this object is unblocked/protected by another auth
/// object, the caller sets @ref authIdChainTarget to that object's FULL
/// id bytes AND sets @ref unblockingPinFlag on the resolved target's own
/// evidence entry. The derivation locates the chain target as the entry
/// whose @ref ownId equals the recorded bytes — never "the first
/// unblocker" — so profiles carrying several unblockers resolve each PIN
/// against its own PUK.
struct PinEvidence
{
    std::string label;
    std::uint8_t reference = 0;
    /// @brief This auth object's own AODF object id bytes
    ///        (CommonAuthObjectAttributes id; libopensc
    ///        @c sc_pkcs15_auth_info.auth_id). Lets the derivation match
    ///        another entry's @ref authIdChainTarget to THIS entry.
    ///        Empty when the card exposes no object id.
    std::vector<std::uint8_t> ownId;
    bool localScope = false; ///< AODF local flag.
    bool inQscdDf = false;   ///< Object path points into the signature DF.
    bool soPinFlag = false;
    bool unblockingPinFlag = false; ///< Set by the caller on a resolved chain target.
    bool unblockDisabledFlag = false;
    bool changeDisabledFlag = false;
    bool initialized = true;
    bool blocked = false;
    /// @brief The card uses PACE and this object has the CAN shape. Set by
    ///        the caller as (session-required-PACE OR family-uses-PACE) AND
    ///        the AODF change-disabled + unblock-disabled flags. Gates the CAN
    ///        kind, which additionally excludes SO/unblocking objects.
    bool paceEvidence = false;
    /// @brief FULL id bytes of the protecting auth object; see the
    ///        chain-resolution contract in the struct documentation.
    std::optional<std::vector<std::uint8_t>> authIdChainTarget;
    /// @brief Driver-reported "PIN must be changed before use" signal
    ///        (e.g. the libopensc SC_PIN_STATE_NEEDS_CHANGE pin-state bit).
    bool needsChangeSignal = false;
};

/// @brief Derives kind/state/capabilities for one credential.
///
/// Precedence: quirks → evidence → conservative defaults. @p allEvidence
/// lets the PUK-presentability rule resolve the protecting PUK's own
/// state/budget (per the chain-resolution contract on @ref PinEvidence).
/// @p quirks may be nullptr (family unknown): nothing beyond
/// evidence-derived kind/state is advertised then.
[[nodiscard]] PinStatusEntry derivePinStatus(const PinEvidence& e, const std::vector<PinEvidence>& allEvidence,
                                             const FamilyQuirks* quirks);

/// @brief Resolved RESET RETRY COUNTER P1 + on-wire data shape for one
///        unblock attempt.
///
/// Extracted from pkcs15-plugin's @c unblockPIN override (Task 11 review
/// fix) so the style→(P1, data-shape) decision is unit-testable without
/// card I/O or a production injection seam — the same "pure decision
/// function living beside the derivation engine" shape as @ref
/// derivePinStatus itself, mirroring the @ref classifyPinOutcome
/// (<LibreSCRS/Plugin/PinOutcome.h>) extraction precedent.
struct UnblockApdu
{
    /// @brief RESET RETRY COUNTER P1, i.e. `quirks.rrcP1[style]`.
    std::uint8_t p1 = 0;
    /// @brief PUK bytes to send — always the caller-supplied @c puk, unchanged.
    std::string_view puk;
    /// @brief New-PIN bytes to send, or empty when the style/caller-input
    ///        combination omits them (@ref UnblockStyle::ResetOnly; @ref
    ///        UnblockStyle::UnblockAndChange with no caller-supplied new PIN).
    std::string_view newPin;
};

/// @brief Resolves the RESET RETRY COUNTER P1 and on-wire data shape for
///        @p style (spec §5.1): @ref UnblockStyle::ResetOnly -> PUK only;
///        @ref UnblockStyle::SetsNewPin -> PUK||newPin; @ref
///        UnblockStyle::UnblockAndChange -> PUK||newPin when the caller
///        supplied one, else PUK only.
///
/// Pure function over its arguments (API-POLICY §8): no card I/O, no
/// state. @p quirks supplies only the static @ref FamilyQuirks::rrcP1
/// table; the data-shape decision is @p style + caller-input alone.
/// Callers pass the credential's @ref PinStatusEntry::unblockStyle (as
/// resolved by @ref derivePinStatus) as @p style.
///
/// @param style  The unblock style already resolved for this credential's
///               kind; behaviour is meaningful only when the credential's
///               @ref PinStatusEntry::unblockable is true.
/// @param quirks The family's quirk row (for @ref FamilyQuirks::rrcP1).
/// @param puk    Caller-supplied PUK bytes; passed through unchanged.
/// @param newPin Caller-supplied candidate new PIN bytes; may be empty.
/// @return The resolved P1 and on-wire data shape.
[[nodiscard]] UnblockApdu resolveUnblockApdu(UnblockStyle style, const FamilyQuirks& quirks, std::string_view puk,
                                             std::string_view newPin) noexcept;

/// @brief Resolved CHANGE REFERENCE DATA P1 + on-wire data shape for one
///        transport-PIN activation attempt (spec §5.2/§6).
///
/// Extracted from pkcs15-plugin's @c activateTransportPin override up
/// front (Task 12), following the exact @ref resolveUnblockApdu precedent
/// (itself the Task 11 review fix) rather than repeating that lesson: the
/// form -> (P1, data-shape) decision is a pure function living beside the
/// derivation engine, unit-testable without card I/O or a production
/// injection seam — the same shape as the @ref classifyPinOutcome
/// (<LibreSCRS/Plugin/PinOutcome.h>) extraction.
struct TransportChangeApdu
{
    /// @brief CHANGE REFERENCE DATA P1, i.e. `quirks->transportChangeP1`.
    std::uint8_t p1 = 0;
    /// @brief Old-data block: the transport value for the `0x00` one-shot
    ///        form, or empty for the `0x01` prior-auth form (the transport
    ///        value was already consumed by a preceding VERIFY, so the
    ///        CHANGE call's old-data block is omitted entirely — never
    ///        padded — for that form).
    std::string_view oldData;
    /// @brief New-PIN bytes to send — always the caller-supplied @c newPin,
    ///        unchanged, in both forms.
    std::string_view newData;
};

/// @brief Resolves the CHANGE REFERENCE DATA P1 and on-wire data shape for
///        @p transportChangeP1 (spec §5.2/§6): `0x01` (prior-auth) ->
///        new-only (the transport value was already VERIFYed by the
///        caller); anything else (the `0x00` ISO-default one-shot form,
///        and conservatively any other family-supplied byte) ->
///        transport||new in one CHANGE REFERENCE DATA call.
///
/// Pure function over its arguments (API-POLICY §8): no card I/O, no
/// state. @p transportChangeP1 is the family row's own
/// @ref FamilyQuirks::transportChangeP1 byte; callers must never hardcode
/// a P1 constant here — the whole point of this function is that the
/// family table drives it.
///
/// @param transportChangeP1 The family's CHANGE REFERENCE DATA P1 for
///                          transport-PIN activation.
/// @param transport         Transport PIN value; passed through unchanged
///                          when the resolved form requires it.
/// @param newPin            Holder's new PIN value; always present in the
///                          returned shape.
/// @return The resolved P1 and on-wire data shape.
[[nodiscard]] TransportChangeApdu resolveTransportChangeApdu(std::uint8_t transportChangeP1, std::string_view transport,
                                                             std::string_view newPin) noexcept;

} // namespace LibreSCRS::Plugin::Internal
