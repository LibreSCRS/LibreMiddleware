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
    /// @brief PACE OID present for the app AND PACE-password
    ///        encoding/corroboration.
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

} // namespace LibreSCRS::Plugin::Internal
