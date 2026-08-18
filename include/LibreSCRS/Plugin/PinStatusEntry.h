// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

/// @file
/// @brief @ref LibreSCRS::Plugin::PinStatusEntry — per-PIN state record
///        returned by @ref LibreSCRS::Plugin::CardPlugin::getPINList.
///
/// @par Thread-safety
/// All types in this header are plain value aggregates; thread-compatible
/// per API-POLICY §8.
///
/// @since 4.0

#include <LibreSCRS/LocalizedText.h>
#include <LibreSCRS/Export.h>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>

namespace LibreSCRS::Plugin {

/// @brief Credential classification derived from card evidence.
/// @since 4.3 — append-only.
enum class PinKind : std::uint8_t {
    Unknown, ///< No safe classification evidence.
    UserPin, ///< General-authentication PIN.
    SignPin, ///< Signature/QSCD PIN (local to the signature DF).
    Puk,     ///< Unblocking key (PUK).
    Can,     ///< PACE Card Access Number pseudo-credential.
};

/// @brief Objective lifecycle state of a credential.
/// Precedence when several apply: Blocked > NeedsChange > Transport > Operational.
/// @since 4.3 — append-only.
enum class PinState : std::uint8_t {
    Unknown,     ///< Not determinable safely.
    Transport,   ///< Transport value set at issuance; not yet personalized.
    Operational, ///< Initialized and usable.
    NeedsChange, ///< Card signals the PIN must be changed before use.
    Blocked,     ///< Retry counter exhausted. Invariant: state==Blocked ⇔ blocked==true.
};

/// @brief How a PUK-based unblock behaves on this credential.
/// Meaningful only when @ref PinStatusEntry::unblockable is true; MUST be
/// Unknown otherwise.
/// @since 4.3 — append-only.
enum class UnblockStyle : std::uint8_t {
    Unknown,          ///< Not unblockable, or style not known.
    ResetOnly,        ///< Counter reset; old PIN value retained.
    SetsNewPin,       ///< New PIN mandatory as part of the unblock.
    UnblockAndChange, ///< Holder chooses: reset-only or set a new value.
};

/// @brief Who can recover a blocked credential.
/// @since 4.3 — append-only.
enum class PinRecovery : std::uint8_t {
    Unknown,       ///< No evidence — clients show generic contact-issuer guidance.
    HolderViaPuk,  ///< Holder can unblock with the PUK through this software.
    IssuerProcess, ///< Only the issuer can recover (e.g. counter challenge/response).
    None,          ///< Terminal — card replacement only.
};

/// @brief Per-PIN state entry returned by @ref CardPlugin::getPINList.
///
/// Plugins MUST populate @ref unblockable accurately: when @ref blocked is true
/// and @ref unblockable is false, the host should surface
/// @ref blockedGuidance rather than offering a PUK-unblock action.
struct PinStatusEntry
{
    /// @brief Plugin-defined label, used as the pinLabel in change/unblock flows.
    std::string label;
    /// @brief Card-native PIN reference (where applicable).
    std::uint8_t reference = 0;
    /// @brief Remaining PIN retry count; @c std::nullopt when unknown.
    std::optional<int> retriesLeft;
    /// @brief True when the PIN has been initialised on-card.
    bool initialized = true;
    /// @brief True when the PIN is currently blocked.
    bool blocked = false;
    /// @brief Enforced minimum length; @c std::nullopt when unknown.
    std::optional<std::size_t> minLength;
    /// @brief Enforced maximum length; @c std::nullopt when unknown.
    std::optional<std::size_t> maxLength;
    /// @brief True when the PIN value is user-changeable.
    ///
    /// Conservative default: `false`. A plugin that supports PIN change
    /// MUST set this explicitly so a plugin that forgets to populate the
    /// flag does not accidentally advertise a change capability it does
    /// not implement — a @ref CardPlugin::changePIN call would then reach
    /// the card layer and fail at protocol time rather than being
    /// short-circuited by the host UI.
    bool canChange = false;

    /// @brief True when the plugin supports PUK-based unblock for this PIN.
    bool unblockable = false;
    /// @brief Optional message displayed when @ref blocked is true and unblock is unavailable.
    std::optional<LocalizedText> blockedGuidance;

    /// @brief Credential classification (conservative default Unknown).
    PinKind kind = PinKind::Unknown;
    /// @brief Objective lifecycle state. Invariants: Blocked ⇔ @ref blocked;
    ///        Transport ⇒ !@ref initialized on transport-capable families.
    PinState state = PinState::Unknown;
    /// @brief Maximum retry count (family knowledge); @c nullopt when unknown.
    std::optional<int> retriesMax;
    /// @brief Remaining usage budget of this credential itself (PUK usage
    ///        counter); @c nullopt when not exposed or not safely readable.
    std::optional<int> usesLeft;
    /// @brief Maximum usage budget of this credential (PUK max uses);
    ///        @c nullopt when not exposed.
    std::optional<int> usesMax;
    /// @brief Remaining times this PIN may be unblocked; @c nullopt unknown.
    std::optional<int> unblocksLeft;
    /// @brief Unblock behaviour; Unknown unless @ref unblockable.
    UnblockStyle unblockStyle = UnblockStyle::Unknown;
    /// @brief Transport→operational activation is supported by this
    ///        credential's family and the credential is in
    ///        @ref PinState::Transport. Family-level capability, NOT a
    ///        live availability claim: the stack may still answer the
    ///        activation call with an Unsupported outcome in this
    ///        increment.
    bool activatable = false;
    /// @brief The associated signing key is still deactivated (bring-up incomplete).
    bool keyActivationPending = false;
    /// @brief Holder can activate that key through this software
    ///        (false where activation is issuer-tool-only).
    bool keyActivatable = false;
    /// @brief Who can recover this credential when blocked.
    PinRecovery recovery = PinRecovery::Unknown;
    /// @brief True when counter queries are known safe on this family.
    ///        Display-only semantics for hosts: explains absent counters;
    ///        MUST NOT be used by clients to trigger probes.
    bool probeSafe = false;
    /// @brief Optional guidance shown when key activation is pending but
    ///        not holder-activatable. @ref blockedGuidance semantics unchanged.
    std::optional<LocalizedText> keyActivationGuidance;

    /// @brief Defaulted member-wise equality.
    [[nodiscard]] bool operator==(const PinStatusEntry&) const noexcept = default;
};

} // namespace LibreSCRS::Plugin
