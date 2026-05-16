// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

/// @file
/// @brief @ref LibreSCRS::Auth::AuthRequirement — closed-shape credential
///        prompt descriptor, plus @ref LibreSCRS::Auth::Purpose and
///        @ref LibreSCRS::Auth::PreReadAuthMethod enums used by its
///        factories.

#include <LibreSCRS/Auth/FieldDescriptor.h>
#include <LibreSCRS/Auth/PaceSecretKind.h>
#include <LibreSCRS/Export.h>
#include <LibreSCRS/LocalizedText.h>
#include <LibreSCRS/SmartCard/AppletAid.h>

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace LibreSCRS::Auth {

/// @brief Semantic category describing what the credential provider is being asked for.
enum class Purpose : std::uint8_t {
    PreRead,              ///< Unlock required before data-group reads (BAC/PACE).
    Signing,              ///< PIN entry for a signing operation.
    ChangePin,            ///< Old + new PIN entry for a PIN change.
    UnblockPin,           ///< PUK + new PIN entry for an unblock-and-change flow.
    EstablishPaceChannel, ///< Per-applet PACE/BAC secret (CAN/MRZ/PIN/PUK).
    CustomExtension,      ///< Plugin-defined purpose outside the canonical set.
};

/// @brief Pre-read unlock mechanisms for travel-document-style cards.
enum class PreReadAuthMethod : std::uint8_t {
    None,    ///< No pre-read authentication required.
    BacMrz,  ///< ICAO 9303 Basic Access Control derived from MRZ.
    PaceCan, ///< PACE using a Card Access Number.
};

/// @brief Authoritative description of a credential prompt.
///
/// The plugin or signing pipeline constructs an @ref AuthRequirement via one
/// of the static factory functions (`forPreRead`, `forSigning`,
/// `forChangePin`, `forUnblockPin`) and hands it to a `CredentialProvider`.
/// @ref fields is the contract: each @ref FieldDescriptor describes one
/// value the provider must collect and return in
/// @ref CredentialResult::values, keyed by its @ref FieldDescriptor::id.
///
/// @par Invariant enforcement
/// The type's data members are private; external code cannot construct an
/// `AuthRequirement` from scratch or mutate the field list. The factories
/// are the only way to produce a populated instance and are responsible for
/// maintaining the documented invariants (unique field ids, valid
/// `equalToFieldId` back-references). Copy, move and comparison remain
/// available so callers can pass the value around freely.
///
/// Factories are preferred over a Builder here because the shape of an
/// `AuthRequirement` is closed — each factory produces a known,
/// card-family-independent field set that reflects a well-defined UX flow.
/// In contrast, `SigningRequest` uses a Builder because its shape is
/// open-ended (many optional fields, new capabilities added over time).
/// Rule of thumb: factories for closed shapes, Builders for open, evolving
/// shapes.
///
/// @par Value semantics vs. SigningRequest
/// `AuthRequirement` is fully copyable (no secret material; members are
/// POD + `std::string` + `std::vector<FieldDescriptor>`), unlike sibling
/// @ref LibreSCRS::Signing::SigningRequest which is move-only because of
/// its pimpl-backed storage and its lifetime coupling to the backend
/// signing pipeline. Hosts routinely clone `AuthRequirement` values into
/// UI model objects and across worker threads, so copy/move/assign are all
/// defaulted.
///
/// @par Thread-safety
/// Thread-compatible (see API-POLICY §8). `AuthRequirement` is an immutable
/// value type after construction: all data members are private and there are
/// no mutating accessors. Distinct instances never share state. Copies may be
/// freely passed across threads; concurrent reads of the same instance are
/// race-free.
///
/// @since 4.0 — private data + accessor API. Pre-4.0 code that used direct
/// aggregate access (`req.fields`, `req.retriesLeft`, …) must migrate to
/// the `fields()`, `retriesLeft()` accessors.
class LIBRESCRS_PUBLIC_API AuthRequirement
{
public:
    /// @brief Copy constructor — the usual value-type operation.
    AuthRequirement(const AuthRequirement&) = default;
    /// @brief Move constructor — the usual value-type operation.
    AuthRequirement(AuthRequirement&&) noexcept = default;
    /// @brief Copy assignment — the usual value-type operation.
    AuthRequirement& operator=(const AuthRequirement&) = default;
    /// @brief Move assignment — the usual value-type operation.
    AuthRequirement& operator=(AuthRequirement&&) noexcept = default;
    /// @brief Destructor.
    ~AuthRequirement() = default;

    // -- Accessors -----------------------------------------------------------

    /// @brief Purpose category of the request.
    [[nodiscard]] Purpose purpose() const noexcept
    {
        return purposeValue;
    }

    /// @brief Inputs the provider must collect (presentation order).
    ///
    /// Returned as an immutable view — callers iterate or index but do not
    /// mutate.
    [[nodiscard]] std::span<const FieldDescriptor> fields() const noexcept
    {
        return fieldList;
    }

    /// @brief Card-reported retry count, when available.
    [[nodiscard]] const std::optional<int>& retriesLeft() const noexcept
    {
        return retriesValue;
    }

    /// @brief Optional explanatory message shown alongside the prompt.
    [[nodiscard]] const std::optional<LocalizedText>& message() const noexcept
    {
        return messageText;
    }

    /// @brief Optional title shown as the prompt heading.
    [[nodiscard]] const std::optional<LocalizedText>& title() const noexcept
    {
        return titleText;
    }

    // -- Factories -----------------------------------------------------------

    /// @brief Build a requirement for pre-read unlock using the given method.
    /// @param method Pre-read unlock mechanism. `None` yields a no-field
    ///               requirement; `BacMrz` yields a single MRZ field;
    ///               `PaceCan` yields a single 6-digit CAN field.
    /// @note Infallible — the input is a closed enum with no invalid values.
    ///       See API-POLICY §5.1.
    [[nodiscard]] static AuthRequirement forPreRead(PreReadAuthMethod method) noexcept;

    /// @brief Build a requirement for collecting a single signing PIN.
    /// @param pinLabel User-visible English fallback label (e.g. "UserPIN").
    ///                 Must be non-empty.
    /// @param retriesLeft Card-reported retry count, or a negative value
    ///                    ("unknown") to leave @ref retriesLeft as
    ///                    `std::nullopt`.
    /// @throws std::invalid_argument if @p pinLabel is empty.
    ///         See API-POLICY §5.1.
    /// @note Convenience overload — internally constructs a
    ///       @ref LocalizedText with an empty @c key and @p pinLabel as
    ///       @c defaultText. Hosts that need a translatable label
    ///       should prefer the @ref LocalizedText overload below.
    [[nodiscard]] static AuthRequirement forSigning(std::string pinLabel, int retriesLeft);

    /// @brief Build a requirement for collecting a single signing PIN, with a
    ///        translatable label.
    /// @param pinLabel Translator-friendly bundle. The bundle's
    ///                 @ref LocalizedText::defaultText (or @ref
    ///                 LocalizedText::key if the fallback is empty)
    ///                 must be non-empty so the resulting credential prompt
    ///                 has a renderable label.
    /// @param retriesLeft Card-reported retry count, or a negative value
    ///                    ("unknown") to leave @ref retriesLeft as
    ///                    `std::nullopt`.
    /// @throws std::invalid_argument if both @p pinLabel.defaultText and
    ///         @p pinLabel.key are empty. See API-POLICY §5.1.
    /// @since 4.0 — preferred entry point for hosts that surface translated
    ///         PIN labels (e.g. "Signing PIN" / "ПИН за потпис"). Eliminates
    ///         the implicit i18n leak the @c std::string overload introduced
    ///         when callers wanted a translation key.
    [[nodiscard]] static AuthRequirement forSigning(LocalizedText pinLabel, int retriesLeft);

    /// @brief Build a requirement for a PIN change (current + new + confirm).
    /// @param pinLabel User-visible English fallback label for the PIN being
    ///                 changed. Must be non-empty.
    /// @param retriesLeft Card-reported retry count on the current PIN, or a
    ///                    negative value ("unknown") to leave
    ///                    @ref retriesLeft as `std::nullopt`.
    /// @throws std::invalid_argument if @p pinLabel is empty.
    ///         See API-POLICY §5.1.
    [[nodiscard]] static AuthRequirement forChangePin(std::string pinLabel, int retriesLeft);

    /// @brief Build a requirement for a PIN change with a translatable label.
    /// @param pinLabel Translator-friendly bundle. The bundle's
    ///                 @ref LocalizedText::defaultText (or @ref
    ///                 LocalizedText::key if the fallback is empty)
    ///                 must be non-empty so the resulting credential prompt
    ///                 has a renderable label.
    /// @param retriesLeft Card-reported retry count, or a negative value
    ///                    ("unknown") to leave @ref retriesLeft as
    ///                    `std::nullopt`.
    /// @throws std::invalid_argument if both @p pinLabel.defaultText and
    ///         @p pinLabel.key are empty. See API-POLICY §5.1.
    /// @note Field-label policy. Unlike the @c std::string overload (which
    ///       prepends English "Current "/"New " to the PIN label), the
    ///       @ref LocalizedText overload assigns @p pinLabel as-is to all
    ///       three fields and relies on @ref FieldDescriptor::id values
    ///       (`"currentPin"`, `"newPin"`, `"confirmPin"`) for hosts to
    ///       distinguish role. This avoids synthesising untranslatable
    ///       English prefixes onto otherwise i18n-aware labels.
    /// @since 4.0 — preferred entry point for hosts that surface translated
    ///         PIN labels for PIN-change workflows.
    [[nodiscard]] static AuthRequirement forChangePin(LocalizedText pinLabel, int retriesLeft);

    /// @brief Build a requirement for a PUK-based unblock (PUK + new + confirm).
    /// @param pinLabel User-visible English fallback label for the PIN being
    ///                 unblocked. Must be non-empty.
    /// @throws std::invalid_argument if @p pinLabel is empty.
    ///         See API-POLICY §5.1.
    [[nodiscard]] static AuthRequirement forUnblockPin(std::string pinLabel);

    /// @brief Build a requirement for a PUK-based unblock with a translatable label.
    /// @param pinLabel Translator-friendly bundle for the PIN being unblocked.
    ///                 See @ref forChangePin LocalizedText overload for the
    ///                 empty-bundle validation rule and the field-label policy.
    /// @throws std::invalid_argument if both @p pinLabel.defaultText and
    ///         @p pinLabel.key are empty. See API-POLICY §5.1.
    /// @since 4.0
    [[nodiscard]] static AuthRequirement forUnblockPin(LocalizedText pinLabel);

    /// @brief Build a requirement for a PACE / BAC secret prompt keyed
    ///        per-applet.
    /// @param aid The applet whose secure channel is being established.
    /// @param kind Which shared-secret variant the card expects
    ///             (CAN / MRZ / PIN / PUK).
    /// @param retriesLeft Card-reported retry count. PACE/BAC cards
    ///        typically do not surface a counter; pass `std::nullopt`
    ///        for the unknown case.
    /// @param reasonForUser Optional explanatory message rendered alongside
    ///        the prompt (e.g. "Insert the CAN printed on the back of your
    ///        ID card"). May be the empty default-constructed value if the
    ///        host has nothing to add.
    /// @note Infallible — the input contract is structurally validated by
    ///       its types.
    ///
    /// @since 4.1
    [[nodiscard]] static AuthRequirement forPaceSecret(
        LibreSCRS::SmartCard::AppletAid aid,
        PaceSecretKind kind,
        std::optional<int> retriesLeft,
        LocalizedText reasonForUser) noexcept;

    // -- PACE/BAC accessors -------------------------------------------------

    /// @brief Which PACE/BAC secret kind the card needs. Populated only
    ///        when @ref purpose returns @ref Purpose::EstablishPaceChannel.
    /// @since 4.1
    [[nodiscard]] std::optional<PaceSecretKind> paceKind() const noexcept
    {
        return paceKindValue;
    }

    /// @brief Which applet's channel is being established. Populated only
    ///        when @ref purpose returns @ref Purpose::EstablishPaceChannel.
    /// @since 4.1
    [[nodiscard]] const std::optional<LibreSCRS::SmartCard::AppletAid>& paceApplet() const noexcept
    {
        return paceAppletValue;
    }

private:
    AuthRequirement() = default;

    // Project convention (CLAUDE.md): no trailing underscores on member
    // variables. The accessor names (`purpose()`, `fields()`, `retriesLeft()`,
    // `message()`, `title()`) necessarily differ from the data members, so
    // we use descriptive non-conflicting names instead of an `m_` prefix.
    Purpose purposeValue = Purpose::Signing;
    std::vector<FieldDescriptor> fieldList;
    std::optional<int> retriesValue;
    std::optional<LocalizedText> messageText;
    std::optional<LocalizedText> titleText;
    std::optional<PaceSecretKind> paceKindValue;
    std::optional<LibreSCRS::SmartCard::AppletAid> paceAppletValue;
};

} // namespace LibreSCRS::Auth
