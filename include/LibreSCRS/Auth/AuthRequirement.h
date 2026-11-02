// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

/// @file
/// @brief @ref LibreSCRS::Auth::AuthRequirement — closed-shape credential
///        prompt descriptor, its @ref LibreSCRS::Auth::Purpose, and the
///        @ref LibreSCRS::Auth::PreReadAuthMethod a plugin reports.

#include <LibreSCRS/Auth/FieldDescriptor.h>
#include <LibreSCRS/Auth/PaceSecretKind.h>
#include <LibreSCRS/Export.h>
#include <LibreSCRS/LocalizedText.h>

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace LibreSCRS::Auth {

/// @brief Semantic category describing what the credential provider is being asked for.
enum class Purpose : std::uint8_t {
    Signing,              ///< PIN entry for a signing operation.
    EstablishPaceChannel, ///< Per-applet PACE/BAC secret (CAN/MRZ/PIN/PUK).
    CustomExtension,      ///< Plugin-defined purpose outside the canonical set.
};

/// @brief Pre-read unlock mechanisms for travel-document-style cards.
///
/// Each value names the *credential* the host must collect, not the
/// protocol run against the card — a plugin may use either BAC or PACE
/// to consume an MRZ-derived secret, and which protocol is actually
/// selected is plugin business, not something this enum encodes.
enum class PreReadAuthMethod : std::uint8_t {
    None, ///< No pre-read authentication required.
    Mrz,  ///< MRZ-derived secret (ICAO 9303 Basic Access Control or PACE).
    Can,  ///< Card Access Number (PACE).
};

/// @brief Authoritative description of a credential prompt.
///
/// The plugin or signing pipeline constructs an @ref AuthRequirement via one
/// of the static factory functions (`forSigning`, `forPaceSecret`) and hands
/// it to a `CredentialProvider`.
/// @ref fields gives the length bounds of the value the provider collects.
/// The provider returns it in @ref CredentialResult::values under the
/// credential's name: `"pin"` for a signing requirement; `"can"`, `"mrz"`,
/// `"pin"` or `"puk"` for a PACE secret, as @ref paceKind says.
///
/// @par Invariant enforcement
/// The type's data members are private; external code cannot construct an
/// `AuthRequirement` from scratch or mutate the field list. The factories
/// are the only way to produce a populated instance. Copy, move and
/// comparison remain available so callers can pass the value around freely.
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
/// @since 4.0 — private data + accessor API.
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

    /// @brief Optional explanatory message shown alongside the prompt.
    [[nodiscard]] const std::optional<LocalizedText>& message() const noexcept
    {
        return messageText;
    }

    // -- Factories -----------------------------------------------------------

    /// @brief Build a requirement for collecting a single signing PIN.
    [[nodiscard]] static AuthRequirement forSigning();

    /// @brief Build a requirement for a PACE / BAC secret prompt.
    /// @param kind Which shared-secret variant the card expects
    ///             (CAN / MRZ / PIN / PUK).
    /// @param reasonForUser Optional explanatory message rendered alongside
    ///        the prompt (e.g. "Insert the CAN printed on the back of your
    ///        ID card"). May be the empty default-constructed value if the
    ///        host has nothing to add.
    /// @note Infallible — the input contract is structurally validated by
    ///       its types.
    ///
    /// @since 4.1
    [[nodiscard]] static AuthRequirement forPaceSecret(PaceSecretKind kind, LocalizedText reasonForUser) noexcept;

    // -- PACE/BAC accessors -------------------------------------------------

    /// @brief Which PACE/BAC secret kind the card needs. Populated only
    ///        when @ref purpose returns @ref Purpose::EstablishPaceChannel.
    /// @since 4.1
    [[nodiscard]] std::optional<PaceSecretKind> paceKind() const noexcept
    {
        return paceKindValue;
    }

private:
    AuthRequirement() = default;

    // Project convention: no trailing underscores on member
    // variables. The accessor names necessarily differ from the data
    // members, so we use descriptive non-conflicting names instead of an
    // `m_` prefix.
    Purpose purposeValue = Purpose::Signing;
    std::vector<FieldDescriptor> fieldList;
    std::optional<LocalizedText> messageText;
    std::optional<PaceSecretKind> paceKindValue;
};

} // namespace LibreSCRS::Auth
