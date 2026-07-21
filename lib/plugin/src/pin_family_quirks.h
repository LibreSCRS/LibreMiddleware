// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware."
#endif

#pragma once

/// @file
/// @brief Static per-family credential quirk table consumed by the
///        credential-lifecycle derivation.
///
/// Encodes only conservatively verified family knowledge: a row never
/// advertises a capability (e.g. an unblock command form) that has not
/// been confirmed for that family. Everything genuinely unknown stays at
/// the conservative defaults (`false` / `Unknown` / `nullopt`) so a
/// consumer combining quirks with card evidence can only narrow, never
/// overclaim.
///
/// LIBRESCRS_INTERNAL: not part of public API.

#include <LibreSCRS/LocalizedText.h>
#include <LibreSCRS/Plugin/PinStatusEntry.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>

namespace LibreSCRS::Plugin::Internal {

/// @brief Identity of a credential family with a static quirk row.
enum class FamilyId : std::uint8_t {
    Unknown,             ///< No family evidence — @ref findFamilyQuirks returns nullptr.
    CurrentLkCardEdge,   ///< Current Serbian eID applet (CardEdge, single-PIN model).
    VeridosAppletSuite1, ///< ePasslet applet-suite generation 1 (PKCS#15 with transport-born SIGN PIN).
    VeridosAppletSuite2, ///< ePasslet applet-suite generation 2 (SRB-eID V2.00).
    Piv,                 ///< NIST PIV.
    AetPosta,            ///< Postal CA card profile (issuer-tool key activation).
};

/// @brief Per-@ref PinKind static knowledge for one family.
///
/// Aggregate with conservative defaults: a default-constructed entry
/// advertises nothing.
struct FamilyKindQuirks
{
    /// @brief The family supports holder-performed PIN change for this kind.
    bool canChange = false;
    /// @brief The family's RESET RETRY COUNTER command form for this kind
    ///        is verified knowledge. Stays false until hardware-verified;
    ///        an unverified variant must never be advertised.
    bool rrcVariantKnown = false;
    /// @brief Verified unblock behaviour; Unknown when not verified.
    UnblockStyle unblockStyle = UnblockStyle::Unknown;
    /// @brief Static recovery authority when this kind is blocked; Unknown
    ///        where recovery is evidence-dependent (derivation decides).
    PinRecovery blockedRecovery = PinRecovery::Unknown;
    /// @brief Guidance shown when blocked and no holder recovery exists.
    std::optional<LocalizedText> blockedGuidance;
    /// @brief Family-known maximum retry count; nullopt when unknown.
    std::optional<int> retriesMax;
};

/// @brief Number of @ref PinKind members covered by @ref FamilyQuirks::kinds.
/// PinKind is append-only; kinds appended later fall back to conservative
/// defaults via the accessors.
inline constexpr std::size_t kPinKindCount = 5;
static_assert(static_cast<std::size_t>(PinKind::Can) == kPinKindCount - 1,
              "kPinKindCount must cover PinKind::Unknown..PinKind::Can");

/// @brief Static quirk row for one credential family.
///
/// Aggregate (no constructors, all-public data) so derivation tests can
/// construct synthetic rows — e.g. a row with a known RRC variant — that
/// the real table deliberately does not contain.
struct FamilyQuirks
{
    FamilyId id = FamilyId::Unknown;
    /// @brief Family issues transport-value PINs that need activation.
    bool supportsTransportPin = false;
    /// @brief Retry-counter queries are known safe (non-consuming) here.
    bool probeSafe = false;
    /// @brief Per-kind knowledge, indexed by static_cast<std::size_t>(PinKind).
    std::array<FamilyKindQuirks, kPinKindCount> kinds{};
    /// @brief Family-level guidance shown while the signing key awaits
    ///        issuer-side activation (issuer-tool-only families).
    std::optional<LocalizedText> keyActivationGuidance;

    /// @name Per-kind accessors (conservative defaults for kinds beyond the table)
    /// @{
    [[nodiscard]] bool canChange(PinKind k) const noexcept;
    [[nodiscard]] bool rrcVariantKnown(PinKind k) const noexcept;
    [[nodiscard]] UnblockStyle unblockStyle(PinKind k) const noexcept;
    [[nodiscard]] PinRecovery blockedRecovery(PinKind k) const noexcept;
    /// @brief Returns a copy; not noexcept (copying may allocate).
    [[nodiscard]] std::optional<LocalizedText> blockedGuidance(PinKind k) const;
    [[nodiscard]] std::optional<int> retriesMax(PinKind k) const noexcept;
    /// @}
};

/// @brief Looks up the static quirk row for @p id.
/// @return Pointer to a static const row, or nullptr for
///         @ref FamilyId::Unknown / an id without a row. Also returns
///         nullptr on allocation failure while the table is first built
///         (callers already treat nullptr as "no family knowledge").
[[nodiscard]] const FamilyQuirks* findFamilyQuirks(FamilyId id) noexcept;

} // namespace LibreSCRS::Plugin::Internal
