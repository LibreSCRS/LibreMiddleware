// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

/// @file
/// @brief Security-verification vocabulary —
///        @ref LibreSCRS::Plugin::SecurityCategory,
///        @ref LibreSCRS::Plugin::SecurityCheck, and
///        @ref LibreSCRS::Plugin::SecurityStatus — with string-view
///        conversions for wire/serialization.
///
/// @par Thread-safety
/// Thread-compatible (see API-POLICY §8). All types in this header are plain
/// value-aggregates with no internal synchronisation. Distinct instances are
/// independent; concurrent reads of the same instance are race-free.
/// #LibreSCRS::Plugin::SecurityStatus::computeOverall mutates the instance and is therefore
/// single-threaded relative to that instance. The free `*ToString` /
/// `*FromString` helpers are pure functions.
///
/// @since 4.0

#include <LibreSCRS/Export.h>

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace LibreSCRS::Plugin {

/// @brief Category of a @ref LibreSCRS::Plugin::SecurityCheck.
///
/// Replaces the earlier free-form @c std::string category with a closed
/// enumeration. Producers (plugins) and consumers (aggregation, UI) now share
/// a type-checked vocabulary; invalid categories cannot be expressed.
///
/// For wire/serialization contexts that need a stable string token, use
/// `categoryToString` / `categoryFromString`.
enum class SecurityCategory : std::uint8_t {
    DataIntegrity, ///< Hash/MAC integrity of data groups.
    Authenticity,  ///< Signature / passive authentication over the data.
    Genuineness,   ///< Chip genuineness (active authentication / chip auth).
    Other,         ///< Plugin-defined check outside the canonical categories.
};

/// @brief One security-verification check result (e.g. passive auth, chip auth).
struct SecurityCheck
{
    /// @brief Plugin-defined identifier for the check.
    std::string checkId;
    /// @brief Category classification; one of @c SecurityCategory.
    SecurityCategory category = SecurityCategory::Other;

    /// @brief Outcome of a single security check.
    ///
    /// PascalCase enumerators align with every other public enum in the SDK
    /// (`SignatureFormat::Pades`, `MonitorEvent::Kind::ReaderAdded`, etc.).
    /// The serialization wire format preserved by `statusToString` /
    /// `statusFromString` remains the historical UPPERCASE token form
    /// ("PASSED", "FAILED", "NOT_PERFORMED", "NOT_SUPPORTED", "SKIPPED").
    /// @note Append-only: new status values may be added in future minor
    ///       releases. Consumer @c switch statements must include a
    ///       @c default branch.
    enum class Status : std::uint8_t {
        Passed,       ///< Check was performed and succeeded.
        Failed,       ///< Check was performed and failed.
        NotPerformed, ///< Check was not run (e.g. prerequisite missing).
        NotSupported, ///< Card or plugin does not implement the check.
        Skipped,      ///< Caller chose to bypass the check.
    };
    /// @brief Check outcome.
    Status status = Status::NotPerformed;

    /// @brief Short human-readable label.
    std::string label;
    /// @brief Supplemental detail rendered next to the outcome.
    std::string detail;
    /// @brief Populated when @ref status is @ref Status::Failed.
    std::string errorDetail;

    /// @brief Defaulted member-wise equality.
    [[nodiscard]] bool operator==(const SecurityCheck&) const noexcept = default;
};

/// @brief Aggregate security evaluation over a set of @ref SecurityCheck entries.
struct SecurityStatus
{
    /// @brief Individual check results.
    std::vector<SecurityCheck> checks;

    /// @brief Overall outcome for @c SecurityCategory::DataIntegrity checks.
    SecurityCheck::Status overallIntegrity = SecurityCheck::Status::NotPerformed;
    /// @brief Overall outcome for @c SecurityCategory::Authenticity checks.
    SecurityCheck::Status overallAuthenticity = SecurityCheck::Status::NotPerformed;
    /// @brief Overall outcome for @c SecurityCategory::Genuineness checks.
    SecurityCheck::Status overallGenuineness = SecurityCheck::Status::NotPerformed;

    /// @brief Recompute the three overall fields from @ref checks.
    ///
    /// Aggregation rules (per category): Failed wins over Passed, Passed wins
    /// over NotSupported, NotSupported wins over NotPerformed. Checks with
    /// unknown categories are ignored.
    ///
    /// @note @ref SecurityCategory::Other checks are deliberately excluded
    ///       from all three `overall*` aggregates — they exist for
    ///       plugin-specific checks that don't fit
    ///       @ref SecurityCategory::DataIntegrity,
    ///       @ref SecurityCategory::Authenticity, or
    ///       @ref SecurityCategory::Genuineness, and aggregating them into
    ///       the canonical three would distort their semantic meaning.
    ///       Hosts that want to surface `Other` checks must iterate @ref
    ///       checks directly.
    ///
    /// Exported from the LibreSCRS::Plugin library — no header-inline body, so
    /// mixed-ABI consumers cannot end up with divergent aggregation logic
    /// across translation units.
    LIBRESCRS_PUBLIC_API void computeOverall();
};

/// @brief Convert a @ref LibreSCRS::Plugin::SecurityCheck::Status value to its canonical string.
///
/// Returns one of: "PASSED", "FAILED", "NOT_PERFORMED", "NOT_SUPPORTED",
/// "SKIPPED". An invalid enumerator value (e.g. a cast of a raw integer
/// outside the declared range) falls through to "UNKNOWN" — a sentinel
/// distinct from every recognised token so `statusFromString("UNKNOWN")`
/// still returns @c std::nullopt.
///
/// @note The wire format is historical UPPERCASE even though the enumerator
///       names are PascalCase — stability of the string form across the 4.0
///       PascalCase refactor is deliberate.
/// @note Returns a @c std::string_view backed by string-literal storage
///       (static duration). Zero-allocation on the hot aggregation path.
///       Callers that need an owning @c std::string must construct one
///       explicitly (`std::string{statusToString(s)}`).
[[nodiscard]] inline constexpr std::string_view statusToString(SecurityCheck::Status s) noexcept
{
    switch (s) {
    case SecurityCheck::Status::Passed:
        return "PASSED";
    case SecurityCheck::Status::Failed:
        return "FAILED";
    case SecurityCheck::Status::NotPerformed:
        return "NOT_PERFORMED";
    case SecurityCheck::Status::NotSupported:
        return "NOT_SUPPORTED";
    case SecurityCheck::Status::Skipped:
        return "SKIPPED";
    }
    return "UNKNOWN";
}

/// @brief Parse a canonical status string.
/// @param s One of "PASSED", "FAILED", "NOT_PERFORMED", "NOT_SUPPORTED",
///          "SKIPPED".
/// @return The matching @ref LibreSCRS::Plugin::SecurityCheck::Status on success; @c std::nullopt
///         for unrecognized or empty input. Callers must decide what an
///         unrecognized serialized status means in their context —
///         silently collapsing unknown input to NotPerformed is the
///         safest-looking wrong answer for a security-outcome type.
///
/// Fits API-POLICY §5.2 (runtime-error model): the string typically arrives
/// from a wire/file format, so malformed input is an environmental failure
/// rather than a programmer-error validation case.
///
/// @note Takes @c std::string_view for symmetry with #LibreSCRS::Plugin::categoryFromString
///       and to enable compile-time evaluation. @c std::string and
///       string-literal call sites convert implicitly without an
///       intermediate allocation.
[[nodiscard]] inline constexpr std::optional<SecurityCheck::Status> statusFromString(std::string_view s) noexcept
{
    if (s == "PASSED")
        return SecurityCheck::Status::Passed;
    if (s == "FAILED")
        return SecurityCheck::Status::Failed;
    if (s == "NOT_PERFORMED")
        return SecurityCheck::Status::NotPerformed;
    if (s == "NOT_SUPPORTED")
        return SecurityCheck::Status::NotSupported;
    if (s == "SKIPPED")
        return SecurityCheck::Status::Skipped;
    return std::nullopt;
}

/// @brief Canonical string form of a @c SecurityCategory for wire/serialization.
///
/// Historical tokens: "data_integrity", "data_authenticity",
/// "chip_genuineness", "other". An invalid enumerator value falls through
/// to "unknown" — distinct from every recognised token so
/// `categoryFromString` rejects it symmetrically.
/// @note Returns a @c std::string_view backed by string-literal storage
///       (static duration). Zero-allocation. Callers that need an owning
///       @c std::string must construct one explicitly.
[[nodiscard]] inline constexpr std::string_view categoryToString(SecurityCategory c) noexcept
{
    switch (c) {
    case SecurityCategory::DataIntegrity:
        return "data_integrity";
    case SecurityCategory::Authenticity:
        return "data_authenticity";
    case SecurityCategory::Genuineness:
        return "chip_genuineness";
    case SecurityCategory::Other:
        return "other";
    }
    return "unknown";
}

/// @brief Parse a @c SecurityCategory wire token.
/// @return The matching enumerator on success; @c std::nullopt for unknown input.
[[nodiscard]] inline constexpr std::optional<SecurityCategory> categoryFromString(std::string_view s) noexcept
{
    if (s == "data_integrity")
        return SecurityCategory::DataIntegrity;
    if (s == "data_authenticity")
        return SecurityCategory::Authenticity;
    if (s == "chip_genuineness")
        return SecurityCategory::Genuineness;
    if (s == "other")
        return SecurityCategory::Other;
    return std::nullopt;
}

} // namespace LibreSCRS::Plugin
