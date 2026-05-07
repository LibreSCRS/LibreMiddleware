// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

/// @file
/// @brief @ref LibreSCRS::Certificate::ObjectIdentifier — canonical X.509 OID
///        type with best-effort friendly-name lookup.
///
/// @par Thread-safety
/// Thread-compatible (see API-POLICY §8). @ref
/// LibreSCRS::Certificate::ObjectIdentifier is a plain value aggregate with
/// no internal synchronisation. Distinct instances are independent;
/// concurrent reads of the same instance are race-free. Comparison and hash
/// are pure functions.
///
/// @since 4.0

#include <LibreSCRS/Export.h>

#include <compare>
#include <cstddef>
#include <functional>
#include <string>

namespace LibreSCRS::Certificate {

/// @brief Canonical X.509 Object Identifier (dotted-decimal form).
///
/// Round-trips unknown OIDs without information loss; #dottedDecimal is
/// always populated, while #friendlyName is best-effort against the
/// LibreSCRS OID database (a superset of OpenSSL + Rust oid-registry +
/// BouncyCastle + ETSI EN 319 412-5 + ICAO 9303 + Serbian-curated).
/// @since 4.0
struct LIBRESCRS_PUBLIC_API ObjectIdentifier
{
    /// @brief Canonical dotted-decimal representation (e.g. "2.5.4.3").
    /// Always populated; this is the equality and hash key.
    std::string dottedDecimal;

    ObjectIdentifier() = default;

    /// @brief Construct from a dotted-decimal OID string.
    /// @param oidString dotted-decimal form (e.g. "2.5.4.3"). Stored verbatim.
    explicit ObjectIdentifier(std::string oidString);

    /// @brief Friendly name for well-known OIDs; empty for unknown.
    /// @note The known-name table is best-effort; callers must not assume
    ///       a particular OID has a friendly name. Use #dottedDecimal
    ///       as the canonical identifier.
    [[nodiscard]] std::string friendlyName() const;

    /// @brief Equality on #dottedDecimal.
    [[nodiscard]] bool operator==(const ObjectIdentifier&) const noexcept = default;

    /// @brief Three-way comparison on #dottedDecimal (lexicographic).
    [[nodiscard]] auto operator<=>(const ObjectIdentifier&) const = default;
};

} // namespace LibreSCRS::Certificate

/// @brief `std::hash` specialisation enabling use of #LibreSCRS::Certificate::ObjectIdentifier
///        as a key in unordered associative containers.
/// @since 4.0
template <>
struct std::hash<LibreSCRS::Certificate::ObjectIdentifier>
{
    /// @brief Hashes #LibreSCRS::Certificate::ObjectIdentifier::dottedDecimal.
    std::size_t operator()(const LibreSCRS::Certificate::ObjectIdentifier& oid) const noexcept
    {
        return std::hash<std::string>{}(oid.dottedDecimal);
    }
};
