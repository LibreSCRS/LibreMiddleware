// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

/// @file
/// @brief @ref LibreSCRS::Certificate::DistinguishedName — parsed X.509
///        Distinguished Name with typed convenience accessors.
///
/// @par Thread-safety
/// Thread-compatible (see API-POLICY §8). Both
/// @ref LibreSCRS::Certificate::DistinguishedNameComponent and
/// @ref LibreSCRS::Certificate::DistinguishedName are plain value aggregates
/// with no internal synchronisation. Distinct instances are independent;
/// concurrent reads of the same instance are race-free. All convenience
/// accessors are read-only.
///
/// @since 4.0

#include <LibreSCRS/Certificate/ObjectIdentifier.h>
#include <LibreSCRS/Export.h>

#include <string>
#include <vector>

namespace LibreSCRS::Certificate {

/// @brief One Relative Distinguished Name (RDN) component (e.g. `CN=John`).
///
/// #value is UTF-8 encoded — see #LibreSCRS::Certificate::ParsedCertificate
/// string-encoding policy: all ASN.1 string types (PrintableString,
/// UTF8String, BMPString, IA5String, T.61String) are converted to UTF-8 at
/// parse time.
/// @since 4.0
struct LIBRESCRS_PUBLIC_API DistinguishedNameComponent
{
    /// @brief Attribute type OID (e.g. 2.5.4.3 for commonName).
    ObjectIdentifier oid;
    /// @brief UTF-8 encoded attribute value.
    std::string value;
};

/// @brief A parsed Distinguished Name. Provides typed convenience accessors
///        for common RFC 5280 attributes plus a generic ordered list of all
///        RDNs (including unknown OIDs).
///
/// Convenience accessors return the first matching component's value or an
/// empty string if absent. The full ordered list is always available via
/// #components.
/// @since 4.0
struct LIBRESCRS_PUBLIC_API DistinguishedName
{
    /// @brief Ordered list of RDN components as parsed from the certificate.
    std::vector<DistinguishedNameComponent> components;

    /// @brief First commonName (CN) attribute, or empty.
    /// @throws std::bad_alloc on allocation failure.
    [[nodiscard]] std::string commonName() const;
    /// @brief First organization (O) attribute, or empty.
    /// @throws std::bad_alloc on allocation failure.
    [[nodiscard]] std::string organization() const;
    /// @brief First organizationalUnit (OU) attribute, or empty.
    /// @throws std::bad_alloc on allocation failure.
    [[nodiscard]] std::string organizationalUnit() const;
    /// @brief First country (C) attribute, or empty.
    /// @throws std::bad_alloc on allocation failure.
    [[nodiscard]] std::string country() const;
    /// @brief First stateOrProvinceName (ST) attribute, or empty.
    /// @throws std::bad_alloc on allocation failure.
    [[nodiscard]] std::string stateOrProvince() const;
    /// @brief First locality (L) attribute, or empty.
    /// @throws std::bad_alloc on allocation failure.
    [[nodiscard]] std::string locality() const;
    /// @brief First emailAddress (E) attribute, or empty.
    /// @throws std::bad_alloc on allocation failure.
    [[nodiscard]] std::string emailAddress() const;
};

} // namespace LibreSCRS::Certificate
