// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

/// @file
/// @brief @ref LibreSCRS::SecureChannel::PaceParams — public carrier for
///        the PACE handshake inputs consumed by @ref PaceChannel::establish,
///        plus the @ref LibreSCRS::SecureChannel::PaceSecurityInfo entry
///        returned by @ref parsePaceOidsFromCardAccess. Mirrors the internal
///        PACE handshake parameter type one-for-one so the public surface
///        does not depend on any internal header.

#include <LibreSCRS/Auth/PaceSecretKind.h>
#include <LibreSCRS/Export.h>
#include <LibreSCRS/Secure/String.h>

#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace LibreSCRS::SecureChannel {

/// @brief BSI TR-03110 standardised domain-parameter identifiers for PACE.
///
/// Per BSI TR-03110-3 §A.2.1.1, PACE parameter IDs 0–31 are reserved as a
/// closed enum referencing well-known elliptic-curve or DH-modulus parameter
/// sets. Values 0–7 and 17–31 are RFU; 8–16 are the populated assignments
/// the spec currently defines. Consumers reading EF.CardAccess values
/// outside the populated set should treat the card as advertising an
/// unsupported PACE parameter and fall back. Append-only per
/// API-POLICY §9 as the BSI table allocates additional values.
///
/// @since 4.1
enum class PaceStandardisedDomainParam : std::uint8_t {
    Secp192r1 = 8, ///< secp192r1 (NIST P-192) — discouraged for new deployments.
    BrainpoolP192r1 = 9,
    Secp224r1 = 10, ///< secp224r1 (NIST P-224).
    BrainpoolP224r1 = 11,
    Secp256r1 = 12,       ///< secp256r1 (NIST P-256).
    BrainpoolP256r1 = 13, ///< brainpoolP256r1 — most common Serbian / EU eID choice.
    BrainpoolP384r1 = 14,
    BrainpoolP512r1 = 15,
    Secp521r1 = 16, ///< secp521r1 (NIST P-521).
    // Append new values here as the BSI spec allocates them.
};

/// @brief Inputs for a single PACE handshake attempt.
///
/// Callers populate @ref oid + @ref paramId from parsing EF.CardAccess on
/// the card; @ref passwordType + @ref password come from the credentials
/// cache populated by the host or the credential provider.
///
/// @par ABI export
/// Plain aggregate; carries no LIBRESCRS_PUBLIC_API annotation on the
/// type itself per API-POLICY §6 (Export.h policy on aggregates — type-
/// level export attribute is meaningful only for classes with vtables /
/// out-of-line member functions; aggregates carry only field storage).
///
/// @since 4.1
struct PaceParams
{
    /// @brief PACE protocol OID, e.g. "0.4.0.127.0.7.2.2.4.2.4".
    std::string oid;

    /// @brief Variant of the shared secret carried in @ref password.
    LibreSCRS::Auth::PaceSecretKind passwordType = LibreSCRS::Auth::PaceSecretKind::Can;

    /// @brief Shared-secret bytes. Caller-owned; cleansed by the channel
    ///        on handshake completion.
    LibreSCRS::Secure::String password;

    /// @brief BSI TR-03110 standardised domain-parameter identifier
    ///        (default: @ref PaceStandardisedDomainParam::BrainpoolP256r1).
    PaceStandardisedDomainParam paramId = PaceStandardisedDomainParam::BrainpoolP256r1;
};

/// @brief One PACE security information entry parsed from EF.CardAccess.
///
/// Combines the BSI TR-03110 PACE OID with the standardised domain
/// parameter identifier the card advertises for that OID. Cards may
/// advertise the same OID with multiple parameter sets; consumers
/// receive one PaceSecurityInfo per (oid, paramId) pair.
///
/// Named struct + typed @ref paramId enum reads cleanly at call sites
/// (`info.paramId` over `pair.second`) and matches API-POLICY §7 on
/// avoiding `std::pair` in public return types: the field names carry
/// semantic intent the positional pair cannot.
///
/// @since 4.1
struct PaceSecurityInfo
{
    /// @brief PACE protocol OID, e.g. "0.4.0.127.0.7.2.2.4.2.4".
    std::string oid;
    /// @brief BSI TR-03110 standardised domain-parameter identifier
    ///        advertised by the card for @ref oid.
    PaceStandardisedDomainParam paramId;

    /// @since 4.1
    [[nodiscard]] bool operator==(const PaceSecurityInfo&) const noexcept = default;
};

/// @brief Parse EF.CardAccess (ASN.1 SET OF SecurityInfo) and return the
///        PACE entries it advertises as @ref PaceSecurityInfo records.
///
/// @p cardAccess is the raw byte content read from EF.CardAccess (FID 011C
/// under MF). Returns an empty vector when the file does not contain any
/// PACE SecurityInfo (i.e. the card does not advertise PACE).
///
/// @par Out-of-range paramId
/// EF.CardAccess values outside the populated BSI table (0–7 and 17–31 RFU
/// in TR-03110-3 §A.2.1.1) are skipped at the parsing boundary: the OID
/// is not returned in the result vector. The caller therefore never sees
/// a @ref PaceStandardisedDomainParam value that does not match one of the
/// enum members.
///
/// This is a pure function over the input bytes; no card I/O.
///
/// @since 4.1
[[nodiscard]] LIBRESCRS_PUBLIC_API std::vector<PaceSecurityInfo>
parsePaceOidsFromCardAccess(std::span<const std::uint8_t> cardAccess);

} // namespace LibreSCRS::SecureChannel
