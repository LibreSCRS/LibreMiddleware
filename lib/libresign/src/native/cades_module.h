// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

#include "types.h"
#include "native/revocation_client.h"

#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace libresign {

class Pkcs11Token;

class CAdESModule
{
public:
    // Create CAdES B-B detached signature.
    // Returns DER-encoded CMS SignedData.
    std::vector<uint8_t> signBB(const std::vector<uint8_t>& data, Pkcs11Token& token);

    // Upgrade B-B -> B-T: add signature timestamp.
    std::vector<uint8_t> addTimestamp(const std::vector<uint8_t>& cms, const TSAConfig& tsa);

    // Upgrade B-T -> B-LT: add revocation data.
    std::vector<uint8_t> addRevocationData(const std::vector<uint8_t>& cms, const RevocationData& revData);

    // Upgrade B-LT -> B-LTA: add archive timestamp.
    std::vector<uint8_t> addArchiveTimestamp(const std::vector<uint8_t>& cms, const TSAConfig& tsa);

    // Convenience: sign at requested level in one call.
    SigningResult sign(const std::vector<uint8_t>& data, Pkcs11Token& token, SignatureLevel level,
                       const TSAConfig& tsa);

    /// @brief Append a new SignerInfo to a prior detached CAdES signature.
    ///
    /// Multi-signer CAdES per ETSI EN 319 122-1: each signer's SignerInfo
    /// sits side-by-side in the same SignedData. The new signer signs the
    /// same originalDoc bytes as the existing ones; each SignerInfo carries
    /// its own signing-cert ESS attribute and its own optional B-T / B-LT /
    /// B-LTA unsigned attributes.
    ///
    /// B-B for the new signer is fully implemented. Level upgrades above
    /// B-B for a single signer require @ref addTimestamp /
    /// @ref addRevocationData / @ref addArchiveTimestamp to grow per-signer
    /// targeting (today they operate on the first SignerInfo only). Until
    /// that rework lands, this method fails fast with
    /// @ref SignFailureKind::PolicyViolation when @p level is above
    /// @c SignatureLevel::B_B rather than silently producing a spec-wrong
    /// document.
    ///
    /// @param prior        DER-encoded prior CMS ContentInfo (detached)
    /// @param originalDoc  the original payload — MUST match what the prior
    ///                     signers signed; empty input is rejected because
    ///                     a detached CMS does not carry the payload
    /// @param token        signing token (already opened + logged in)
    /// @param level        desired level for the NEW signer (B-B only)
    /// @param tsa          TSA config — unused at B-B; reserved for the
    ///                     per-signer B-T+ rework
    /// @return @ref SigningResult — DER-encoded CMS with the appended signer
    [[nodiscard]] SigningResult appendSigner(std::span<const uint8_t> prior, std::span<const uint8_t> originalDoc,
                                             Pkcs11Token& token, SignatureLevel level, const TSAConfig& tsa);
};

} // namespace libresign
