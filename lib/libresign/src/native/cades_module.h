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

    // The three upgrade helpers below act on the CMS's FIRST SignerInfo, which
    // is unambiguous only on a single-signer document (the PAdES path, where
    // each PDF signature is its own CMS). Multi-signer documents go through
    // sign() / appendSigner(), whose shared ladder targets one signer by
    // pointer — a SignerInfo's position is not stable across a DER encode,
    // because signerInfos is an ASN.1 SET OF and DER writes SET OF members in
    // sorted-encoding order.

    // Upgrade B-B -> B-T: add signature timestamp.
    std::vector<uint8_t> addTimestamp(const std::vector<uint8_t>& cms, const TSAConfig& tsa);

    // Embed the issuing CA chain (chainDer[1..], leaf already carried by the
    // SignerInfo) in the CMS certificates set so a B-LT signature is
    // self-contained for path building. No-op for a chain of <= 1 cert.
    std::vector<uint8_t> addCertificateChain(const std::vector<uint8_t>& cms,
                                             const std::vector<std::vector<uint8_t>>& chainDer);

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
    /// B-B, B-T and B-LT are supported for the new signer: the signature
    /// timestamp and the revocation values are per-signer unsigned attributes,
    /// applied to the appended SignerInfo alone through the same ladder
    /// sign() uses. B-LT additionally embeds the new signer's path material,
    /// which is a union into the shared certificate set — prior signers'
    /// certificates are never evicted.
    ///
    /// B-LTA fails fast with @ref SignFailureKind::PolicyViolation. The
    /// archive-timestamp message imprint of ETSI EN 319 122-1 §5.5.4 is
    /// computed over the whole SignedData, certificate set included, so an
    /// archive timestamp minted for an appended signer would describe a
    /// document state the prior signers' archive timestamps do not — and
    /// theirs cannot be recomputed without their PKCS#11 sessions.
    ///
    /// @param prior        DER-encoded prior CMS ContentInfo (detached)
    /// @param originalDoc  the original payload — MUST match what the prior
    ///                     signers signed; empty input is rejected because
    ///                     a detached CMS does not carry the payload
    /// @param token        signing token (already opened + logged in)
    /// @param level        desired level for the NEW signer (B-B, B-T or B-LT)
    /// @param tsa          TSA config — required from B-T upwards
    /// @return @ref SigningResult — DER-encoded CMS with the appended signer
    [[nodiscard]] SigningResult appendSigner(std::span<const uint8_t> prior, std::span<const uint8_t> originalDoc,
                                             Pkcs11Token& token, SignatureLevel level, const TSAConfig& tsa);
};

} // namespace libresign
