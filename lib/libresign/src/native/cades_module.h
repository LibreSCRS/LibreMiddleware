// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

#include "types.h"
#include "native/revocation_client.h"

#include <openssl/cms.h>

#include <cstdint>
#include <string>
#include <vector>

namespace libresign {

class SigningKey;

/// Embed the issuing CA chain (@p chainDer[1..]; the leaf is already carried
/// by the SignerInfo) in the CMS certificates set, so a B-LT signature is
/// self-contained for path building. Adds to the set, never replaces it.
void addCertificateChainTo(CMS_ContentInfo* cms, const std::vector<std::vector<uint8_t>>& chainDer);

/// Whether the CMS signer carries the `signing-time` signed attribute.
///
/// The two ETSI baselines built on this CMS disagree: EN 319 122-1 requires
/// `signing-time` in a CAdES baseline signature, while EN 319 142-1 forbids it
/// in a PAdES baseline one — there the claimed time is the signature
/// dictionary's `/M` entry. A CMS carrying it inside a PDF grades PAdES-BES,
/// not PAdES-BASELINE-B. No default: every caller states its profile.
enum class SigningTimeAttribute {
    Include, ///< CAdES / ASiC-E — EN 319 122-1 requires the attribute.
    Omit,    ///< PAdES — EN 319 142-1 forbids it; `/M` carries the time.
};

class CAdESModule
{
public:
    // Create CAdES B-B detached signature.
    // Returns DER-encoded CMS SignedData.
    std::vector<uint8_t> signBB(const std::vector<uint8_t>& data, SigningKey& key, SigningTimeAttribute signingTime);

    // The two upgrade helpers below act on the CMS's FIRST SignerInfo, which
    // is unambiguous only on a single-signer document (the PAdES path, where
    // each PDF signature is its own CMS). sign() runs a ladder that targets
    // its signer by pointer — a SignerInfo's position is not stable across a
    // DER encode, because signerInfos is an ASN.1 SET OF and DER writes SET OF
    // members in sorted-encoding order.

    // Upgrade B-B -> B-T: add signature timestamp.
    std::vector<uint8_t> addTimestamp(const std::vector<uint8_t>& cms, const TSAConfig& tsa);

    // Upgrade B-T -> B-LT: add revocation data.
    std::vector<uint8_t> addRevocationData(const std::vector<uint8_t>& cms, const RevocationData& revData);

    // Convenience: sign at requested level in one call.
    SigningResult sign(const std::vector<uint8_t>& data, SigningKey& key, SignatureLevel level, const TSAConfig& tsa);
};

/// Test seam: add the B-LTA archive timestamp to the FIRST SignerInfo of a
/// single-signer @p cms, exactly as sign() does for B-LTA. It lets a test hand
/// in a document sign() cannot produce, such as one whose SET OF members are
/// not in DER order. Not called by the library.
std::vector<uint8_t> addArchiveTimestampForTest(const std::vector<uint8_t>& cms, const TSAConfig& tsa);

} // namespace libresign
