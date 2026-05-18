// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace libresign {

/// @brief Validation material to embed in a PDF Document Security Store
///        dictionary (ETSI EN 319 142-1 §5.4.2 / ISO 32000-2 §12.8.4.3).
///
/// Each entry is the raw DER encoding of the artefact:
///   - @c certs           : signer + chain X.509 certificates
///   - @c crls            : DER-encoded CertificateList values
///   - @c ocspResponses   : DER-encoded OCSPResponse values
struct PdfDssMaterial
{
    std::vector<std::vector<std::uint8_t>> certs;
    std::vector<std::vector<std::uint8_t>> crls;
    std::vector<std::vector<std::uint8_t>> ocspResponses;
};

/// @brief Build the bytes of a Document Security Store dictionary object plus
///        its referenced indirect-object streams (one per cert/CRL/OCSP),
///        ready to be appended to a PDF incremental update.
///
/// Object numbers are allocated contiguously starting at @p firstObjNum :
///   @c firstObjNum                                  : the DSS dictionary
///   @c firstObjNum + 1 ... + N                      : N cert streams
///   @c firstObjNum + 1 + N ... + N + M              : M CRL streams
///   @c firstObjNum + 1 + N + M ... + N + M + K      : K OCSP streams
/// The caller is responsible for stitching the xref table, trailer and
/// @c startxref marker; this function emits only the indirect objects.
///
/// The VRI sub-dictionary is keyed by the lowercase-hex SHA-1 of the signed
/// /Contents bytes per ISO 32000-2 §12.8.4.3. Its /Cert /CRL /OCSP arrays
/// re-use the same top-level indirect references (no duplicate streams).
///
/// @param material        validation data to embed
/// @param firstObjNum     first available PDF object number
/// @param sigContentsHex  lowercase-hex SHA-1 of the signed /Contents bytes,
///                        emitted verbatim as the VRI sub-dictionary name per
///                        ISO 32000-2 §12.8.4.3; the caller is responsible for
///                        the SHA-1 hash and the lowercase-hex encoding
/// @param[out] dssObjNum  object number of the top-level DSS dictionary
/// @return concatenated indirect-object bytes (DSS + each stream); empty when
///         @p material has no certs, no CRLs and no OCSP responses, in which
///         case the caller should omit the /DSS catalog entry entirely.
std::vector<std::uint8_t> buildDssBlock(const PdfDssMaterial& material, std::size_t firstObjNum,
                                        const std::string& sigContentsHex, std::size_t& dssObjNum);

} // namespace libresign
