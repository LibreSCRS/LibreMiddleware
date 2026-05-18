// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

#include "native/pdf_dss.h"
#include "tsa_client.h"

#include <cstdint>
#include <vector>

namespace libresign {

/// @brief Append a /DocTimeStamp second incremental update to a B-LT PDF
///        per ETSI EN 319 142-1 §5.5 + ISO 32000-2 §12.8.5.
///
/// The returned byte block must be appended to @p bltPdf to produce a
/// B-LTA-conformant document. The block carries:
///   - one /Type /DocTimeStamp signature dictionary with
///     /SubFilter /ETSI.RFC3161 and the DER-encoded RFC 3161
///     TimeStampToken hex-embedded into /Contents
///   - one /FT /Sig field + invisible /Subtype /Widget annotation
///     (Rect [0 0 0 0] — DocTimeStamps carry no visual)
///   - a new catalog override whose /AcroForm.Fields extends the prior
///     Fields array with the new signature field
///   - an optional /DSS streams + dict block carrying the TSA cert
///     chain when @p tsaChainMaterial is non-empty (VRI keyed by the
///     SHA-1 of the TST bytes per ISO 32000-2 §12.8.4.3)
///   - the xref table of this incremental update, its trailer with
///     /Prev pointing at the prior startxref, the new startxref, and
///     the closing %%EOF
///
/// The TST is acquired by SHA-256-hashing the byte range that excludes
/// the /Contents placeholder of THIS update (the same byte-range
/// mechanic as a regular signature), then invoking
/// @ref TSAClient::timestamp on that hash. The returned token is the
/// bare RFC 3161 TimeStampToken (no additional CAdES wrapping) — that
/// IS the content of a /DocTimeStamp per ETSI EN 319 142-1 §5.5.
///
/// @param bltPdf       the complete B-LT PDF (sig dict + DSS already present)
/// @param tsa          TSA endpoint configuration
/// @param tsaChainMat  cert / CRL / OCSP material for the TSA's own chain;
///                     pass an empty @ref PdfDssMaterial to skip the
///                     embedded DSS update (the TST will still be valid
///                     but downstream validators may downgrade LTA).
/// @return the new incremental block; the caller appends it to @p bltPdf
///         to produce the B-LTA PDF.
/// @throws std::runtime_error on parse failure of @p bltPdf, TSA
///         transport / protocol failure, or /Contents allocation
///         insufficiency (when the returned TST exceeds the 16 KiB
///         placeholder).
[[nodiscard]] std::vector<std::uint8_t> appendDocTimeStamp(const std::vector<std::uint8_t>& bltPdf,
                                                           const TSAConfig& tsa, const PdfDssMaterial& tsaChainMat);

} // namespace libresign
