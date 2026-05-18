// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

#include "types.h"
#include "ttf_subset.h"

#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace libresign {

class Pkcs11Token;

/// @brief Bundle of artefacts produced by createAppearanceStream().
///
/// The PDF appearance content stream and the matching subsetted Liberation
/// Sans font program must be emitted together — the content stream
/// references new GIDs that only the subset knows. Returning both
/// atomically removes the temporal coupling that an internal cache member
/// would impose between createAppearanceStream() and preparePdf().
struct AppearanceData
{
    std::vector<uint8_t> contentStream;
    TtfSubset subset;
};

class PAdESModule
{
public:
    SigningResult sign(const std::vector<uint8_t>& pdfData, Pkcs11Token& token, SignatureLevel level,
                       const TSAConfig& tsa, const VisualSignatureParams& visual);

    /// @brief Append a new signer to an existing PAdES PDF.
    ///
    /// PAdES' incremental-update structure means a prior-signed PDF is itself
    /// a valid input to @ref sign — the new sig field, widget, and CMS occupy
    /// a fresh incremental update layered on top. This method is a thin
    /// wrapper that documents the semantic intent and lets the per-format
    /// dispatcher reach a uniform API.
    ///
    /// @param prior        the existing PDF (may carry one or more PAdES sigs)
    /// @param originalDoc  may be empty (the original is recoverable from the
    ///                     PAdES incremental structure); when non-empty, a
    ///                     future enhancement can verify it matches the prior
    ///                     PDF's signed range — currently informational only
    /// @param token        signing token (already opened + logged in)
    /// @param level        desired signature level for the NEW signature
    /// @param tsa          TSA config for the new signature
    /// @param visual       visual signature params for the new field
    /// @return @ref SigningResult — same shape as @ref sign
    [[nodiscard]] SigningResult appendSigner(std::span<const uint8_t> prior, std::span<const uint8_t> originalDoc,
                                             Pkcs11Token& token, SignatureLevel level, const TSAConfig& tsa,
                                             const VisualSignatureParams& visual);

    /// @brief Build the PDF appearance content stream and the matching
    /// subsetted Liberation Sans font program.
    ///
    /// Returns both atomically so callers don't have to track an implicit
    /// ordering coupling between content stream emission and font object
    /// emission.
    [[nodiscard]] AppearanceData createAppearanceStream(const VisualSignatureParams& visual) const;

private:
    struct PreparedPdf
    {
        std::vector<uint8_t> bytes;
        size_t contentsHexStart; // offset where hex string starts (after '<')
        size_t contentsHexLen;   // length of hex placeholder in bytes (chars/2)
    };

    PreparedPdf preparePdf(const std::vector<uint8_t>& pdfData, const VisualSignatureParams& visual,
                           size_t contentsAllocBytes);
};

} // namespace libresign
