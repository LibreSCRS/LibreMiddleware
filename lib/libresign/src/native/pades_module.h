// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

#include "types.h"
#include "ttf_subset.h"

#include <cstdint>
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
