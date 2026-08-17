// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif
#pragma once

#include <LibreSCRS/Signing/Enums.h> // LibreSCRS::Signing::SignatureFormat

#include <types.h> // libresign::kPdfMagic / kPdfHeaderScanWindow

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <format>
#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace LibreSCRS::Signing::detail {

// Cheap structural pre-check: does the document's leading magic / minimum size
// plausibly match the requested format? Returns a dev-facing diagnostic string
// when it obviously does not (so sign() fails fast with InvalidDocument before
// opening the card), or std::nullopt when the document is plausibly valid (the
// deep parse still runs and classifies precisely). Allocation-light, no parse.
[[nodiscard]] inline std::optional<std::string> documentPrecheck(SignatureFormat format,
                                                                 std::span<const std::uint8_t> doc)
{
    // ONLY PAdES gets a cheap magic gate: this is the exact sniff-vs-parse
    // mismatch #6 targets (a %PDF- prefix accepted at entry but rejected deep in
    // the PAdES parser). Every other format legitimately signs arbitrary bytes
    // at entry (ASiC-E packages any input into a fresh ZIP; CAdES-detached and
    // XAdES/JAdES envelope/detach over arbitrary content) — a magic gate there
    // would false-reject valid input. Emptiness is left to the existing entry
    // guards. No parse; allocation only on the (rare) reject path.
    if (format == SignatureFormat::Pades) {
        // The header need NOT sit at byte 0. PAdESModule::sign tolerates a
        // non-PDF prefix ahead of "%PDF-" (Adobe Acrobat Implementation Notes
        // §H.3 — multipart/form-data wrappers from web-form uploads are the
        // real-world source) and strips it before parsing, matching Acrobat,
        // Foxit, qpdf and pdfinfo. This gate scans the SAME window off the SAME
        // constants (libresign::kPdfHeaderScanWindow / kPdfMagic) so the two
        // cannot drift: a stricter gate fail-fasts documents the engine signs
        // happily, a looser one stops failing fast.
        //
        // The 8-byte floor is the pre-existing cheap minimum-size reject
        // ("%PDF-" plus a version), independent of where the header sits. It
        // also short-circuits the view construction on an empty span.
        static constexpr std::size_t kMinPdfBytes = 8;
        const bool ok =
            doc.size() >= kMinPdfBytes && std::string_view(reinterpret_cast<const char*>(doc.data()),
                                                           std::min(doc.size(), libresign::kPdfHeaderScanWindow))
                                                  .find(libresign::kPdfMagic) != std::string_view::npos;
        if (!ok)
            return std::format("Input is not a PDF (no {} header in the first {} bytes, or too small)",
                               libresign::kPdfMagic, libresign::kPdfHeaderScanWindow);
    }
    return std::nullopt;
}

} // namespace LibreSCRS::Signing::detail
