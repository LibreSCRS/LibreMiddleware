// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif
#pragma once

#include <LibreSCRS/Signing/Enums.h> // LibreSCRS::Signing::SignatureFormat

#include <cstdint>
#include <cstring>
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
        static constexpr std::string_view kPdfMagic = "%PDF-";
        const bool ok = doc.size() >= 8 && std::memcmp(doc.data(), kPdfMagic.data(), kPdfMagic.size()) == 0;
        if (!ok)
            return std::string{"Input is not a PDF (missing %PDF- header or too small)"};
    }
    return std::nullopt;
}

} // namespace LibreSCRS::Signing::detail
