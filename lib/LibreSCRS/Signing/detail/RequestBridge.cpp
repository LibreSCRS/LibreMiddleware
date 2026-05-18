// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

// Implementation of the internal libresign request-translation bridge.
// Moved out of RequestBridge.h so the unit test
// suite (test/LibreSCRS_Signing_test.cpp) links against the identical symbol
// that SigningService.cpp links against — strongest possible test oracle,
// and protects against future `static` locals / #ifdef TESTING divergence.
//
// LIBRESCRS_INTERNAL_BUILD is defined on the LibreSCRS_Signing target
// (see lib/LibreSCRS/CMakeLists.txt), which both unblocks the header's
// #error guard here and is uniform across all four public LibreSCRS_*
// targets.

#include "RequestBridge.h"

namespace LibreSCRS::Signing::detail {

libresign::SignatureFormat mapFormat(LibreSCRS::Signing::SignatureFormat f)
{
    using S = LibreSCRS::Signing::SignatureFormat;
    switch (f) {
    case S::Pades:
        return libresign::SignatureFormat::Pades;
    case S::Cades:
        return libresign::SignatureFormat::Cades;
    case S::Xades:
        return libresign::SignatureFormat::Xades;
    case S::Jades:
        return libresign::SignatureFormat::Jades;
    case S::AsicE:
        return libresign::SignatureFormat::AsicE;
    }
    return libresign::SignatureFormat::Pades;
}

libresign::SignatureLevel mapLevel(LibreSCRS::Signing::SignatureLevel l)
{
    using L = LibreSCRS::Signing::SignatureLevel;
    switch (l) {
    case L::B_B:
        return libresign::SignatureLevel::B_B;
    case L::B_T:
        return libresign::SignatureLevel::B_T;
    case L::B_LT:
        return libresign::SignatureLevel::B_LT;
    case L::B_LTA:
        return libresign::SignatureLevel::B_LTA;
    }
    return libresign::SignatureLevel::B_B;
}

libresign::SignaturePackaging mapPackaging(LibreSCRS::Signing::PackagingMode p)
{
    using P = LibreSCRS::Signing::PackagingMode;
    return p == P::Detached ? libresign::SignaturePackaging::Detached : libresign::SignaturePackaging::Enveloped;
}

void translatePublicRequestToLibresign(const LibreSCRS::Signing::SigningRequest& request,
                                       libresign::SigningRequest& out)
{
    out.fileName = request.inputFile().filename().string();
    out.format = mapFormat(request.format());
    out.packaging = mapPackaging(request.packaging());
    out.level = mapLevel(request.level());
    out.allowExpiredCertificate = request.allowExpiredCert();

    // Signature-dictionary fields (ISO 32000-1:2008 §12.8.1): independent of
    // visual appearance. Always forwarded so an invisible signature can
    // still carry /Reason, /Location and /ContactInfo — mirrors
    // pades_module.cpp's unconditional emission of these keys.
    out.visual.reason = request.reason();
    out.visual.location = request.location();
    out.visual.contactInfo = request.contactInfo();

    // Visual appearance only when the caller supplied an explicit
    // VisualSignatureParams. When visualParams() is empty,
    // out.visual.enabled stays false (its default), preserving the default
    // "invisible signature" behaviour.
    //
    // Bind the optional to a local: visualParams() returns by value (a
    // copy), so repeated calls would copy repeatedly. Single bind, single
    // copy — also yields a stable reference for field access.
    if (auto visual = request.visualParams()) {
        // libresign::VisualSignatureParams carries the fields the current
        // PAdES engine honours: enabled + page + geometry (x/y/width/height)
        // + text. The public LibreSCRS::Signing::VisualSignatureParams 4.0
        // surface maps 1:1 onto these fields.
        //
        // Font family / font size / background image: NOT part of the 4.0
        // public surface AND not present in libresign::VisualSignatureParams.
        // A 4.1+ reintroduction requires extending BOTH sides — the public
        // struct AND the internal struct — plus wiring the engine renderer
        // to honour them. Deliberate 4.0 drop: shipping the three fields
        // without wiring would give consumers silent-ignore behaviour for a
        // visible property, which is worse than not offering the knob.
        out.visual.enabled = true;
        // Public API exposes a 0-based pageIndex (see VisualSignatureParams::Builder::pageIndex,
        // documented "pageIndex must be >= 0"); libresign's pades_module treats `visual.page`
        // as 1-based with `<= 0` meaning "last page". Without the +1 conversion every consumer
        // off-by-ones onto the previous page, and pageIndex(0) silently falls through to the
        // last-page fallback.
        out.visual.page = visual->pageIndex() + 1;
        out.visual.x = static_cast<float>(visual->x());
        out.visual.y = static_cast<float>(visual->y());
        out.visual.width = static_cast<float>(visual->width());
        out.visual.height = static_cast<float>(visual->height());
        out.visual.text = visual->textTemplate();
    }
}

} // namespace LibreSCRS::Signing::detail
