// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

// Internal (non-public) helper: translate the public
// @ref LibreSCRS::Signing::SigningRequest into the corresponding
// @ref libresign::SigningRequest that the native / DSS backends consume.
//
// This header is intentionally outside include/ — it is not part of the
// public LibreMiddleware API. It lives under lib/ so that:
//   * SigningService.cpp can include it to keep the translation in one place.
//   * The unit test suite (test/LibreSCRS_Signing_test.cpp) can exercise the
//     exact production translation without spinning up a PC/SC reader, a
//     PKCS#11 token, or a live filesystem input — isolating the bridge
//     contract from end-to-end test scaffolding.
//
// Bodies live in RequestBridge.cpp : with two
// includers (SigningService.cpp and the bridge test), the inline-in-header
// shape delivered zero reuse benefit and forced the test to link its own
// instantiation rather than the production one. Moving to a .cpp means
// tests and production link the identical symbol — strongest possible
// oracle, and protects against future `static` locals / #ifdef TESTING
// divergence.
//
// The helper translates everything that comes from the public
// SigningRequest: fileName, format, packaging, level, visual-dictionary
// fields (reason / location / contactInfo) and — when @ref visualParams is
// configured — the visual appearance rectangle. It deliberately does NOT
// touch @c libReq.document or @c libReq.tsa: those carry state sourced
// outside the request (file bytes and the service-level TsaProvider
// snapshot), which the caller wires up in @c SigningService::sign.
//
// Do NOT depend on this header from consumer code: the mapping is an
// implementation detail of the libresign adapter.

#include <LibreSCRS/Signing/Enums.h>
#include <LibreSCRS/Signing/SigningRequest.h>
#include <LibreSCRS/Signing/VisualSignatureParams.h>

#include <types.h>

namespace LibreSCRS::Signing::detail {

/// Translate the public @ref SignatureFormat onto libresign's enum.
libresign::SignatureFormat mapFormat(LibreSCRS::Signing::SignatureFormat f);

/// Translate the public @ref SignatureLevel onto libresign's enum.
libresign::SignatureLevel mapLevel(LibreSCRS::Signing::SignatureLevel l);

/// Translate the public @ref PackagingMode onto libresign's enum.
libresign::SignaturePackaging mapPackaging(LibreSCRS::Signing::PackagingMode p);

/// Translate the public @ref SigningRequest into the libresign-internal
/// @ref libresign::SigningRequest that the sign-module pipelines consume.
///
/// Leaves @c out.document and @c out.tsa untouched: document bytes are
/// loaded by the caller from @c request.inputFile(), and the TSA config is
/// driven by the service-level provider snapshot (see
/// @c SigningService::sign). This keeps the bridge a pure, side-effect-free
/// field-by-field translation that is trivially unit-testable.
///
/// @par Invisible-signature semantics
/// The PDF signature-dictionary fields @c /Reason, @c /Location and
/// @c /ContactInfo are defined by ISO 32000-1:2008 §12.8.1 as siblings of
/// @c /ByteRange — they describe the signature itself, not any visual
/// widget. Consequently they are forwarded into
/// @c out.visual.{reason,location,contactInfo} unconditionally, regardless
/// of whether the caller configured a visible signature appearance. Only
/// @c visual.enabled and the on-page rectangle depend on
/// @ref SigningRequest::visualParams being populated.
///
/// @par Visual-appearance surface (4.0 vs. 4.1+)
/// libresign::VisualSignatureParams carries the fields that the current
/// PAdES engine honours: @c enabled + @c page + geometry
/// (@c x / @c y / @c width / @c height) + @c text. The public
/// @ref LibreSCRS::Signing::VisualSignatureParams 4.0 surface maps 1:1
/// onto these fields.
///
/// Font family / font size / background image: NOT part of the 4.0 public
/// surface AND not present in @c libresign::VisualSignatureParams. A 4.1+
/// reintroduction requires extending BOTH sides — the public struct AND
/// the internal struct — plus wiring the engine renderer to honour them.
/// The 4.0 surface drop is deliberate: shipping the three fields without
/// wiring would give consumers silent-ignore behaviour for a visible
/// signature-appearance property, which is worse than not offering the
/// knob at all.
void translatePublicRequestToLibresign(const LibreSCRS::Signing::SigningRequest& request,
                                       libresign::SigningRequest& out);

} // namespace LibreSCRS::Signing::detail
