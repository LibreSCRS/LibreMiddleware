// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

// Internal (non-public) helper: translate a libresign::SigningResult into the
// corresponding LibreSCRS::Signing::SigningResult::Status value.
//
// This header is intentionally outside include/ — it is not part of the public
// LibreMiddleware API. It lives under lib/ so that:
//   * SigningService.cpp can include it to keep the classifier in one place.
//   * The unit test suite (test/LibreSCRS_Signing_test.cpp) can include it to
//     lock the error-mapping contract down without needing a live PC/SC reader.
//
// Do NOT depend on this header from consumer code: the mapping is an
// implementation detail of the libresign adapter.

#include <LibreSCRS/Signing/SigningResult.h>
#include <types.h>

#include <string>
#include <string_view>

namespace LibreSCRS::Signing::detail {

/// Map a libresign failure to a LibreSCRS status code.
///
/// The native backend surfaces PKCS#11 failures via `checkRv` in
/// `libresign::native::pkcs11_token.cpp` as strings of the form
/// `"<op> failed: CKR 0x<UPPER-HEX>"`; the DSS backend forwards the Java
/// exception message body. The classifier matches both shapes:
///
///   * Explicit `CKR 0x<UPPER-HEX>` tokens cover the native backend precisely.
///   * Upper-case CKR names and plain "Wrong PIN" / "BLOCKED" cover DSS output.
///
/// Canonical reference for the hex codes: PKCS#11 v2.40 §A.4.
///   CKR_PIN_INCORRECT = 0x000000A0
///   CKR_PIN_INVALID   = 0x000000A1
///   CKR_PIN_LEN_RANGE = 0x000000A2
///   CKR_PIN_EXPIRED   = 0x000000A3
///   CKR_PIN_LOCKED    = 0x000000A4
///
/// The classifier deliberately does NOT check the lowercase substring "pin":
/// that false-positive-matches strings like "pipeline" or filesystem paths.
inline LibreSCRS::Signing::SigningResult::Status classifyLibresignError(const libresign::SigningResult& r)
{
    const std::string& detail = r.errorMessage;
    auto contains = [&](std::string_view needle) { return detail.find(needle) != std::string::npos; };

    // PIN-entry failures: user gave a wrong / malformed PIN but the card is
    // still usable. The UI can reprompt.
    if (contains("CKR 0x000000A0") || contains("CKR 0x000000A1") || contains("CKR 0x000000A2") ||
        contains("CKR_PIN_INCORRECT") || contains("wrong PIN") || contains("Wrong PIN"))
        return LibreSCRS::Signing::SigningResult::Status::PinVerificationFailed;

    // Card-blocked / expired-PIN: terminal for this session; the user must
    // unblock via PUK (or the card is permanently locked).
    if (contains("CKR 0x000000A3") || contains("CKR 0x000000A4") || contains("CKR_PIN_LOCKED") ||
        contains("CKR_PIN_EXPIRED") || contains("BLOCKED") || contains("locked"))
        return LibreSCRS::Signing::SigningResult::Status::CardBlocked;

    // Timestamp authority failures — network / policy / format rejection.
    if (contains("timestamp") || contains("TSA") || contains("tsa") || contains("timestamping"))
        return LibreSCRS::Signing::SigningResult::Status::TsaUnreachable;

    return LibreSCRS::Signing::SigningResult::Status::SigningEngineError;
}

} // namespace LibreSCRS::Signing::detail
