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

#include <LibreSCRS/Auth/ErrorKeys.h>
#include <LibreSCRS/LocalizedText.h>
#include <LibreSCRS/Signing/SigningResult.h>
#include <types.h>

#include <string>
#include <string_view>
#include <utility>

namespace LibreSCRS::Signing::detail {

/// Map a libresign failure to a LibreSCRS status code.
///
/// Primary path (4.2+): `r.failureKind` carries a typed
/// `libresign::SignFailureKind` that the module set at the precise point
/// the failure was known. Closed switch under `-Wswitch-enum` so adding a
/// new kind triggers a compile error here.
///
/// Fallback path (legacy 4.0/4.1 callers): when `failureKind` is unset
/// (e.g. PIN-failure surfacing via Pkcs11Token throw before any module
/// gets a chance to classify), parse `errorMessage` substring tokens to
/// recover PIN / card-blocked / TSA classes. Canonical hex reference:
///
///   CKR_PIN_INCORRECT = 0x000000A0
///   CKR_PIN_INVALID   = 0x000000A1
///   CKR_PIN_LEN_RANGE = 0x000000A2
///   CKR_PIN_EXPIRED   = 0x000000A3
///   CKR_PIN_LOCKED    = 0x000000A4
///
/// The fallback deliberately does NOT check the lowercase substring "pin":
/// that false-positive-matches strings like "pipeline" or filesystem paths.
inline LibreSCRS::Signing::SigningResult::Status classifyLibresignError(const libresign::SigningResult& r)
{
    using S = LibreSCRS::Signing::SigningResult::Status;
    using libresign::SignFailureKind;

    if (r.failureKind.has_value()) {
        switch (*r.failureKind) {
        case SignFailureKind::TsaUnreachable:
            return S::TsaUnreachable;
        case SignFailureKind::PinFailed:
            return S::PinVerificationFailed;
        case SignFailureKind::UserCancelled:
            return S::UserCancelled;
        case SignFailureKind::InvalidInput:
            return S::InvalidRequest;
        case SignFailureKind::PolicyViolation:
            return S::InvalidRequest;
        case SignFailureKind::CardError:
        case SignFailureKind::RevocationFetchFailed:
        case SignFailureKind::PdfPreparationError:
        case SignFailureKind::XmlSerializationError:
        case SignFailureKind::JsonSerializationError:
        case SignFailureKind::ZipBuildError:
        case SignFailureKind::OpensslError:
        case SignFailureKind::EngineError:
            return S::SigningEngineError;
        }
        return S::SigningEngineError; // defensive — switch closes via -Wswitch-enum on every value
    }

    // Legacy fallback: substring match on errorMessage. Reached only when
    // the module returned the typed shape without populating failureKind,
    // OR when a CKR exception propagates from Pkcs11Token before any
    // module wraps it. Signing-engine modules populate failureKind on
    // every return path; this branch survives for the Pkcs11Token
    // exception path.
    const std::string& detail = r.errorMessage;
    auto contains = [&](std::string_view needle) { return detail.find(needle) != std::string::npos; };

    if (contains("CKR 0x000000A0") || contains("CKR 0x000000A1") || contains("CKR 0x000000A2") ||
        contains("CKR_PIN_INCORRECT") || contains("wrong PIN") || contains("Wrong PIN"))
        return S::PinVerificationFailed;

    if (contains("CKR 0x000000A3") || contains("CKR 0x000000A4") || contains("CKR_PIN_LOCKED") ||
        contains("CKR_PIN_EXPIRED") || contains("BLOCKED") || contains("locked"))
        return S::CardBlocked;

    if (contains("timestamp") || contains("TSA") || contains("tsa") || contains("timestamping"))
        return S::TsaUnreachable;

    return S::SigningEngineError;
}

/// Translate a typed libresign failure kind into the user-facing
/// @ref LibreSCRS::LocalizedText carried by @ref SigningResult::userMessage.
///
/// Closed switch under `-Wswitch-enum` so adding a new
/// `libresign::SignFailureKind` value fails to compile here until the
/// mapping is updated — keeping the user-facing message contract aligned
/// with the engine-side classification.
///
/// Catch-all engine-side categories (PdfPreparationError, *SerializationError,
/// ZipBuildError, OpensslError, EngineError) collapse onto the generic
/// @ref Auth::ErrorKeys::signingEngineError message: the GUI surfaces
/// "see log for details" because these are bug-class failures the user
/// cannot recover from at the UI layer.
inline LibreSCRS::LocalizedText kindToUserMessage(libresign::SignFailureKind k)
{
    using libresign::SignFailureKind;
    namespace EK = LibreSCRS::Auth::ErrorKeys;
    switch (k) {
    case SignFailureKind::TsaUnreachable:
        return EK::tsaUnreachable();
    case SignFailureKind::RevocationFetchFailed:
        return EK::revocationFetchFailed();
    case SignFailureKind::CardError:
        return EK::cardError();
    case SignFailureKind::PinFailed:
        return EK::pinVerificationFailed();
    case SignFailureKind::UserCancelled:
        return EK::userCancelled();
    case SignFailureKind::InvalidInput:
        return EK::invalidRequest();
    case SignFailureKind::PolicyViolation:
        return EK::policyViolation();
    case SignFailureKind::PdfPreparationError:
    case SignFailureKind::XmlSerializationError:
    case SignFailureKind::JsonSerializationError:
    case SignFailureKind::ZipBuildError:
    case SignFailureKind::OpensslError:
    case SignFailureKind::EngineError:
        return EK::signingEngineError();
    }
    std::unreachable();
}

} // namespace LibreSCRS::Signing::detail
