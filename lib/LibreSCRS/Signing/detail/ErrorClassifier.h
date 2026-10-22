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

#include <utility>

namespace LibreSCRS::Signing::detail {

/// Map a libresign failure to a LibreSCRS status code.
///
/// `r.failureKind` carries the typed `libresign::SignFailureKind` that the
/// engine set at the precise point the failure was known; every failure is
/// made with one. Closed switch under `-Wswitch-enum` so adding a new kind
/// triggers a compile error here.
inline LibreSCRS::Signing::SigningResult::Status classifyLibresignError(const libresign::SigningResult& r)
{
    using S = LibreSCRS::Signing::SigningResult::Status;
    using libresign::SignFailureKind;

    if (!r.failureKind.has_value())
        return S::SigningEngineError;
    switch (*r.failureKind) {
    case SignFailureKind::TsaUnreachable:
        return S::TsaUnreachable;
    case SignFailureKind::PinFailed:
        return S::PinVerificationFailed;
    case SignFailureKind::PinBlocked:
        return S::CardBlocked;
    case SignFailureKind::UserCancelled:
        return S::UserCancelled;
    case SignFailureKind::InvalidInput:
        return S::InvalidRequest;
    case SignFailureKind::PolicyViolation:
        return S::InvalidRequest;
    // Document-content faults: the bytes are not a valid document of the
    // requested format. Client-input, user-fixable — its own status so the
    // client says "fix your file", not "engine error".
    case SignFailureKind::PdfPreparationError:
    case SignFailureKind::InvalidDocument:
        return S::InvalidDocument;
    case SignFailureKind::CardError:
    case SignFailureKind::RevocationFetchFailed:
    // Chain-incomplete keeps the engine-error status (LC's -Wswitch-enum
    // consumers gain no public enum value); the dedicated user-message
    // key below carries the actionable distinction.
    case SignFailureKind::CertificateChainIncomplete:
    case SignFailureKind::XmlSerializationError:
    case SignFailureKind::JsonSerializationError:
    case SignFailureKind::ZipBuildError:
    case SignFailureKind::OpensslError:
    case SignFailureKind::EngineError:
        return S::SigningEngineError;
    }
    return S::SigningEngineError; // defensive — switch closes via -Wswitch-enum on every value
}

/// Translate a typed libresign failure kind into the user-facing
/// @ref LibreSCRS::LocalizedText carried by @ref SigningResult::userMessage.
///
/// Closed switch under `-Wswitch-enum` so adding a new
/// `libresign::SignFailureKind` value fails to compile here until the
/// mapping is updated — keeping the user-facing message contract aligned
/// with the engine-side classification.
///
/// Catch-all engine-side categories (*SerializationError, ZipBuildError,
/// OpensslError, EngineError) collapse onto the generic
/// @ref Auth::ErrorKeys::signingEngineError message: the GUI surfaces
/// "see log for details" because these are bug-class failures the user
/// cannot recover from at the UI layer. Document-content faults
/// (PdfPreparationError, InvalidDocument) instead map to
/// @ref Auth::ErrorKeys::invalidDocument — a user-fixable "replace the file"
/// class distinct from the engine bucket.
inline LibreSCRS::LocalizedText kindToUserMessage(libresign::SignFailureKind k)
{
    using libresign::SignFailureKind;
    namespace EK = LibreSCRS::Auth::ErrorKeys;
    switch (k) {
    case SignFailureKind::TsaUnreachable:
        return EK::tsaUnreachable();
    case SignFailureKind::RevocationFetchFailed:
        return EK::revocationFetchFailed();
    case SignFailureKind::CertificateChainIncomplete:
        return EK::certificateChainIncomplete();
    case SignFailureKind::CardError:
        return EK::cardError();
    case SignFailureKind::PinFailed:
        return EK::pinVerificationFailed();
    // No message of its own: the card is what failed the user, and the status
    // (CardBlocked) carries the distinction.
    case SignFailureKind::PinBlocked:
        return EK::cardError();
    case SignFailureKind::UserCancelled:
        return EK::userCancelled();
    case SignFailureKind::InvalidInput:
        return EK::invalidRequest();
    case SignFailureKind::PolicyViolation:
        return EK::policyViolation();
    case SignFailureKind::PdfPreparationError:
    case SignFailureKind::InvalidDocument:
        return EK::invalidDocument();
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
