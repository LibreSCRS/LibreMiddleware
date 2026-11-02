// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

/// @file
/// @brief @ref LibreSCRS::Signing::SigningResult — status-coded outcome of a
///        signing attempt, with named factories for each @ref
///        LibreSCRS::Signing::SigningResult::Status value.
///
/// @par Thread-safety
/// All types in this header are plain value aggregates; thread-compatible
/// per API-POLICY §8.
///
/// @since 4.0

#include <LibreSCRS/Auth/ErrorKeys.h>
#include <LibreSCRS/Export.h>
#include <LibreSCRS/LocalizedText.h>

#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace LibreSCRS::Signing {

/// @brief Outcome of @ref SigningService::sign.
///
/// Construct via one of the named factories (@ref okWithBytes, @ref invalidRequest,
/// @ref trustStoreUnavailableDiagnosticOnly, @ref userCancelled,
/// @ref pinVerificationFailed, @ref cardBlocked, @ref tsaUnreachable,
/// @ref signingEngineError, @ref invalidDocument) to guarantee
/// @ref status is set at construction. The type is intentionally not
/// default-constructible: a security-sensitive "undefined outcome" default is
/// not permitted.
///
/// @par 4.0 mandatory userMessage
/// @ref userMessage is no longer wrapped in @c std::optional. Every factory
/// requires a @ref LibreSCRS::LocalizedText; callers with no message-specific
/// text pass one of the centralised builders in
/// @ref LibreSCRS::Auth::ErrorKeys.
struct SigningResult
{
    /// @brief Outcome classification for a signing attempt.
    enum class Status : std::uint8_t {
        /// Signature produced; the signed document is in @ref signedDocumentBytes.
        Ok,
        /// Request validation failed — malformed/incomplete @ref SigningRequest,
        /// or empty `CredentialProvider`.
        InvalidRequest,
        /// The libresign backend rejected the trust configuration supplied at
        /// SigningService construction (unreachable Trusted List URL,
        /// unwritable cache directory, etc.).
        TrustStoreUnavailable,
        /// Credential provider returned UserCancelled.
        UserCancelled,
        /// PIN verification against the card failed.
        PinVerificationFailed,
        /// Card reports the signing PIN as blocked.
        CardBlocked,
        /// Timestamp authority could not be contacted (HTTP call failed /
        /// timed out, or no TsaProvider configured for a level that requires
        /// one — B-T / B-LT / B-LTA).
        TsaUnreachable,
        /// Underlying signing engine reported an error not otherwise
        /// classified by the other @ref Status values.
        SigningEngineError,
        /// @brief The document supplied for signing is invalid or unreadable
        ///        (wrong file type, corrupt, unparseable, or empty). Distinct
        ///        from @ref InvalidRequest (malformed request parameters) and
        ///        @ref SigningEngineError (unclassified engine fault). The user
        ///        fixes the input file. Append-only. @since 5.0
        InvalidDocument,
    };

    /// @brief Outcome classification. Always set by a factory.
    Status status;
    /// @brief Translator-friendly user-facing message. Always populated;
    ///        callers with no specific message pass one of the
    ///        @ref LibreSCRS::Auth::ErrorKeys builders.
    LocalizedText userMessage;
    /// @brief Technical detail suitable for logs; may be absent.
    std::optional<std::string> diagnosticDetail;
    /// @brief Signed artifact bytes, set when @ref status is @ref Status::Ok
    ///        (@ref okWithBytes); absent on every failure. @since 5.0
    std::optional<std::vector<std::uint8_t>> signedDocumentBytes;

    // -- Named factories ---------------------------------------------------
    //
    // Factories are @c noexcept: the body only assembles fields by moving
    // already-constructed inputs. Per API-POLICY §5.3, named-factory
    // constructors for status-code results are marked noexcept so call-sites
    // in noexcept contexts (destructors, async pipelines) can use them
    // without exception-handler ceremony.
    //
    // Factories that internally build a @ref LocalizedText (via the
    // @ref Auth::ErrorKeys helpers, which allocate std::string) wrap the
    // body in a top-level try/catch returning a degraded-but-valid result
    // (empty @c userMessage, same @c Status, no @c diagnosticDetail) on
    // @c std::bad_alloc so the noexcept contract is honoured even under
    // memory pressure. Factories that only move caller-supplied
    // @ref LocalizedText do not need the wrap (move-construction is
    // noexcept).

    /// @brief Successful signing: the signed artifact is returned in
    ///        @ref signedDocumentBytes; no file is written. @since 5.0
    [[nodiscard]] static SigningResult okWithBytes(std::vector<std::uint8_t> bytes) noexcept
    {
        // Only Auth::ErrorKeys::signOk() can throw (bad_alloc); it runs before
        // `bytes` is touched, so the catch path still owns `bytes` intact.
        try {
            SigningResult r{Status::Ok, Auth::ErrorKeys::signOk(), std::nullopt};
            r.signedDocumentBytes = std::move(bytes);
            return r;
        } catch (...) {
            SigningResult r{Status::Ok, LocalizedText{}, std::nullopt};
            r.signedDocumentBytes = std::move(bytes);
            return r;
        }
    }

    /// @brief Request validation failed.
    /// @param userMessage Translator-friendly user-facing message; callers
    ///        with nothing more specific pass @ref Auth::ErrorKeys::invalidRequest.
    /// @param diagnosticDetail Optional dev-facing diagnostic string for logs.
    [[nodiscard]] static SigningResult
    invalidRequest(LocalizedText userMessage, std::optional<std::string> diagnosticDetail = std::nullopt) noexcept
    {
        return SigningResult{Status::InvalidRequest, std::move(userMessage), std::move(diagnosticDetail)};
    }

    /// @brief Trust store could not be loaded (TL unreachable, cache
    ///        unwritable, …); the user sees the generic
    ///        @ref Auth::ErrorKeys::trustStoreUnavailable text.
    /// @since 4.0
    [[nodiscard]] static SigningResult trustStoreUnavailableDiagnosticOnly(std::string diagnosticDetail) noexcept
    {
        try {
            return SigningResult{Status::TrustStoreUnavailable, Auth::ErrorKeys::trustStoreUnavailable(),
                                 std::move(diagnosticDetail)};
        } catch (...) {
            return SigningResult{Status::TrustStoreUnavailable, LocalizedText{}, std::nullopt};
        }
    }

    /// @brief User cancelled the credential prompt.
    [[nodiscard]] static SigningResult userCancelled() noexcept
    {
        try {
            return SigningResult{Status::UserCancelled, Auth::ErrorKeys::userCancelled(), std::nullopt};
        } catch (...) {
            return SigningResult{Status::UserCancelled, LocalizedText{}, std::nullopt};
        }
    }

    /// @brief Card reported PIN-incorrect.
    [[nodiscard]] static SigningResult
    pinVerificationFailed(LocalizedText userMessage,
                          std::optional<std::string> diagnosticDetail = std::nullopt) noexcept
    {
        return SigningResult{Status::PinVerificationFailed, std::move(userMessage), std::move(diagnosticDetail)};
    }

    /// @brief Card reported the signing PIN as blocked.
    [[nodiscard]] static SigningResult cardBlocked(LocalizedText userMessage,
                                                   std::optional<std::string> diagnosticDetail = std::nullopt) noexcept
    {
        return SigningResult{Status::CardBlocked, std::move(userMessage), std::move(diagnosticDetail)};
    }

    /// @brief TSA unreachable / not configured for a level that requires it.
    /// @param userMessage Optional translator-friendly user-facing message.
    ///        When @c std::nullopt, the factory substitutes a generic
    ///        TSA-unreachable message.
    /// @param diagnosticDetail Optional dev-facing diagnostic string for logs.
    [[nodiscard]] static SigningResult
    tsaUnreachable(LocalizedText userMessage, std::optional<std::string> diagnosticDetail = std::nullopt) noexcept
    {
        return SigningResult{Status::TsaUnreachable, std::move(userMessage), std::move(diagnosticDetail)};
    }

    /// @brief Signing engine reported an error not classified by the other statuses.
    [[nodiscard]] static SigningResult
    signingEngineError(LocalizedText userMessage, std::optional<std::string> diagnosticDetail = std::nullopt) noexcept
    {
        return SigningResult{Status::SigningEngineError, std::move(userMessage), std::move(diagnosticDetail)};
    }

    /// @brief Diagnostic-only signing-engine error — substitutes the generic
    ///        @ref Auth::ErrorKeys::signingEngineError message. Use only
    ///        when no card-specific message is available; prefer the
    ///        two-argument overload otherwise.
    /// @since 4.0
    [[nodiscard]] static SigningResult signingEngineErrorDiagnosticOnly(std::string diagnosticDetail) noexcept
    {
        try {
            return SigningResult{Status::SigningEngineError, Auth::ErrorKeys::signingEngineError(),
                                 std::move(diagnosticDetail)};
        } catch (...) {
            return SigningResult{Status::SigningEngineError, LocalizedText{}, std::nullopt};
        }
    }

    /// @brief The document to be signed is invalid or unreadable.
    /// @param userMessage Translator-friendly user-facing message.
    /// @param diagnosticDetail Optional dev-facing diagnostic string for logs.
    [[nodiscard]] static SigningResult
    invalidDocument(LocalizedText userMessage, std::optional<std::string> diagnosticDetail = std::nullopt) noexcept
    {
        return SigningResult{Status::InvalidDocument, std::move(userMessage), std::move(diagnosticDetail)};
    }

    /// @brief Default construction is deleted — use a named factory. Security-
    ///        sensitive default "undefined outcome" values are not permitted.
    SigningResult() = delete;

    /// @brief Move-construct from @p other.
    SigningResult(SigningResult&&) noexcept = default;
    /// @brief Move-assign from @p other.
    SigningResult& operator=(SigningResult&&) noexcept = default;
    /// @brief Copy-construct from @p other.
    ///
    /// Copyable by design (mirrors @ref LibreSCRS::Auth::CredentialResult's
    /// 4.0 change). @ref SigningResult carries no secret material —
    /// the fields are a @ref Status, two translator-friendly diagnostic
    /// blobs and the signed document — so duplication raises no cleansing
    /// concern. Enabling copy composes with
    /// `std::optional<SigningResult>` and host code that wants to retain a
    /// result across a post-signing pipeline (log + UI + telemetry without
    /// threading the same moved-from value through every step).
    SigningResult(const SigningResult&) = default;
    /// @brief Copy-assign from @p other. Same rationale as the copy ctor.
    SigningResult& operator=(const SigningResult&) = default;
    ~SigningResult() = default;

private:
    // Field-wise ctor: private so external callers go through the named
    // factories (@ref okWithBytes / @ref invalidRequest / ... / @ref signingEngineError)
    // and the @ref status invariant holds at construction. The factories are
    // member functions and thus retain access. Per API-POLICY §5.1 — closed
    // construction surface for security-sensitive results.
    SigningResult(Status s, LocalizedText user, std::optional<std::string> diag) noexcept
        : status(s), userMessage(std::move(user)), diagnosticDetail(std::move(diag))
    {}
};

} // namespace LibreSCRS::Signing
