// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

/// @file
/// @brief @ref LibreSCRS::Signing::SigningResult — status-coded outcome of a
///        signing attempt, with named factories for each @ref
///        LibreSCRS::Signing::SigningResult::Status value.
///
/// @since 4.0

#include <LibreSCRS/Auth/ErrorKeys.h>
#include <LibreSCRS/Export.h>
#include <LibreSCRS/LocalizedText.h>

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <utility>

namespace LibreSCRS::Signing {

/// @brief Outcome of @ref SigningService::sign.
///
/// Construct via one of the named factories (@ref ok, @ref invalidRequest,
/// @ref trustStoreUnavailable, @ref userCancelled, @ref pinVerificationFailed,
/// @ref cardBlocked, @ref tsaUnreachable, @ref signingEngineError) to guarantee
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
        /// Signature produced and written to @ref outputPath.
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
    };

    /// @brief Outcome classification. Always set by a factory.
    Status status;
    /// @brief Path to the output when @ref status is @ref Status::Ok.
    std::optional<std::filesystem::path> outputPath;
    /// @brief Translator-friendly user-facing message. Mandatory in 4.0;
    ///        callers with no specific message pass one of the
    ///        @ref LibreSCRS::Auth::ErrorKeys builders.
    /// @since 4.0 — was @c std::optional<LocalizedText> in 3.x.
    LocalizedText userMessage;
    /// @brief Technical detail suitable for logs; may be absent.
    std::optional<std::string> diagnosticDetail;

    // -- Named factories ---------------------------------------------------
    //
    // Factories are @c noexcept: the body only assembles fields by moving
    // already-constructed inputs. Per API-POLICY §5.3, named-factory
    // constructors for status-code results are marked noexcept so call-sites
    // in noexcept contexts (destructors, async pipelines) can use them
    // without exception-handler ceremony.

    /// @brief Successful signing; @p output is the written-to path.
    [[nodiscard]] static SigningResult ok(std::filesystem::path output) noexcept
    {
        return SigningResult{Status::Ok, std::move(output), Auth::ErrorKeys::signOk(), std::nullopt};
    }

    /// @brief Request validation failed.
    /// @param userMessage Optional translator-friendly user-facing message.
    ///        Pass @c std::nullopt for the developer-facing-only path
    ///        (purely contract violations such as empty outputPath, where
    ///        an English-only diagnostic is the best the caller has). When
    ///        @c std::nullopt, the factory substitutes the generic
    ///        @ref Auth::ErrorKeys text — 4.0 makes the
    ///        @ref userMessage field mandatory.
    /// @param diagnosticDetail Optional dev-facing diagnostic string for logs.
    [[nodiscard]] static SigningResult
    invalidRequest(LocalizedText userMessage, std::optional<std::string> diagnosticDetail = std::nullopt) noexcept
    {
        return SigningResult{Status::InvalidRequest, std::nullopt, std::move(userMessage), std::move(diagnosticDetail)};
    }

    /// @brief Request validation failed; diagnostic-only variant — the user
    ///        sees the @ref Auth::ErrorKeys generic invalid-request message.
    ///
    /// The name is deliberately long: call sites are signalling a real
    /// trade-off. Callers who can produce a translator-friendly
    /// @ref LibreSCRS::LocalizedText should prefer the two-argument
    /// @ref invalidRequest overload; reach for @ref invalidRequestDiagnosticOnly
    /// only when the failure is purely a developer-facing contract violation
    /// (e.g. empty outputPath), where an English-only diagnostic is already
    /// the best we can do.
    /// @since 4.0 — renamed from @c invalidRequest(std::string) to
    /// make the "no user-specific message" trade-off visible at the call
    /// site. In 4.0 the user message field is mandatory; this overload
    /// substitutes a generic @ref Auth::ErrorKeys text.
    [[nodiscard]] static SigningResult invalidRequestDiagnosticOnly(std::string diagnosticDetail) noexcept
    {
        return SigningResult{Status::InvalidRequest, std::nullopt,
                             LocalizedText{"librescrs.signing.error.invalidRequest", "Signing request is invalid.", {}},
                             std::move(diagnosticDetail)};
    }

    /// @brief Trust store could not be loaded (TL unreachable, cache unwritable, …).
    /// @param userMessage Optional translator-friendly user-facing message.
    ///        When @c std::nullopt, the factory substitutes the generic
    ///        @ref Auth::ErrorKeys::trustStoreUnavailable text.
    /// @param diagnosticDetail Optional dev-facing diagnostic string for logs.
    [[nodiscard]] static SigningResult
    trustStoreUnavailable(LocalizedText userMessage,
                          std::optional<std::string> diagnosticDetail = std::nullopt) noexcept
    {
        return SigningResult{Status::TrustStoreUnavailable, std::nullopt, std::move(userMessage),
                             std::move(diagnosticDetail)};
    }

    /// @brief Diagnostic-only trust-store-unavailable variant — substitutes
    ///        the generic @ref Auth::ErrorKeys::trustStoreUnavailable text.
    ///        Use only when no card-specific message is available; prefer
    ///        the two-argument overload otherwise.
    /// @since 4.0 — sibling pattern to
    /// @ref signingEngineErrorDiagnosticOnly. Replaces the 3.x
    /// `trustStoreUnavailable(std::optional<LocalizedText>)` shape.
    [[nodiscard]] static SigningResult trustStoreUnavailableDiagnosticOnly(std::string diagnosticDetail) noexcept
    {
        return SigningResult{Status::TrustStoreUnavailable, std::nullopt, Auth::ErrorKeys::trustStoreUnavailable(),
                             std::move(diagnosticDetail)};
    }

    /// @brief User cancelled the credential prompt.
    [[nodiscard]] static SigningResult userCancelled() noexcept
    {
        return SigningResult{Status::UserCancelled, std::nullopt, Auth::ErrorKeys::userCancelled(), std::nullopt};
    }

    /// @brief Card reported PIN-incorrect.
    [[nodiscard]] static SigningResult
    pinVerificationFailed(LocalizedText userMessage,
                          std::optional<std::string> diagnosticDetail = std::nullopt) noexcept
    {
        return SigningResult{Status::PinVerificationFailed, std::nullopt, std::move(userMessage),
                             std::move(diagnosticDetail)};
    }

    /// @brief Card reported the signing PIN as blocked.
    [[nodiscard]] static SigningResult cardBlocked(LocalizedText userMessage,
                                                   std::optional<std::string> diagnosticDetail = std::nullopt) noexcept
    {
        return SigningResult{Status::CardBlocked, std::nullopt, std::move(userMessage), std::move(diagnosticDetail)};
    }

    /// @brief TSA unreachable / not configured for a level that requires it.
    /// @param userMessage Optional translator-friendly user-facing message.
    ///        When @c std::nullopt, the factory substitutes a generic
    ///        TSA-unreachable message.
    /// @param diagnosticDetail Optional dev-facing diagnostic string for logs.
    [[nodiscard]] static SigningResult
    tsaUnreachable(LocalizedText userMessage, std::optional<std::string> diagnosticDetail = std::nullopt) noexcept
    {
        return SigningResult{Status::TsaUnreachable, std::nullopt, std::move(userMessage), std::move(diagnosticDetail)};
    }

    /// @brief Diagnostic-only TSA-unreachable variant — substitutes a
    ///        generic timestamp-authority-unreachable message. Use only
    ///        when no signing-engine-specific text is available; prefer
    ///        the two-argument overload otherwise.
    /// @since 4.0 — sibling pattern to
    /// @ref signingEngineErrorDiagnosticOnly. Replaces the 3.x
    /// `tsaUnreachable(std::optional<LocalizedText>)` shape.
    [[nodiscard]] static SigningResult tsaUnreachableDiagnosticOnly(std::string diagnosticDetail) noexcept
    {
        return SigningResult{
            Status::TsaUnreachable, std::nullopt,
            LocalizedText{"librescrs.signing.error.tsaUnreachable", "Timestamp authority is unreachable.", {}},
            std::move(diagnosticDetail)};
    }

    /// @brief Signing engine reported an error not classified by the other statuses.
    [[nodiscard]] static SigningResult
    signingEngineError(LocalizedText userMessage, std::optional<std::string> diagnosticDetail = std::nullopt) noexcept
    {
        return SigningResult{Status::SigningEngineError, std::nullopt, std::move(userMessage),
                             std::move(diagnosticDetail)};
    }

    /// @brief Diagnostic-only signing-engine error — substitutes the generic
    ///        @ref Auth::ErrorKeys::signingEngineError message. Use only
    ///        when no card-specific message is available; prefer the
    ///        two-argument overload otherwise.
    /// @since 4.0 — replaces the 3.x single-argument
    /// `signingEngineError(diag)` shape.
    [[nodiscard]] static SigningResult signingEngineErrorDiagnosticOnly(std::string diagnosticDetail) noexcept
    {
        return SigningResult{Status::SigningEngineError, std::nullopt, Auth::ErrorKeys::signingEngineError(),
                             std::move(diagnosticDetail)};
    }

    /// @brief Default construction is deleted — use a named factory. Security-
    ///        sensitive default "undefined outcome" values are not permitted.
    SigningResult() = delete;

    /// @brief Field-wise constructor used by the factories. Prefer the
    ///        factories at call sites; this constructor is public only so
    ///        `{...}` initialisation inside factories is expressible.
    SigningResult(Status s, std::optional<std::filesystem::path> out, LocalizedText user,
                  std::optional<std::string> diag)
        : status(s), outputPath(std::move(out)), userMessage(std::move(user)), diagnosticDetail(std::move(diag))
    {}

    /// @brief Move-construct from @p other.
    SigningResult(SigningResult&&) noexcept = default;
    /// @brief Move-assign from @p other.
    SigningResult& operator=(SigningResult&&) noexcept = default;
    /// @brief Copy-construct from @p other.
    ///
    /// Copyable by design (mirrors @ref LibreSCRS::Auth::CredentialResult's
    /// 4.0 change). @ref SigningResult carries no secret material —
    /// the fields are a @ref Status, a filesystem path, and two
    /// translator-friendly diagnostic blobs — so duplication raises no
    /// cleansing concern. Enabling copy composes with
    /// `std::optional<SigningResult>` and host code that wants to retain a
    /// result across a post-signing pipeline (log + UI + telemetry without
    /// threading the same moved-from value through every step).
    SigningResult(const SigningResult&) = default;
    /// @brief Copy-assign from @p other. Same rationale as the copy ctor.
    SigningResult& operator=(const SigningResult&) = default;
    ~SigningResult() = default;
};

} // namespace LibreSCRS::Signing
