// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

/// @file
/// @brief @ref LibreSCRS::Plugin::ReadResult — structured outcome of
///        @ref LibreSCRS::Plugin::CardPlugin::readCard, with named
///        factories for every @ref LibreSCRS::Plugin::ReadResult::Status
///        value so plugin ABI boundaries never see a raw exception.
///
/// @par Thread-safety
/// All types in this header are plain value aggregates; thread-compatible
/// per API-POLICY §8.

#include <LibreSCRS/Auth/ErrorKeys.h>
#include <LibreSCRS/Export.h>
#include <LibreSCRS/LocalizedText.h>
#include <LibreSCRS/Plugin/CardData.h>

#include <cstdint>
#include <optional>
#include <string>
#include <utility>

namespace LibreSCRS::Plugin {

/// @brief Plugin-returned outcome of @ref CardPlugin::readCard.
///
/// Exceptions crossing a dlopen'd plugin boundary with a mismatched C++
/// standard library are undefined behaviour; the ABI-safe contract is a
/// status enum + optional payload. Plugin implementations wrap their
/// internal logic in a catch-all and convert throws into a
/// @ref ReadResult::communicationError or @ref ReadResult::parseError
/// outcome at the boundary.
///
/// Construct via one of the named factories (@ref ok, @ref communicationError,
/// @ref parseError, @ref unsupportedCard, @ref authenticationFailed) so the
/// @ref status is guaranteed to be populated. Default construction is deleted
/// — an "undefined outcome" for a security-sensitive result is a footgun.
///
/// @par Mandatory userMessage
/// @ref userMessage is never wrapped in @c std::optional. Every factory
/// requires a @ref LibreSCRS::LocalizedText; callers with no card-specific
/// message pass one of the centralised builders in
/// @ref LibreSCRS::Auth::ErrorKeys (e.g. @ref Auth::ErrorKeys::genericComm).
/// Removes a class of "we forgot to set a message" bugs and gives the host
/// a translatable string for every error path.
struct ReadResult
{
    /// @brief Outcome classification for a card-read attempt.
    ///
    /// @ref Cancelled mirrors the sibling cancellation surface on
    /// @ref LibreSCRS::Signing::SigningResult::Status::Cancelled so caller-
    /// driven cancellation is distinguishable from a real I/O fault. The
    /// @ref LibreSCRS::Auth::ErrorKeys::cancelled diagnostic key remains
    /// the canonical translator-facing message for this status.
    /// @note Append-only: new status values may be added in future minor
    ///       releases. Consumer @c switch statements must include a
    ///       @c default branch.
    enum class Status : std::uint8_t {
        Ok,                   ///< Read completed successfully; @ref data is populated.
        CommunicationError,   ///< Card I/O failed (reader, SCard, PACE/SM).
        ParseError,           ///< Card returned data that did not match the expected layout.
        UnsupportedCard,      ///< Plugin advertised a match but the card data contradicts it.
        AuthenticationFailed, ///< PIN / CAN / MRZ / PUK required but not supplied or rejected.
        Cancelled             ///< Caller cancelled via the @ref CancelToken passed to readCard.
    };

    /// @brief Outcome classification. Always set by a factory.
    Status status;
    /// @brief Populated iff @ref status is @ref Status::Ok.
    std::optional<CardData> data;
    /// @brief Translator-friendly user-facing message. Always populated;
    ///        callers with no card-specific message pass one of the
    ///        @ref LibreSCRS::Auth::ErrorKeys builders.
    LocalizedText userMessage;
    /// @brief Optional diagnostic detail for logs / dev-tools.
    ///
    /// Never include raw secret material; used for logging and structured
    /// telemetry, not for end-user display.
    std::optional<std::string> diagnosticDetail;

    /// @brief Construct a successful result carrying @p cardData.
    ///
    /// Internally builds a @ref LocalizedText via @ref Auth::ErrorKeys::readOk
    /// (which allocates @c std::string). The body is wrapped in a top-level
    /// try/catch so the @c noexcept contract holds even on
    /// @c std::bad_alloc — the degraded outcome carries an empty
    /// @c userMessage but preserves @c Status::Ok and @c data.
    [[nodiscard]] static ReadResult ok(CardData cardData) noexcept
    {
        try {
            return ReadResult{Status::Ok, std::move(cardData), Auth::ErrorKeys::readOk(), std::nullopt};
        } catch (...) {
            return ReadResult{Status::Ok, std::nullopt, LocalizedText{}, std::nullopt};
        }
    }

    /// @brief Construct a communication-error result (card I/O failure).
    /// @param msg   Localized message surfaced to the user. Pass one of the
    ///              @ref LibreSCRS::Auth::ErrorKeys builders if no
    ///              card-specific text is appropriate.
    /// @param diag  Optional dev-facing diagnostic string (log / telemetry only).
    [[nodiscard]] static ReadResult communicationError(LocalizedText msg,
                                                       std::optional<std::string> diag = std::nullopt) noexcept
    {
        return ReadResult{Status::CommunicationError, std::nullopt, std::move(msg), std::move(diag)};
    }

    /// @brief Construct a parse-error result (unexpected data layout).
    [[nodiscard]] static ReadResult parseError(LocalizedText msg,
                                               std::optional<std::string> diag = std::nullopt) noexcept
    {
        return ReadResult{Status::ParseError, std::nullopt, std::move(msg), std::move(diag)};
    }

    /// @brief Construct an unsupported-card result: the plugin advertised a
    ///        match via @ref CardPlugin::canHandle or
    ///        @ref CardPlugin::canHandleConnection but the subsequent reads
    ///        show the card does not actually belong to this family.
    [[nodiscard]] static ReadResult unsupportedCard(LocalizedText msg,
                                                    std::optional<std::string> diag = std::nullopt) noexcept
    {
        return ReadResult{Status::UnsupportedCard, std::nullopt, std::move(msg), std::move(diag)};
    }

    /// @brief Construct an authentication-failed result: the plugin needs a
    ///        credential (PIN, CAN, MRZ, PUK) that was not supplied or was
    ///        rejected by the card.
    [[nodiscard]] static ReadResult authenticationFailed(LocalizedText msg,
                                                         std::optional<std::string> diag = std::nullopt) noexcept
    {
        return ReadResult{Status::AuthenticationFailed, std::nullopt, std::move(msg), std::move(diag)};
    }

    /// @brief Construct a cancelled result: the caller-supplied
    ///        @ref CancelToken reported cancellation before the plugin could
    ///        finish the read.
    ///
    /// @since 4.0 — sibling of @ref Signing::SigningResult::cancelled.
    /// Use this in preference to a @ref communicationError with a sentinel
    /// "cancelled" key; callers that route on @ref Status::Cancelled can
    /// then distinguish a clean user-cancel from a hardware I/O fault.
    [[nodiscard]] static ReadResult cancelled() noexcept
    {
        try {
            return ReadResult{Status::Cancelled, std::nullopt, Auth::ErrorKeys::cancelled(), std::nullopt};
        } catch (...) {
            return ReadResult{Status::Cancelled, std::nullopt, LocalizedText{}, std::nullopt};
        }
    }

    /// @brief Default construction is deleted — use a named factory to
    ///        guarantee @ref status is set. Matches the security-sensitive
    ///        default policy applied to @ref Auth::CredentialResult and
    ///        @ref Signing::SigningResult.
    ReadResult() = delete;

    /// @brief Copy-construct; independent copy of the payload.
    ReadResult(const ReadResult&) = default;
    /// @brief Move-construct; source is left in a valid but unspecified state.
    ReadResult(ReadResult&&) noexcept = default;
    /// @brief Copy-assign; independent copy of the payload.
    ReadResult& operator=(const ReadResult&) = default;
    /// @brief Move-assign; source is left in a valid but unspecified state.
    ReadResult& operator=(ReadResult&&) noexcept = default;
    /// @brief Destructor.
    ~ReadResult() = default;

private:
    // Field-wise ctor: private so external callers go through the named
    // factories (@ref ok / @ref communicationError / ... / @ref cancelled)
    // and the @ref status invariant holds at construction. The factories are
    // member functions and thus retain access. Per API-POLICY §5.1 — closed
    // construction surface for plugin-ABI results.
    ReadResult(Status s, std::optional<CardData> d, LocalizedText msg, std::optional<std::string> diag) noexcept
        : status(s), data(std::move(d)), userMessage(std::move(msg)), diagnosticDetail(std::move(diag))
    {}
};

} // namespace LibreSCRS::Plugin
