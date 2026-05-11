// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

/// @file
/// @brief @ref LibreSCRS::SmartCard::CardSession — pimpl-backed PC/SC
///        session handle — with the noexcept factory
///        @ref LibreSCRS::SmartCard::CardSession::open and the structured
///        @ref LibreSCRS::SmartCard::OpenError.

#include <LibreSCRS/Export.h>
#include <LibreSCRS/LocalizedText.h>

#include <cstdint>
#include <expected>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace LibreSCRS::SmartCard {

class CardSession;

// Forward-declare the LM-internal access points the public CardSession
// befriends. The actual declarations and implementations live in internal-
// only headers guarded by `#ifndef LIBRESCRS_INTERNAL_BUILD` so external
// consumers never see the underlying types (the implementation-detail
// `LibreSCRS::SmartCard::Internal::PCSCConnection` no longer appears in this public header at
// all — it is reached through @c detail::PcscBridge from internal sources
// only). A friend declaration targeting `detail::name(...)` / `detail::Type`
// still needs the namespace to exist for the friend lookup to match.
/// @cond internal
namespace detail {
LIBRESCRS_PUBLIC_API std::shared_ptr<CardSession> makeDetachedCardSession(std::string readerName);
struct PcscBridge;
LIBRESCRS_PUBLIC_API std::uint64_t sessionGeneration(const CardSession& session) noexcept;
} // namespace detail
/// @endcond

/// @brief Structured error describing why @ref CardSession::open failed.
///
/// @since 4.0
struct OpenError
{
    /// @brief Failure category.
    enum class Kind : std::uint8_t {
        /// Reader does not exist, was unplugged, or the PC/SC service could
        /// not be reached.
        ReaderUnavailable,
        /// Reader is present but carries no card, or the card was removed
        /// between enumeration and the open attempt.
        NoCardPresent,
        /// Card is present but the PC/SC protocol negotiation failed (T=0 /
        /// T=1 mismatch, reader fault, driver bug).
        ProtocolError,
    };

    /// @brief Failure category.
    Kind kind;
    /// @brief Translator-friendly message suitable for a user notification.
    ///
    /// Mandatory in 4.0; producers populate it unconditionally. Callers
    /// without a card-specific text should use one of the
    /// @ref LibreSCRS::Auth::ErrorKeys generic builders.
    /// @note Renamed from @c message in 4.0 for cross-type consistency
    ///       with @ref LibreSCRS::Signing::SigningResult::userMessage and
    ///       @ref LibreSCRS::Auth::CredentialResult::userMessage.
    /// @since 4.0 — was @c std::optional<LocalizedText> in 3.x.
    LocalizedText userMessage;
    /// @brief Optional dev-facing diagnostic (PC/SC return code text, etc.).
    ///        Never includes secret material.
    std::optional<std::string> diagnosticDetail;

    /// @brief Default constructor is deleted.
    ///
    /// In 3.x the userMessage was @c std::optional<LocalizedText>; an
    /// "absent" message was the explicit no-message state. In 4.0 the
    /// field is mandatory @c LocalizedText, but a default-constructed
    /// LocalizedText (empty key, empty fallback) is structurally a valid
    /// userMessage that renders as an empty string. Deleting the default
    /// ctor forces every production site to go through the field-wise
    /// constructor below or named factories — the safety net the
    /// optional-wrapper provided is preserved at the type system level.
    OpenError() = delete;

    /// @brief Field-wise constructor.
    ///
    /// Mirrors the @ref ReadResult / @ref SigningResult policy: the type's
    /// invariants (kind classified, userMessage populated) are established
    /// at construction time and cannot be silently bypassed.
    OpenError(Kind k, LocalizedText msg, std::optional<std::string> diag = std::nullopt) noexcept
        : kind(k), userMessage(std::move(msg)), diagnosticDetail(std::move(diag))
    {}
};

/// @brief Opaque handle for an active PC/SC session against a reader.
///
/// Construct via the noexcept factory @ref CardSession::open with the reader
/// name reported by LibreSCRS::SmartCard::MonitorService::listReaders. Move-only;
/// not copyable. Internally wraps LibreMiddleware's PC/SC connection
/// primitive behind a pimpl so consumers see no dependency on PC/SC headers.
///
/// Lifetime of the underlying hardware connection matches the CardSession
/// lifetime. Destroying the CardSession closes the connection. Consumers
/// that need shared ownership (e.g. to hand the session to
/// LibreSCRS::Signing::SigningService::sign) should move the opened session
/// into a @c std::shared_ptr<CardSession> via the helper below or take the
/// session out of the @c std::expected<CardSession, OpenError> with
/// @c std::make_shared<CardSession>(std::move(*result)).
///
/// @par Thread-safety
/// Thread-compatible (see API-POLICY §8). A CardSession represents an
/// exclusive PC/SC connection to a single reader/card and is NOT internally
/// synchronised: concurrent operations against the same session from
/// multiple threads are undefined. Callers
/// that need to dispatch work from several threads must serialise APDUs
/// externally (e.g. by holding the session under a mutex) or allocate one
/// session per worker. The pure accessors (@ref readerName, @ref atr,
/// @ref isConnected) read immutable post-construction state and may be
/// called concurrently. Sibling pimpl-backed types
/// (@ref LibreSCRS::Signing::SigningService) take a
/// @c std::shared_ptr<CardSession> by value and assume the caller has
/// already established that exclusivity for the duration of the call.
///
/// @since 4.0
class LIBRESCRS_PUBLIC_API CardSession
{
public:
    /// @brief Opens a PC/SC session against the named reader.
    /// @return On success, the opened session. On failure, a fully
    /// populated @ref OpenError carrying classification, user-facing
    /// message, and dev-facing diagnostic.
    /// @since 4.0 — was @c OpenSessionResult (deriving from
    ///         @c std::variant<CardSession, OpenError>); migration to
    ///         @c std::expected closes the asymmetry with sibling 4.0
    ///         fallible factories @ref Certificate::ParsedCertificate::fromDer
    ///         and @ref Trust::TrustStoreService::create.
    /// @par C++23 Idiom
    /// @code
    /// auto result = CardSession::open(readerName);
    /// if (!result) {
    ///     log("Open failed: {}", result.error().userMessage.defaultText);
    ///     return;
    /// }
    /// CardSession session = std::move(*result);
    /// @endcode
    [[nodiscard]] static std::expected<CardSession, OpenError> open(std::string readerName) noexcept;

    ~CardSession();
    CardSession(const CardSession&) = delete;
    CardSession& operator=(const CardSession&) = delete;
    /// @brief Move-constructible. Pimpl makes this a cheap pointer move;
    ///        the moved-from session holds no Impl and must not be used for
    ///        any operation other than destruction or move-assignment from
    ///        another CardSession. Matches the invariant of sibling
    ///        pimpl-backed classes (@ref LibreSCRS::Signing::SigningService,
    ///        @ref LibreSCRS::Signing::SigningRequest).
    CardSession(CardSession&&) noexcept;
    /// @brief Move-assignable. Same moved-from invariant as the move ctor.
    CardSession& operator=(CardSession&&) noexcept;

    /// @brief True when this object holds a valid (non-moved-from) pimpl.
    ///
    /// `if (!session)` is always well-defined; calling @ref readerName,
    /// @ref atr, or @ref isConnected on a moved-from session is undefined
    /// behaviour. Consumers that move sessions into
    /// @c std::shared_ptr<CardSession> for signing should check the
    /// source-object state before the move if the source remains in scope.
    /// @since 4.0.
    explicit operator bool() const noexcept
    {
        return d != nullptr;
    }

    /// @brief Name of the reader this session is bound to.
    /// @note Pure accessor, `noexcept` per API-POLICY §5.3. Calling any
    ///       accessor on a moved-from session is undefined behaviour; see
    ///       the move-ctor contract above.
    [[nodiscard]] const std::string& readerName() const noexcept;

    /// @brief ATR bytes reported by the card at session open.
    /// @note Pure accessor, `noexcept` per API-POLICY §5.3. Calling any
    ///       accessor on a moved-from session is undefined behaviour.
    [[nodiscard]] const std::vector<std::uint8_t>& atr() const noexcept;

    /// @brief True while the session is open; false after reset / removal.
    /// @note Pure accessor, `noexcept` per API-POLICY §5.3. Calling any
    ///       accessor on a moved-from session is undefined behaviour.
    [[nodiscard]] bool isConnected() const noexcept;

private:
    // Detail-namespace free functions are the internal access points for
    // test factories (makeDetachedCardSession) and plugin/signing bridges
    // (unwrap, sessionGeneration). Friending them directly removes the
    // earlier CardSessionFactory class indirection. Declarations live in
    // internal-only headers under `LibreSCRS/SmartCard/detail/`; friend
    // declarations here inject the names at enclosing-namespace scope
    // without leaking any prototypes into the public include tree.
    friend std::shared_ptr<CardSession> detail::makeDetachedCardSession(std::string readerName);
    friend struct detail::PcscBridge;
    friend std::uint64_t detail::sessionGeneration(const CardSession& session) noexcept;

    CardSession();
    /// @brief Private constructor used by @ref open and the detail factories.
    ///        Not part of the public surface: the throwing shape was
    ///        replaced by the noexcept factory in 4.0.
    explicit CardSession(std::string readerName);

    struct Impl;
    std::unique_ptr<Impl> d;
};

} // namespace LibreSCRS::SmartCard
