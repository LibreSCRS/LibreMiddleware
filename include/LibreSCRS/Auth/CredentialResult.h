// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

/// @file
/// @brief @ref LibreSCRS::Auth::CredentialResult — secret-carrying outcome
///        of a @ref LibreSCRS::Auth::CredentialProvider callback, keyed by
///        @ref LibreSCRS::Auth::FieldDescriptor::id.

#include <LibreSCRS/Auth/ErrorKeys.h>
#include <LibreSCRS/LocalizedText.h>
#include <LibreSCRS/Export.h>
#include <LibreSCRS/Secure/String.h>

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace LibreSCRS::Auth {

/// @brief Provider-side return value for a credential prompt.
///
/// Construct via one of the named factories — @ref ok, @ref cancelled, or
/// @ref error — to guarantee @ref status is set at construction. The type is
/// intentionally not default-constructible: an "undefined outcome" default for
/// a security-sensitive result is a footgun. A buggy provider that forgets to
/// choose an outcome must fail at compile time, not return silently
/// uninitialised memory to a signing pipeline.
struct CredentialResult
{
    /// @brief Outcome classification for a credential prompt.
    /// @note Append-only: new status values may be added in future minor
    ///       releases. Consumer @c switch statements must include a
    ///       @c default branch.
    enum class Status : std::uint8_t {
        Ok,            ///< Prompt completed successfully; @ref values is populated.
        UserCancelled, ///< User dismissed or cancelled the prompt.
        Error,         ///< Provider-internal failure; @ref userMessage may carry detail.
    };

    /// @brief Key/value pair carrying a single prompt field.
    using Entry = std::pair<std::string, LibreSCRS::Secure::String>;

    /// @brief Outcome classification. Always set by a factory.
    Status status;
    /// @brief Collected values keyed by @ref FieldDescriptor::id, in insertion
    ///        order.
    ///
    /// Typical credential prompts carry 1–3 fields (PIN, or PIN + new-PIN +
    /// confirm-PIN, or CAN + PIN). A flat `std::vector<std::pair<...>>`
    /// gives deterministic order for structured logs / replay fixtures,
    /// avoids an `std::map`-shaped red-black tree for a tiny N, and keeps
    /// the @ref Secure::String values densely packed.
    ///
    /// Values cleanse-on-destruction via @ref LibreSCRS::Secure::String —
    /// the storage is zeroised when the vector entry (or the enclosing
    /// @ref CredentialResult) goes out of scope. Keys remain plain
    /// `std::string` because field identifiers ("pin", "puk", "can",
    /// "currentPin", …) are not secret material.
    ///
    /// @warning Callers materialising a @ref LibreSCRS::Secure::String from
    /// a `QString` or `std::string` source remain responsible for cleansing
    /// their own copy — the constructor only cleanses storage owned by the
    /// @ref LibreSCRS::Secure::String itself.
    std::vector<Entry> values;
    /// @brief Translator-friendly user-facing message. Mandatory in 4.0;
    ///        the @ref ok and @ref cancelled factories substitute generic
    ///        success / cancelled messages from @ref Auth::ErrorKeys, so
    ///        every result has a non-empty user-renderable text.
    /// @warning Never include raw secret material in error messages; this
    ///          field is intended for diagnostics, logging, or UI display.
    /// @since 4.0 — was @c std::optional<LocalizedText> in 3.x.
    /// @note Renamed from @c errorMessage in 4.0 for cross-type consistency
    ///       with @ref LibreSCRS::Signing::SigningResult::userMessage and
    ///       @ref LibreSCRS::SmartCard::OpenError::userMessage.
    LocalizedText userMessage;

    /// @brief Locate a credential value by @p key.
    /// @return Pointer to the @ref Secure::String when the key is present,
    ///         @c nullptr otherwise. The returned pointer aliases storage
    ///         owned by this @ref CredentialResult and is invalidated by any
    ///         mutation of @ref values (push/insert/erase/clear) or by the
    ///         @ref CredentialResult going out of scope.
    [[nodiscard]] const LibreSCRS::Secure::String* find(std::string_view key) const noexcept
    {
        for (const auto& [k, v] : values) {
            if (k == key) {
                return &v;
            }
        }
        return nullptr;
    }

    /// @brief Construct a successful result carrying @p values.
    /// @note Prefer this factory over field-wise initialisation — it
    ///       guarantees @ref status is set to @ref Status::Ok.
    /// @note @c noexcept: body only moves already-constructed inputs into a
    ///       locally-initialised aggregate. Per API-POLICY §5.3.
    [[nodiscard]] static CredentialResult ok(std::vector<Entry> values) noexcept
    {
        return CredentialResult{Status::Ok, std::move(values), Auth::ErrorKeys::credentialsCollected()};
    }

    /// @brief Construct a user-cancelled result (no @ref values).
    /// @note @c noexcept: cannot throw; the generic message is a
    ///       move-from-temporary.
    [[nodiscard]] static CredentialResult cancelled() noexcept
    {
        return CredentialResult{Status::UserCancelled, {}, Auth::ErrorKeys::userCancelled()};
    }

    /// @brief Construct a provider-error result.
    /// @param userMessage Translator-friendly user-facing message.
    ///        Pass one of the @ref Auth::ErrorKeys builders if no
    ///        provider-specific text is appropriate.
    /// @since 4.0 — was @c std::optional<LocalizedText> in 3.x with
    ///        a default of @c std::nullopt.
    /// @note @c noexcept: moves the already-constructed @p userMessage.
    [[nodiscard]] static CredentialResult error(LocalizedText userMessage) noexcept
    {
        return CredentialResult{Status::Error, {}, std::move(userMessage)};
    }

    /// @brief Default construction is deleted — use a named factory to
    ///        guarantee @ref status is populated. Security-sensitive default
    ///        "undefined outcome" values are not permitted.
    CredentialResult() = delete;

    /// @brief Field-wise constructor used by the factories. Prefer the
    ///        factories at call sites; this constructor is public only so
    ///        `{...}` initialisation inside factories is expressible.
    CredentialResult(Status s, std::vector<Entry> v, LocalizedText msg) noexcept
        : status(s), values(std::move(v)), userMessage(std::move(msg))
    {}

    /// @brief Move-construct from @p other.
    CredentialResult(CredentialResult&&) noexcept = default;
    /// @brief Move-assign from @p other.
    CredentialResult& operator=(CredentialResult&&) noexcept = default;
    /// @brief Copy-construct by deep-copying @p other.
    ///
    /// @ref LibreSCRS::Secure::String is copyable by design — each copy
    /// owns an independent, separately-cleansed storage block. Enabling
    /// copy here composes with `std::optional<CredentialResult>` and with
    /// host code that wants to retain the result through a multi-step
    /// pipeline (e.g. re-prompt on InvalidPin, where the first attempt's
    /// diagnostic is also logged).
    ///
    /// Every copy's @ref values is its own cleansed allocation: when any
    /// single copy goes out of scope, only that copy's storage is
    /// zeroised. Callers that never need two live copies should still
    /// prefer moves — the copy is a deep clone of every @c Secure::String
    /// entry and grows linearly with the number of collected fields.
    ///
    /// @since 4.0 — previously deleted. The original deletion
    /// reflected a "no duplication of secrets" posture; that posture is
    /// already expressed by @c Secure::String's per-copy cleansing
    /// semantics, and the deletion was blocking ergonomic uses
    /// (`std::optional<CredentialResult>` in plugin retry pipelines) with
    /// no matching security benefit.
    CredentialResult(const CredentialResult&) = default;
    /// @brief Copy-assign by deep-copying @p other. Same per-copy cleansing
    ///        semantics as the copy ctor.
    CredentialResult& operator=(const CredentialResult&) = default;
    ~CredentialResult() = default;
};

} // namespace LibreSCRS::Auth
