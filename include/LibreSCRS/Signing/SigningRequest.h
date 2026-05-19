// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

/// @file
/// @brief @ref LibreSCRS::Signing::SigningRequest — immutable description
///        of a signing operation, built via the fluent
///        @ref LibreSCRS::Signing::SigningRequest::Builder.

#include <LibreSCRS/Export.h>
#include <LibreSCRS/Signing/Enums.h>
#include <LibreSCRS/Signing/TsaProvider.h>
#include <LibreSCRS/Signing/VisualSignatureParams.h>

#include <filesystem>
#include <memory>
#include <optional>
#include <string>

namespace LibreSCRS::Signing {

/// @brief Immutable description of a signing operation.
///
/// Opaque pimpl, move-only. Construct via @ref Builder. Most accessors
/// return `const&` references whose lifetimes match the owning
/// @ref SigningRequest; @ref visualParams returns
/// `std::optional<VisualSignatureParams>` by value so the caller's copy is
/// independent of the request's lifetime.
///
/// @par Move-only vs. AuthRequirement
/// Unlike sibling @ref LibreSCRS::Auth::AuthRequirement (fully copyable,
/// plain-data + `std::vector` of small descriptors), `SigningRequest` is
/// pimpl-backed and move-only. Callers consume the request exactly once by
/// handing it to @ref LibreSCRS::Signing::SigningService::sign; duplicating
/// a request would imply two concurrent sign operations against the same
/// input/output files, which is a caller-side footgun the move-only shape
/// prevents at compile time.
///
/// @par Validation policy
/// @ref Builder applies a "validation at @ref Builder::build" policy: the
/// individual setters never throw, invariants (required fields, cross-field
/// combinations like `visualParams + non-PAdES`) are checked inside
/// @ref Builder::build and surface as @c std::invalid_argument. Contrast with
/// @ref VisualSignatureParams::Builder, which validates at each setter:
/// @ref SigningRequest has inter-field constraints that the builder can only
/// verify once all fields have been supplied (for example, `visualParams`
/// requires `format == PAdES`, which may be set in either order), so the
/// assemble-then-validate shape is unavoidable here. Callers wrap the
/// @ref Builder::build call in a try/catch per API-POLICY §5.1.
///
/// @par Thread-safety
/// Thread-compatible (see API-POLICY §8). @ref SigningRequest is immutable
/// after @ref Builder::build returns; the pimpl holds value data (paths,
/// optionals, an owned `VisualSignatureParams` copy, and a copy of the
/// `TsaProvider` `std::function`) with no internal synchronisation. The
/// move-only shape means there is at most one owner at a time, so concurrent
/// reads of the *same* instance are race-free by structure. The Builder is
/// single-threaded relative to its own instance.
///
/// @since 4.0
///
/// @see SigningRequest::Builder
class LIBRESCRS_PUBLIC_API SigningRequest
{
public:
    class Builder;

    /// @brief Move-construct from @p other.
    SigningRequest(SigningRequest&&) noexcept;
    /// @brief Move-assign from @p other.
    SigningRequest& operator=(SigningRequest&&) noexcept;
    SigningRequest(const SigningRequest&) = delete;
    SigningRequest& operator=(const SigningRequest&) = delete;
    ~SigningRequest();

    /// @brief True when this object holds a valid (non-moved-from) pimpl.
    ///
    /// After `SigningRequest b{std::move(a)}`, `a` is moved-from; any
    /// accessor call on `a` is undefined behaviour. This conversion lets
    /// callers defensively check for the moved-from state without incurring
    /// the UB — `if (!req)` is always well-defined.
    ///
    /// @since 4.0.
    explicit operator bool() const noexcept
    {
        return d != nullptr;
    }

    /// @brief Input document path.
    /// @note Returned reference is valid while this object is alive.
    /// @note Pure accessor, @c noexcept per API-POLICY §5.3.
    [[nodiscard]] const std::filesystem::path& inputFile() const noexcept;
    /// @brief Output signed-document path.
    /// @note Returned reference is valid while this object is alive.
    /// @note Pure accessor, @c noexcept per API-POLICY §5.3.
    [[nodiscard]] const std::filesystem::path& outputFile() const noexcept;
    /// @brief Target signature format.
    /// @note Pure accessor, @c noexcept per API-POLICY §5.3.
    [[nodiscard]] SignatureFormat format() const noexcept;
    /// @brief Target signature level.
    /// @note Pure accessor, @c noexcept per API-POLICY §5.3.
    [[nodiscard]] SignatureLevel level() const noexcept;
    /// @brief Packaging mode (enveloped / detached).
    /// @note Pure accessor, @c noexcept per API-POLICY §5.3.
    [[nodiscard]] PackagingMode packaging() const noexcept;
    /// @brief Signing reason; may be empty.
    /// @note Returned reference is valid while this object is alive.
    /// @note Pure accessor, @c noexcept per API-POLICY §5.3.
    [[nodiscard]] const std::string& reason() const noexcept;
    /// @brief Signing location; may be empty.
    /// @note Returned reference is valid while this object is alive.
    /// @note Pure accessor, @c noexcept per API-POLICY §5.3.
    [[nodiscard]] const std::string& location() const noexcept;
    /// @brief Signer contact info; may be empty.
    /// @note Returned reference is valid while this object is alive.
    /// @note Pure accessor, @c noexcept per API-POLICY §5.3.
    [[nodiscard]] const std::string& contactInfo() const noexcept;
    /// @brief PKCS#11 key alias (certificate label) selecting the signing key.
    /// @note Empty when the backend should auto-select (single-cert cards).
    /// @note Pure accessor, @c noexcept per API-POLICY §5.3.
    [[nodiscard]] const std::string& certificateLabel() const noexcept;
    /// @brief Access the visual signature parameters, if any were set.
    /// @return An optional value — empty when @ref Builder::visualParams was
    ///         not called, populated when it was (only valid for PAdES
    ///         requests).
    /// @note Returns a copy. The returned optional is independently owned;
    ///       modifying, moving or destroying the source @ref SigningRequest
    ///       does NOT invalidate the returned value. This avoids the
    ///       caller-invalidation footgun of returning a pointer into
    ///       mutable pimpl state.
    /// @note The copy is trivially cheap — @ref VisualSignatureParams is
    ///       pimpl-backed with small-data geometry and a short text
    ///       template.
    /// @note Copying a @c std::optional<VisualSignatureParams> may allocate
    ///       for the nested pimpl; the method is therefore NOT marked
    ///       @c noexcept even though it is a pure accessor — the exception
    ///       in API-POLICY §5.3 for accessors that return by value applies
    ///       here.
    [[nodiscard]] std::optional<VisualSignatureParams> visualParams() const;

    /// @brief Per-request TSA provider override, or empty std::function if
    ///        the service-level provider supplied at
    ///        @ref SigningService construction should be used.
    /// @return Returns a copy; the returned value is independently owned and
    ///         survives subsequent moves, assignments, or destruction of the
    ///         source @ref SigningRequest. @c TsaProvider is a
    ///         @c std::function so the copy is move-cheap for stored closures.
    ///         Matches the @ref visualParams accessor's independent-lifetime
    ///         contract.
    /// @note   To test whether an override was installed without invoking it,
    ///         prefer @ref hasTsaOverride (noexcept, no copy).
    /// @note Returning a @c std::function by value may allocate when the
    ///       stored target is larger than the small-function buffer; per
    ///       API-POLICY §5.3 this accessor is intentionally NOT marked
    ///       @c noexcept. The exception exposed to the caller would be
    ///       `std::bad_alloc` on copy of the captured state.
    /// @since 4.0
    [[nodiscard]] TsaProvider tsaOverride() const;

    /// @brief True when a per-request TSA provider override was installed
    ///        via @ref Builder::tsaOverride.
    ///
    /// Intent-check without the allocation risk of copying the stored
    /// @c std::function. Prefer over `static_cast<bool>(req.tsaOverride())`
    /// for host code that only needs to branch on "did the caller supply
    /// an override?".
    /// @since 4.0.
    [[nodiscard]] bool hasTsaOverride() const noexcept;

    /// @brief When @c true, the signing service does not refuse a
    ///        certificate whose @c notAfter is in the past.
    ///
    /// Default @c false: an expired signing certificate aborts the sign
    /// with @ref LibreSCRS::Signing::SigningResult::Status::SigningEngineError.
    /// Callers that have surfaced an
    /// explicit warning to the user and obtained acknowledgement may set
    /// this flag to @c true to let the sign proceed. The resulting
    /// signature will still be flagged invalid by standards-compliant
    /// validators (eIDAS Article 26: a qualified signature requires a
    /// certificate valid at the time of signing); the flag only suppresses
    /// the @em local pre-flight refusal, it does not retroactively make
    /// the produced signature valid downstream.
    /// @since 4.1
    [[nodiscard]] bool allowExpiredCert() const noexcept;

private:
    friend class Builder;
    SigningRequest();
    struct Impl;
    std::unique_ptr<Impl> d;
};

/// @brief Fluent builder producing an immutable @ref SigningRequest.
///
/// Setters accept arguments by value/move and return a reference to the
/// builder. @ref build is rvalue-qualified — construct a named builder and
/// finalise with `std::move(builder).build()`.
///
/// @par Validation policy
/// Setters never throw; validation happens only inside @ref build. This
/// "validation at @c build()" shape is forced by the cross-field
/// dependencies in a signing request (e.g. `visualParams` requires
/// `format == PAdES`, and either setter may be invoked first). Compare
/// @ref VisualSignatureParams::Builder, which has no such dependencies and
/// validates each setter individually. Per API-POLICY §5.1, callers wrap
/// the @ref build call in a try/catch for @c std::invalid_argument.
class LIBRESCRS_PUBLIC_API SigningRequest::Builder
{
public:
    Builder();
    ~Builder();
    /// @brief Move-construct the builder.
    Builder(Builder&&) noexcept;
    /// @brief Move-assign the builder.
    Builder& operator=(Builder&&) noexcept;

    /// @brief Set the input document path.
    Builder& inputFile(std::filesystem::path path);
    /// @brief Set the output signed-document path.
    Builder& outputFile(std::filesystem::path path);
    /// @brief Set the signature format.
    Builder& format(SignatureFormat f) noexcept;
    /// @brief Set the signature level.
    Builder& level(SignatureLevel l) noexcept;
    /// @brief Set the packaging mode.
    Builder& packaging(PackagingMode p) noexcept;
    /// @brief Set the signing reason.
    /// @note Written into the PDF signature dictionary (ISO 32000-1:2008 §12.8.1)
    ///       regardless of whether @ref visualParams is configured. An invisible
    ///       signature still carries this field.
    Builder& reason(std::string r);
    /// @brief Set the signing location.
    /// @note Written into the PDF signature dictionary (ISO 32000-1:2008 §12.8.1)
    ///       regardless of whether @ref visualParams is configured. An invisible
    ///       signature still carries this field.
    Builder& location(std::string loc);
    /// @brief Set the signer contact info.
    /// @note Written into the PDF signature dictionary (ISO 32000-1:2008 §12.8.1)
    ///       regardless of whether @ref visualParams is configured. An invisible
    ///       signature still carries this field.
    Builder& contactInfo(std::string info);
    /// @brief Set the certificate label / PKCS#11 key alias used to select the signing key.
    Builder& certificateLabel(std::string label);
    /// @brief Attach visual signature parameters (PAdES only). Takes ownership by move;
    /// call with `std::move(params)`. Passing an lvalue is a compile error.
    Builder& visualParams(VisualSignatureParams&& params);
    /// @brief Install a per-request TSA provider. When set, the signing
    ///        service calls this provider at sign time instead of the
    ///        service-level provider supplied at @ref SigningService
    ///        construction.
    /// @note To supply a bare URL without auth, use the staticTsa() factory:
    ///       @code
    ///         builder.tsaOverride(staticTsa("https://tsa.example.com"));
    ///       @endcode
    /// @since 4.0
    Builder& tsaOverride(TsaProvider provider);
    /// @brief Allow a sign to proceed even when the signing certificate's
    ///        @c notAfter is in the past.
    ///
    /// Default behaviour (flag unset / @c false) refuses the sign with
    /// @ref LibreSCRS::Signing::SigningResult::Status::SigningEngineError.
    /// Hosts that surface an explicit
    /// expired-cert warning to the user and receive acknowledgement set
    /// this flag to honour that consent.
    /// @since 4.1
    Builder& allowExpiredCert(bool allow) noexcept;

    /// @brief Validate and produce a @ref SigningRequest.
    /// @throws std::invalid_argument if required fields are missing or
    ///         combinations are invalid (e.g., @ref visualParams set on a
    ///         non-PAdES request). Per API-POLICY §5.1.
    [[nodiscard]] SigningRequest build() &&;

private:
    struct Impl;
    std::unique_ptr<Impl> d;
};

} // namespace LibreSCRS::Signing
