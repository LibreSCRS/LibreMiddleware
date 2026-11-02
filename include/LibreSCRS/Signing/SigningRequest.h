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

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

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
/// handing it to @ref LibreSCRS::Signing::SigningService::sign; the move-only
/// shape keeps one request to one signature at compile time.
///
/// @par Validation policy
/// @ref Builder applies a "validation at @ref Builder::buildForBufferSign"
/// policy: the individual setters never throw, cross-field combinations like
/// `visualParams + non-PAdES` are checked inside
/// @ref Builder::buildForBufferSign and surface as @c std::invalid_argument. Contrast with
/// @ref VisualSignatureParams::Builder, which validates at each setter:
/// @ref SigningRequest has inter-field constraints that the builder can only
/// verify once all fields have been supplied (for example, `visualParams`
/// requires `format == PAdES`, which may be set in either order), so the
/// assemble-then-validate shape is unavoidable here. Callers wrap the
/// @ref Builder::buildForBufferSign call in a try/catch per API-POLICY §5.1.
///
/// @par Thread-safety
/// Thread-compatible (see API-POLICY §8). @ref SigningRequest is immutable
/// after @ref Builder::buildForBufferSign returns; the pimpl holds value data
/// (strings, optionals, an owned `VisualSignatureParams` copy) with no
/// internal synchronisation. The
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
    /// @since 4.0
    explicit operator bool() const noexcept
    {
        return d != nullptr;
    }

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
    /// @brief Card-side CKA_ID of the signing key/cert pair — the REUSE-SAFE
    ///        name of the EXACT key. When set, it must name the key of the
    ///        signer passed to @ref SigningService::sign; a request whose key
    ///        id names another key is refused rather than signed with the
    ///        signer it was handed. Empty leaves the choice to that signer
    ///        alone. A key id longer than a PKCS#15 identifier (255 bytes) is
    ///        refused with @ref SigningResult::Status::InvalidRequest.
    /// @note Pure accessor, @c noexcept per API-POLICY §5.3.
    /// @since 5.0
    [[nodiscard]] const std::vector<std::uint8_t>& keyId() const noexcept;
    /// @brief Name of the document being signed — the only name the signing
    ///        engines have for it.
    ///
    ///        The signing engines consume this as the document's identity
    ///        inside the produced artifact: it becomes the ASiC-E container
    ///        entry name and the basename of the XAdES / JAdES detached
    ///        reference. Left empty, ASiC-E container creation fails outright
    ///        ("Invalid filename for ASiC entry"), so callers targeting a
    ///        container format must set it.
    /// @note Only the FINAL path component is honoured — any directory
    ///       components are stripped at translation time, so a caller cannot
    ///       inject path separators (or a `../` traversal) into a container
    ///       entry name. This accessor returns the raw string as supplied;
    ///       the strip happens on the way to the engine, not in the setter.
    /// @note Degenerate names — those that are empty after the strip (a
    ///       trailing separator, e.g. `"a/b/"`), or that strip down to `"."`
    ///       or `".."` — are treated as UNSET; they are never handed to the
    ///       engine as a name.
    /// @note This is a NAME, not a location: the document is never opened,
    ///       resolved or written through it.
    /// @note Returned reference is valid while this object is alive.
    /// @note Pure accessor, @c noexcept per API-POLICY §5.3.
    /// @since 5.0
    [[nodiscard]] const std::string& documentName() const noexcept;
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

    /// @brief Per-request time-stamping authority installed by
    ///        @ref Builder::tsaOverride. Its URL is empty when the request
    ///        names none, and the authority supplied at @ref SigningService
    ///        construction is used.
    /// @note Returned reference is valid while this object is alive.
    /// @note Pure accessor, @c noexcept per API-POLICY §5.3.
    /// @since 4.0
    [[nodiscard]] const TsaProvider& tsaOverride() const noexcept;

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
/// builder. @ref buildForBufferSign is rvalue-qualified — construct a named
/// builder and finalise with `std::move(builder).buildForBufferSign()`.
///
/// @par Validation policy
/// Setters never throw; validation happens only inside
/// @ref buildForBufferSign. This "validation at build" shape is forced by the
/// cross-field dependencies in a signing request (e.g. `visualParams`
/// requires `format == PAdES`, and either setter may be invoked first). Compare
/// @ref VisualSignatureParams::Builder, which has no such dependencies and
/// validates each setter individually. Per API-POLICY §5.1, callers wrap
/// the @ref buildForBufferSign call in a try/catch for
/// @c std::invalid_argument.
class LIBRESCRS_PUBLIC_API SigningRequest::Builder
{
public:
    Builder();
    ~Builder();
    /// @brief Move-construct the builder.
    Builder(Builder&&) noexcept;
    /// @brief Move-assign the builder.
    Builder& operator=(Builder&&) noexcept;

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
    /// @brief Set the card-side CKA_ID that names the EXACT signing key; see
    ///        @ref SigningRequest::keyId. @since 5.0
    Builder& keyId(std::vector<std::uint8_t> id);
    /// @brief Name the document being signed.
    ///
    /// Required for container formats: this is what names the ASiC-E
    /// container entry and the XAdES / JAdES detached reference. Optional
    /// everywhere else.
    /// @note Only the final path component is honoured — directory components
    ///       are stripped at translation time, so callers cannot inject path
    ///       separators into container entries. Degenerate names (empty after
    ///       the strip, `"."` or `".."`) are treated as unset.
    /// @note Names the in-memory document only — nothing is opened or written
    ///       through this string.
    /// @since 5.0
    Builder& documentName(std::string name);
    /// @brief Attach visual signature parameters (PAdES only). Takes ownership by move;
    /// call with `std::move(params)`. Passing an lvalue is a compile error.
    Builder& visualParams(VisualSignatureParams&& params);
    /// @brief Install a per-request time-stamping authority. When it names a
    ///        URL, the signing service contacts it instead of the authority
    ///        supplied at @ref SigningService construction; one naming no URL
    ///        leaves that authority in place.
    /// @note Use the staticTsa() factory:
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

    /// @brief Validate and produce a @ref SigningRequest for
    ///        @ref SigningService::sign, which carries the document and the
    ///        signed result in memory.
    /// @note Set @ref documentName when the target format embeds the
    ///       document's name (ASiC-E entry, XAdES / JAdES detached reference).
    ///       @ref documentName stays OPTIONAL — it is not validated here.
    /// @throws std::invalid_argument only for invalid field combinations
    ///         (e.g. @ref visualParams on a non-PAdES request). Per
    ///         API-POLICY §5.1. @since 5.0
    [[nodiscard]] SigningRequest buildForBufferSign() &&;

private:
    struct Impl;
    std::unique_ptr<Impl> d;
};

} // namespace LibreSCRS::Signing
