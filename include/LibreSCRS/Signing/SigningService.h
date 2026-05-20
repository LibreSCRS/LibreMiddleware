// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

/// @file
/// @brief @ref LibreSCRS::Signing::SigningService — the public entry point
///        for PAdES / XAdES / JAdES / CAdES / ASiC-E signing. Pure DI
///        (@ref LibreSCRS::Trust::TrustStoreService (shared, async-owning)
///        + @ref LibreSCRS::Signing::TsaProvider in the ctor, per-call
///        @ref LibreSCRS::Auth::CredentialProvider and @ref
///        LibreSCRS::Plugin::CardPlugin dependencies), move-only,
///        pimpl-backed.

#include <LibreSCRS/Auth/CredentialProvider.h>
#include <LibreSCRS/Export.h>
#include <LibreSCRS/Signing/SigningRequest.h>
#include <LibreSCRS/Signing/SigningResult.h>
#include <LibreSCRS/Signing/TsaProvider.h>
#include <LibreSCRS/SmartCard/CardSession.h>
#include <LibreSCRS/Trust/TrustStoreService.h>

#include <cstdint>
#include <memory>
#include <span>

// Forward declaration for the plugin interface; full header stays out of this
// public surface.
namespace LibreSCRS::Plugin {
class CardPlugin;
}

namespace LibreSCRS::Signing {

/// @brief Entry point for producing advanced electronic signatures on the
///        payload described by a @ref SigningRequest.
///
/// Constructed via explicit ctor taking a @ref Trust::TrustStoreService
/// (shared) + `TsaProvider`. Configuration is immutable post-construction;
/// to change trust or TSA settings, construct a new SigningService.
///
/// @note Lifecycle: caller-owned. Typical ownership is via
///       `std::make_shared<SigningService>(trustService, std::move(tsa))`,
///       but stack construction is equally valid. No process-wide shared
///       state is retained; each constructed instance is independent.
/// @par Thread-safety
/// Thread-safe (see API-POLICY §8). The @ref sign overloads can be called
/// concurrently from multiple threads, each with its own
/// `(cardPlugin, session)` pair. The injected
/// @ref Trust::TrustStoreService is itself thread-safe (status / wait /
/// observer methods are reentrant); concurrent @ref sign calls share the
/// same trust snapshot through @ref Trust::TrustStoreService::trustStore.
/// No lazy global initialisation occurs in @ref sign — the public-trust
/// pointer is plumbed via the constructor.
///
/// However, **multiple concurrent `sign()` calls must use distinct
/// `cardPlugin` and `cardSession` arguments**: the `CardPlugin` /
/// `CardSession` thread-safety contract (see
/// @ref LibreSCRS::Plugin::CardPlugin) requires that each PC/SC card
/// session is owned by at most one signing operation at a time. Sharing
/// the same `(plugin, session)` pair across threads will produce
/// undefined card-protocol state.
class LIBRESCRS_PUBLIC_API SigningService
{
public:
    /// @brief Construct a signing service with the trust-anchor lifecycle
    ///        owner and TSA lookup callback it will use for every
    ///        @ref sign call.
    /// @param trustService Shared, async-owning lifecycle for the
    ///                     @ref Trust::TrustStore that backs every
    ///                     chain-validation step at sign time. Constructed
    ///                     by the caller via
    ///                     @ref Trust::TrustStoreService::create. Must not
    ///                     be null. The signing service holds the shared
    ///                     pointer for its full lifetime — eager TL fetches
    ///                     drive the underlying store, lazy TL fetches
    ///                     during @ref sign merge into the same store via
    ///                     the friend mechanism so that @ref sign and
    ///                     non-signing consumers (cert viewer, plugin
    ///                     registry) all observe the same trust universe.
    /// @param tsa TSA lookup callback used for B_T and higher signature
    ///            levels. Pass `TsaProvider{}` (a default-constructed empty
    ///            std::function) when TSA is unavailable; B-B signatures
    ///            that require no timestamp will still succeed, while
    ///            B-T/B-LT/B-LTA requests will fail at @ref sign time with
    ///            a TSA-required error. A per-request override supplied via
    ///            @ref SigningRequest::Builder::tsaOverride takes precedence
    ///            over this service-level provider.
    /// @note This ctor does not throw; validation is deferred to @ref sign.
    /// @since 4.0
    explicit SigningService(std::shared_ptr<Trust::TrustStoreService> trustService, TsaProvider tsa);

    ~SigningService();

    SigningService(const SigningService&) = delete;
    SigningService& operator=(const SigningService&) = delete;
    /// @brief Move-constructible. Pimpl makes this a cheap pointer move;
    ///        the moved-from service holds no Impl and must not be used.
    SigningService(SigningService&&) noexcept;
    /// @brief Move-assignable. Same moved-from invariant as the move ctor.
    SigningService& operator=(SigningService&&) noexcept;

    /// @brief True when this object holds a valid (non-moved-from) pimpl.
    ///
    /// `if (!service)` is always well-defined; invoking @ref sign on a
    /// moved-from service is undefined behaviour. This accessor lets
    /// callers check for the moved-from state without triggering the UB.
    /// Matches the sibling convention on @ref SigningRequest,
    /// @ref VisualSignatureParams, @ref LibreSCRS::SmartCard::CardSession,
    /// @ref LibreSCRS::SmartCard::MonitorService, @ref LibreSCRS::Secure::Buffer
    /// and @ref LibreSCRS::Secure::String.
    /// @since 4.0
    explicit operator bool() const noexcept;

    /// @brief Produce a signature for @p request.
    /// @param request Immutable signing parameters.
    /// @param credentialProvider Callback that collects the signing PIN.
    /// @param cardPlugin Plugin used to drive on-card operations. Borrowed
    ///                   by const-reference per C++ Core Guidelines F.7 /
    ///                   F.16 — the call-site keeps the shared owner; the
    ///                   service copies internally only when an async
    ///                   worker needs to outlive the call. Const-qualified
    ///                   element type because @ref sign exercises only the
    ///                   plugin's const interface.
    /// @param session Live card session. Borrowed by const-reference, with
    ///                the service copying internally only for worker
    ///                hand-off. Element type is non-const because the
    ///                signing engine mutates session state (current applet,
    ///                cached secrets) as the sign flow progresses.
    /// @return SigningResult whose @ref SigningResult::status is always set.
    /// @note Returns @ref SigningResult::Status::TrustStoreUnavailable when
    ///       the libresign backend rejects the trust configuration vended by
    ///       the @ref Trust::TrustStoreService supplied at construction (for
    ///       example, an unreachable Trusted List URL or an unwritable cache
    ///       directory). Returns @ref SigningResult::Status::InvalidRequest
    ///       if @p cardPlugin or @p session is null, or
    ///       @p credentialProvider is empty.
    /// @par Blocking
    /// This call blocks for the duration of the signing operation: PIN
    /// verification + APDU signing on the card (typically 1-3 s), plus
    /// any TSA round-trip for B-T / B-LT / B-LTA levels (typically
    /// 0.5-5 s, network-dependent), plus libresign packaging. GUI hosts
    /// must invoke @ref sign on a worker thread; calling it from the UI
    /// thread will freeze the UI for several seconds. A future
    /// cancellation-aware async overload (@ref LibreSCRS::CancelToken) is
    /// on the roadmap; the current API is synchronous.
    /// @par XAdES DETACHED Reference URI constraint
    /// When @p request.format selects XAdES with DETACHED packaging, the
    /// emitted `ds:Reference URI` attribute names the original file by
    /// its percent-encoded basename (e.g. `URI="my%20doc.bin"`).
    /// Conformant XAdES validators (EU DSS, ETSI test bench, Adobe)
    /// resolve that URI relative to the location of the `.xml` signature
    /// file, so the original payload MUST be present alongside the
    /// signature with the exact filename it carried at sign time.
    /// Callers that hand the signed `.xml` to a recipient over the wire
    /// must include the original file too; without it, validation fails
    /// at the reference-resolution step before any cryptographic check
    /// runs.
    /// @par Exceptions
    /// `noexcept`. Per API-POLICY §5.3 noexcept-alloc contract, internal
    /// `std::bad_alloc` from libresign request construction, file I/O
    /// buffers, or std::string formatting is caught and surfaced as
    /// @ref SigningResult::Status::SigningEngineError; defence-in-depth
    /// catches for `std::exception` and any other escaped throw map to
    /// the same status with a diagnostic message. All functional failure
    /// modes (trust unavailable, TSA unreachable, invalid request, user
    /// cancel) surface as a non-Ok @ref SigningResult::Status without
    /// involving the exception machinery.
    [[nodiscard]] SigningResult sign(const SigningRequest& request, Auth::CredentialProvider credentialProvider,
                                     const std::shared_ptr<const LibreSCRS::Plugin::CardPlugin>& cardPlugin,
                                     const std::shared_ptr<LibreSCRS::SmartCard::CardSession>& session) noexcept;

    /// @brief Append a new signer to a prior signature, producing a multi-
    ///        signature document with the new signer's signature alongside
    ///        the existing ones.
    ///
    /// For ENVELOPED formats (PAdES, XAdES-Enveloped, JAdES-Enveloped,
    /// ASiC-E) @p originalDocument may be empty — the original payload is
    /// recoverable from @p priorSignature. When non-empty, the engine
    /// asserts it matches the embedded original and returns
    /// @ref SigningResult::Status::InvalidRequest on mismatch (tamper
    /// detection).
    ///
    /// For DETACHED formats (CAdES, XAdES-Detached, JAdES-Detached)
    /// @p originalDocument is MANDATORY — RFC 7797 / ETSI EN 319 122 / etc.
    /// detached blobs do not carry the original by spec. An empty
    /// @p originalDocument against a detached prior returns
    /// @ref SigningResult::Status::InvalidRequest naming the missing
    /// original.
    ///
    /// Format is INFERRED from @p priorSignature (PDF / XML / JSON / CMS
    /// SEQUENCE / ZIP magic) and overrides any value in
    /// @p request.format. @p request supplies signer-side parameters
    /// (level, TSA configuration, visual appearance, contactInfo) for the
    /// new signer only; prior signers' attributes are left untouched.
    ///
    /// @param request           Immutable signing parameters for the new
    ///                          signer.
    /// @param priorSignature    The existing signed document / signature
    ///                          container being extended. Borrowed for the
    ///                          duration of the call; the implementation
    ///                          does not retain the span past return.
    /// @param originalDocument  The original payload bytes. Empty for the
    ///                          common ENVELOPED case (use the original
    ///                          recovered from @p priorSignature). Non-empty
    ///                          for DETACHED priors (mandatory) or for
    ///                          ENVELOPED tamper-check assertions.
    /// @param credentialProvider Callback that collects the signing PIN
    ///                          for the new signer (same contract as
    ///                          @ref sign).
    /// @return SigningResult whose @ref SigningResult::status is always
    ///         set. Same status taxonomy as @ref sign, plus
    ///         @ref SigningResult::Status::InvalidRequest for missing
    ///         original / unrecognised prior-signature magic / tamper
    ///         mismatch.
    /// @par Blocking
    /// Same blocking contract as @ref sign — PIN verification + APDU
    /// signing + optional TSA round-trip + packaging. Call on a worker
    /// thread from GUI hosts.
    /// @par Exceptions
    /// `noexcept`. Same noexcept-alloc contract as @ref sign: internal
    /// `std::bad_alloc` and any other escaped throw degrade to
    /// @ref SigningResult::Status::SigningEngineError with a diagnostic
    /// message rather than crossing the noexcept boundary.
    /// @since 4.1
    [[nodiscard]] SigningResult
    appendSigner(const SigningRequest& request, std::span<const std::uint8_t> priorSignature,
                 std::span<const std::uint8_t> originalDocument, Auth::CredentialProvider credentialProvider,
                 const std::shared_ptr<const LibreSCRS::Plugin::CardPlugin>& cardPlugin,
                 const std::shared_ptr<LibreSCRS::SmartCard::CardSession>& session) noexcept;

    // @since 4.0: trustStore() getter removed — consumers obtain the trust
    // store from the @ref Trust::TrustStoreService they constructed and
    // passed to this service's ctor. The lifecycle ownership model splits
    // cleanly between Trust (TrustStoreService) and Signing (SigningService).

private:
    struct Impl;
    std::unique_ptr<Impl> d;
};

} // namespace LibreSCRS::Signing
