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
#include <LibreSCRS/Plugin/PluginTypes.h>
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
/// Thread-safe (see API-POLICY §8). @ref sign can be called concurrently
/// from multiple threads, each with its own
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
    /// @param tsa Time-stamping authority used for B_T and higher signature
    ///            levels. Pass `TsaProvider{}` (no URL) when none is
    ///            available; B-B signatures that require no timestamp will
    ///            still succeed, while B-T/B-LT/B-LTA requests will fail at
    ///            @ref sign time with a TSA-required error. A per-request
    ///            override supplied via
    ///            @ref SigningRequest::Builder::tsaOverride takes precedence
    ///            over this service-level authority.
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
    /// @ref LibreSCRS::SmartCard::MonitorService and
    /// @ref LibreSCRS::Secure::String.
    /// @since 4.0
    explicit operator bool() const noexcept;

    /// @brief Produce a signature entirely in memory, with the signing key the
    ///        caller has already chosen: the document to sign is supplied as a
    ///        byte span and the finished artifact is returned in
    ///        @ref SigningResult::signedDocumentBytes — no file is read or
    ///        written.
    ///
    /// A host that read the card's certificates to choose the key passes
    /// its choice: the service neither reads the certificates again nor
    /// chooses again, so one signature costs one read and one rule decides
    /// which key signs. @p signer must carry its key handle
    /// (@ref LibreSCRS::Plugin::CertificateData::keyFID); a request key id
    /// (@ref SigningRequest::keyId), when set, must name @p signer's key.
    /// The certificate chain is built from @p cardCerts: @p signer's
    /// certificate first, then only the certificates that verify as its
    /// issuers.
    ///
    /// A document that already carries a signature in the requested format
    /// gains one more, beside the ones it carries: a PDF through an
    /// incremental update, an enveloped XAdES or JAdES document and an ASiC-E
    /// container by adding the new signer to them. A detached XAdES or JAdES
    /// signature and a CAdES signature do not carry the document they sign,
    /// so they are refused rather than signed as if they were the document.
    ///
    /// @param request Immutable signing parameters (build via
    ///                @ref SigningRequest::Builder::buildForBufferSign).
    /// @param input The document bytes to sign. Borrowed for the duration of
    ///              the call; the service does not retain the span past
    ///              return. Empty input or input exceeding the 256 MiB cap
    ///              returns @ref SigningResult::Status::InvalidRequest.
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
    /// @param signer    The key to sign with, as the plugin reported it.
    /// @param cardCerts Every certificate the plugin reported for the card.
    /// @return SigningResult whose @ref SigningResult::status is always set;
    ///         on @ref SigningResult::Status::Ok the artifact is in
    ///         @ref SigningResult::signedDocumentBytes.
    /// @note Returns @ref SigningResult::Status::TrustStoreUnavailable when
    ///       the libresign backend rejects the trust configuration vended by
    ///       the @ref Trust::TrustStoreService supplied at construction (for
    ///       example, an unreachable Trusted List URL or an unwritable cache
    ///       directory). Returns @ref SigningResult::Status::InvalidRequest
    ///       if @p cardPlugin or @p session is null, @p credentialProvider is
    ///       empty, or @p signer carries no key handle.
    /// @note The PIN the provider supplies is deposited in @p cardPlugin for
    ///       @p session for the signature. After a successful signature with
    ///       a key the card does not require the PIN for on every use (no
    ///       always-authenticate), the PIN stays deposited for @p session, so
    ///       a following signature in the same session presents it again
    ///       without a prompt, until the host calls
    ///       @ref LibreSCRS::Plugin::CardPlugin::clearCredentials for the
    ///       session. After a failed signature, or with an
    ///       always-authenticate key, it is erased before this returns. A host
    ///       managing the deposit itself uses
    ///       @ref LibreSCRS::Plugin::ScopedPinDeposit.
    /// @par Blocking
    /// This call blocks for the duration of the signing operation: PIN
    /// verification + APDU signing on the card (typically 1-3 s), plus
    /// any TSA round-trip for B-T / B-LT / B-LTA levels (typically
    /// 0.5-5 s, network-dependent), plus libresign packaging. GUI hosts
    /// must invoke @ref sign on a worker thread; calling it from the UI
    /// thread will freeze the UI for several seconds.
    /// @par XAdES DETACHED Reference URI constraint
    /// When @p request.format selects XAdES with DETACHED packaging, the
    /// emitted `ds:Reference URI` attribute names the original document by
    /// its percent-encoded name (e.g. `URI="my%20doc.bin"`), taken from
    /// @ref SigningRequest::documentName. Conformant XAdES validators (EU DSS,
    /// ETSI test bench, Adobe) resolve that URI relative to the location of
    /// the `.xml` signature file, so the original payload MUST be present
    /// alongside the signature under that name. Callers that hand the signed
    /// `.xml` to a recipient over the wire must include the original file
    /// too; without it, validation fails at the reference-resolution step
    /// before any cryptographic check runs.
    /// @par Exceptions
    /// `noexcept`. Per API-POLICY §5.3 noexcept-alloc contract, internal
    /// `std::bad_alloc` from libresign request construction or std::string
    /// formatting is caught and surfaced as
    /// @ref SigningResult::Status::SigningEngineError; defence-in-depth
    /// catches for `std::exception` and any other escaped throw map to
    /// the same status with a diagnostic message. All functional failure
    /// modes (trust unavailable, TSA unreachable, invalid request, user
    /// cancel) surface as a non-Ok @ref SigningResult::Status without
    /// involving the exception machinery.
    /// @since 5.0
    [[nodiscard]] SigningResult sign(const SigningRequest& request, std::span<const std::uint8_t> input,
                                     Auth::CredentialProvider credentialProvider,
                                     const std::shared_ptr<const LibreSCRS::Plugin::CardPlugin>& cardPlugin,
                                     const std::shared_ptr<LibreSCRS::SmartCard::CardSession>& session,
                                     const LibreSCRS::Plugin::CertificateData& signer,
                                     std::span<const LibreSCRS::Plugin::CertificateData> cardCerts) noexcept;

    // @since 4.0: trustStore() getter removed — consumers obtain the trust
    // store from the @ref Trust::TrustStoreService they constructed and
    // passed to this service's ctor. The lifecycle ownership model splits
    // cleanly between Trust (TrustStoreService) and Signing (SigningService).

private:
    struct Impl;
    std::unique_ptr<Impl> d;
};

} // namespace LibreSCRS::Signing
