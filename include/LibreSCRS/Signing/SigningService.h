// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

/// @file
/// @brief @ref LibreSCRS::Signing::SigningService — the public entry point
///        for PAdES / XAdES / JAdES signing. Pure DI (@ref
///        LibreSCRS::Trust::TrustConfig +
///        @ref LibreSCRS::Signing::TsaProvider in the ctor, per-call
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

#include <memory>

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
/// pointer is plumbed via the constructor, eliminating the lazy-init race
/// the previous TrustConfig-in-ctor design had.
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
    /// @since 4.0.
    explicit operator bool() const noexcept;

    /// @brief Produce a signature for @p request.
    /// @param request Immutable signing parameters.
    /// @param credentialProvider Callback that collects the signing PIN.
    /// @param cardPlugin Plugin used to drive on-card operations. Shared
    ///                   ownership: the service retains the plugin for the
    ///                   duration of the call, which matters if internal
    ///                   workers outlive the caller's stack frame.
    /// @param session Live card session. Shared ownership mirrors @p cardPlugin
    ///                — the session is kept alive until the sign operation
    ///                fully completes, eliminating the UAF-on-shutdown class.
    /// @return SigningResult whose @ref SigningResult::status is always set.
    /// @note Returns @ref SigningResult::Status::TrustStoreUnavailable when
    ///       the libresign backend rejects the TrustConfig supplied at
    ///       construction (for example, an unreachable Trusted List URL or
    ///       an unwritable cache directory). Returns
    ///       @ref SigningResult::Status::InvalidRequest if @p cardPlugin or
    ///       @p session is null, or @p credentialProvider is empty.
    /// @par Blocking
    /// This call blocks for the duration of the signing operation: PIN
    /// verification + APDU signing on the card (typically 1-3 s), plus
    /// any TSA round-trip for B-T / B-LT / B-LTA levels (typically
    /// 0.5-5 s, network-dependent), plus libresign packaging. GUI hosts
    /// must invoke @ref sign on a worker thread; calling it from the UI
    /// thread will freeze the UI for several seconds. There is no
    /// cancellation hook in 4.0 — see the project BACKLOG for the 4.1
    /// async overload that adds @ref LibreSCRS::CancelToken support.
    [[nodiscard]] SigningResult sign(const SigningRequest& request, Auth::CredentialProvider credentialProvider,
                                     std::shared_ptr<LibreSCRS::Plugin::CardPlugin> cardPlugin,
                                     std::shared_ptr<LibreSCRS::SmartCard::CardSession> session);

    // @since 4.0: trustStore() getter removed — consumers obtain the trust
    // store from the @ref Trust::TrustStoreService they constructed and
    // passed to this service's ctor. The lifecycle ownership model splits
    // cleanly between Trust (TrustStoreService) and Signing (SigningService).

private:
    struct Impl;
    std::unique_ptr<Impl> d;
};

} // namespace LibreSCRS::Signing
