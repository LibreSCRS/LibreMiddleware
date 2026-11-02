// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

/// @file
/// @brief @ref LibreSCRS::Trust::TrustStoreService — first-class lifecycle
///        owner of @ref LibreSCRS::Trust::TrustStore. Construction is
///        asynchronous + non-throwing: the local anchor set is built
///        synchronously while eager Trusted-List sources are fetched on
///        internal worker threads; their anchors join the store as they
///        arrive.

#include <LibreSCRS/Export.h>
#include <LibreSCRS/LocalizedText.h>
#include <LibreSCRS/Trust/TrustConfig.h>
#include <LibreSCRS/Trust/TrustStore.h>

#include <cstdint>
#include <expected>
#include <memory>
#include <optional>
#include <string>
#include <utility>

namespace LibreSCRS::Trust {

/// @brief Lifecycle owner of @ref TrustStore. Builds the local anchor set
///        synchronously (bundled certs + optional OS root store) and
///        performs all configured Trusted-List fetches asynchronously.
///
/// `TrustStoreService` is the entry point for every consumer that needs
/// trust-anchor knowledge: the certificate viewer, plugin registry,
/// signing service, and any future tooling. Construction never blocks
/// on network IO and never throws — @ref create always returns a
/// usable service. Eager TL fetches run on internal worker threads and
/// merge their anchors into @ref trustStore as each list verifies.
///
/// @par Lifetime & sharing
/// Owned by @c shared_ptr (the factory enforces this via private ctor).
/// The underlying @ref TrustStore is itself shared with consumers; both
/// stay alive as long as any consumer holds either pointer.
///
/// @par Thread-safety
/// All public methods are thread-safe (see API-POLICY §8). Construction
/// returns before any network IO has begun; the underlying @ref TrustStore
/// uses internal shared/exclusive locking and grows safely from multiple
/// worker threads as anchors arrive.
///
/// @par Design rationale
/// LibreMiddleware policy is "no exceptions across the public API
/// surface; status-code returns instead" — the same policy
/// @ref Signing::SigningService applies to TrustConfig validation. By
/// returning a usable service even when the network is unreachable,
/// callers can render UI immediately (with bundled + system anchors);
/// remote anchors join the same store as they arrive.
///
/// @since 4.0
class LIBRESCRS_PUBLIC_API TrustStoreService
{
public:
    /// @brief Failure outcome of @ref create. Same shape as every other
    ///        public Error type — coarse @ref Kind enum, mandatory
    ///        @ref userMessage, optional @ref diagnosticDetail.
    /// @since 4.0
    struct CreateError
    {
        /// @brief Failure classification. Append-only — coarse in 4.0;
        ///        finer values added additively in 4.x without breaking.
        enum class Kind : std::uint8_t {
            /// TrustConfig path / source / flag combination rejected by
            /// validation (e.g. cacheDirectory points at a nonexistent
            /// path, source URL is malformed). Specific cause in
            /// @ref diagnosticDetail.
            InvalidConfig,
            /// std::bad_alloc caught from the underlying ctor — the
            /// noexcept contract converts the throw into a structured
            /// failure rather than propagating. Mostly hypothetical on
            /// production hardware.
            AllocationFailed,
        };

        Kind kind;
        /// @brief Translator-friendly user-facing message. Mandatory.
        LocalizedText userMessage;
        /// @brief Optional dev-facing detail (logs / telemetry only).
        ///        Never carries secret material.
        std::optional<std::string> diagnosticDetail;

        CreateError(Kind k, LocalizedText msg, std::optional<std::string> diag = std::nullopt) noexcept
            : kind(k), userMessage(std::move(msg)), diagnosticDetail(std::move(diag))
        {}

        /// @brief Default construction is deleted — a default-constructed
        ///        @ref LocalizedText would render as an empty string,
        ///        defeating the mandatory-userMessage invariant. Construct
        ///        via the field-wise constructor with an explicit message.
        CreateError() = delete;
    };

    /// @brief Construct a TrustStoreService over @p config.
    /// @return On success, a non-null `std::shared_ptr<TrustStoreService>`.
    ///         On failure, a @ref CreateError carrying classification and
    ///         diagnostic.
    /// @since 4.0
    /// @par C++23 Idiom
    /// @code
    /// auto result = TrustStoreService::create(std::move(config));
    /// if (!result) {
    ///     log("Trust store init failed: {}", result.error().userMessage.defaultText);
    ///     return;
    /// }
    /// std::shared_ptr<TrustStoreService> svc = *result;
    /// @endcode
    [[nodiscard]] static std::expected<std::shared_ptr<TrustStoreService>, CreateError>
    create(TrustConfig config) noexcept;

    ~TrustStoreService();
    TrustStoreService(const TrustStoreService&) = delete;
    TrustStoreService& operator=(const TrustStoreService&) = delete;
    TrustStoreService(TrustStoreService&&) = delete;
    TrustStoreService& operator=(TrustStoreService&&) = delete;

    /// @brief Read-only access to the composed trust store. The store
    ///        grows asynchronously as eager fetches complete.
    /// @par Thread-safety
    /// Cheap and reentrant. Returned shared_ptr aliases the same underlying
    /// store across the service's lifetime; the store itself uses internal
    /// shared/exclusive locking for concurrent reads/writes.
    /// @par Lifetime & sharing
    /// The returned snapshot is monotonically growing — consumers MUST NOT
    /// cache @ref TrustStore::enumerableAnchors() and assume immutability.
    /// New anchors land asynchronously as eager fetches complete and as
    /// lazy fetches run inside @ref Signing::SigningService::sign.
    /// @since 4.0
    [[nodiscard]] std::shared_ptr<const TrustStore> trustStore() const;

    /// @brief Snapshot of the original config the service was constructed
    ///        with. Useful for diagnostics and for @ref Signing::SigningService
    ///        to forward the same config to the libresign engine.
    /// @par Thread-safety
    /// Reentrant; the returned reference is to immutable post-construction
    /// state.
    /// @since 4.0
    [[nodiscard]] const TrustConfig& config() const;

private:
    explicit TrustStoreService(TrustConfig config);
    struct Impl;
    std::shared_ptr<Impl> d; // shared because async tasks reference it
};

} // namespace LibreSCRS::Trust
