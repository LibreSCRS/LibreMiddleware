// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

/// @file
/// @brief @ref LibreSCRS::Trust::TrustStoreService — first-class lifecycle
///        owner of @ref LibreSCRS::Trust::TrustStore. Construction is
///        asynchronous + non-throwing: the local anchor set is built
///        synchronously while configured Trusted-List sources are fetched on
///        internal worker threads. Consumers observe completion via
///        #LibreSCRS::Trust::TrustStoreService::status,
///        #LibreSCRS::Trust::TrustStoreService::addObserver, or the opt-in
///        #LibreSCRS::Trust::TrustStoreService::waitForEagerFetches.

#include <LibreSCRS/CancelToken.h>
#include <LibreSCRS/Export.h>
#include <LibreSCRS/LocalizedText.h>
#include <LibreSCRS/Trust/TrustConfig.h>
#include <LibreSCRS/Trust/TrustStore.h>

#include <chrono>
#include <cstdint>
#include <expected>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace LibreSCRS::Trust {

/// @brief Lifecycle owner of @ref TrustStore. Builds the local anchor set
///        synchronously (bundled certs + optional OS root store) and
///        performs all configured Trusted-List fetches asynchronously.
///
/// `TrustStoreService` is the entry point for every consumer that needs
/// trust-anchor knowledge: the certificate viewer, plugin registry,
/// signing service, and any future tooling. Construction never blocks
/// on network IO and never throws — @ref create always returns a
/// usable service. Eager TL fetches run on internal worker threads;
/// consumers observe completion via @ref status, @ref addObserver, or
/// the opt-in @ref waitForEagerFetches.
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
/// callers can render UI immediately (with bundled + system anchors)
/// and update the view incrementally as remote anchors arrive.
///
/// @since 4.0
class LIBRESCRS_PUBLIC_API TrustStoreService
{
public:
    /// @brief Per-source fetch outcome.
    /// @since 4.0
    enum class SourceStatus {
        Pending,     ///< fetch not yet started or in flight
        Fetched,     ///< fetch completed successfully; anchors merged
        FetchFailed, ///< network error, parse error, or signature failure
        Skipped,     ///< source disabled or lazy with no demand yet
    };

    /// @brief Aggregate fetch state across all eager sources.
    /// @since 4.0
    enum class AggregateStatus {
        Loading,  ///< at least one eager source still pending
        Ready,    ///< all eager sources fetched successfully (or no eager sources configured)
        Degraded, ///< all eager sources settled; one or more failed
    };

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

    /// @brief Snapshot of fetch state. Cheap; returns by value.
    /// @par Thread-safety
    /// Reentrant; reads under shared lock.
    /// @since 4.0
    [[nodiscard]] AggregateStatus status() const;

    /// @brief Per-source status snapshot, keyed by the source URL.
    /// @note Only enumerates sources from the original @ref TrustConfig.
    /// @par Thread-safety
    /// Reentrant; reads under shared lock.
    /// @since 4.0
    [[nodiscard]] std::vector<std::pair<std::string, SourceStatus>> sourceStatuses() const;

    /// @brief Block until every eager TL fetch is settled, the deadline
    ///        elapses, or @c token requests cancel.
    /// @return The aggregate status at return time. May be @c Loading
    ///         if the deadline elapsed or cancellation fired before
    ///         all sources settled.
    /// @par Use cases
    /// Tests, CLI tooling, and headless consumers that legitimately
    /// want a synchronous wait. GUI consumers should NOT call this
    /// blocking variant — subscribe via @ref addObserver instead.
    /// @par Thread-safety
    /// Reentrant; multiple threads may wait concurrently. Each thread
    /// returns when its own predicate is satisfied.
    /// @since 4.0
    [[nodiscard]] AggregateStatus waitForEagerFetches(std::chrono::milliseconds deadline, CancelToken token = {}) const;

    /// @brief Observer callback fired once per eager source as it
    ///        settles (succeeded, failed, or cancelled).
    /// @note Invoked on an internal worker thread; if the consumer
    ///       lives on a UI thread (Qt, etc.) it must marshal back
    ///       via the platform's queued-invocation primitive.
    /// @since 4.0
    using FetchObserver = std::function<void(std::string_view sourceUrl, SourceStatus)>;

    /// @brief Opaque handle returned by @ref addObserver and consumed by
    ///        @ref removeObserver.
    /// @since 4.0
    using ObserverHandle = std::uint64_t;

    /// @brief Subscribe to fetch-completion events.
    /// @return Opaque handle; pass to @ref removeObserver to detach.
    ///
    /// @par Fire-once contract
    /// Each observer is invoked AT MOST ONCE per (source, terminal-status)
    /// transition, regardless of subscription order. A worker thread that
    /// settles a source while @ref addObserver is mid-flight cannot fire
    /// the new observer for the same generation that addObserver's
    /// synthetic-replay path will fire — the implementation tracks a
    /// per-source generation counter and a per-observer last-seen-generation
    /// map under the service's state mutex. Once a (source, generation)
    /// pair has been claimed by either path, the other path skips it.
    ///
    /// @note Observers added AFTER a source has already settled receive
    ///       a synthetic invocation for that source's terminal status,
    ///       so subscription order is not racy w.r.t. fetches.
    /// @par Thread-safety
    /// Reentrant. The synthetic-replay invocation runs on the calling
    /// thread; subsequent settle events fire on internal worker threads.
    /// @warning Do NOT call @ref addObserver or @ref removeObserver from
    ///          within a `FetchObserver` invocation on the same service
    ///          — this deadlocks. The implementation provides no runtime
    ///          detection guard.
    /// @since 4.0
    [[nodiscard]] ObserverHandle addObserver(FetchObserver observer);

    /// @brief Detach an observer.
    /// @note Idempotent — a no-op when @p handle is unknown or already
    ///       removed. After this call returns, no further invocations
    ///       of the observer are scheduled, but a fire that began
    ///       before the call may still complete on its worker thread.
    /// @par Thread-safety
    /// Reentrant.
    /// @since 4.0
    void removeObserver(ObserverHandle handle);

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
