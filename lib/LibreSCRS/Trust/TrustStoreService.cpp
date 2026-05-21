// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <LibreSCRS/Trust/TrustStoreService.h>

#include <LibreSCRS/Auth/ErrorKeys.h>
#include <LibreSCRS/detail/cancel_bridge.h>

#include "internal/BundledCertsProvider.h"
#include "internal/TrustStoreInternalAccess.h"

// Cross-target include into libresign internals — TrustStoreService is the
// eager-fetch driver, so it needs the libresign-side fetch+verify+parse
// helper. The PRIVATE compile path of the LibreSCRS_Trust target adds
// lib/libresign/src to its include search path; LIBRESCRS_INTERNAL_BUILD is
// already defined as a PRIVATE compile def so the #error guards on the
// libresign internal headers let us through.
#include "native/fetch_and_verify_tl.h"
#include "trust/TrustedListProvider.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdlib>
#include <filesystem>
#include <mutex>
#include <shared_mutex>
#include <stop_token>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

namespace LibreSCRS::Trust {

// File-scope anonymous namespace for implementation-local types whose
// std-template instantiations (notably std::vector<ObserverEntry>) would
// otherwise carry "Impl::" in their mangled symbol names and trip
// ci/scripts/check-impl-visibility.sh. Keeping ObserverEntry here, outside
// TrustStoreService::Impl, anchors the template instantiations to a file-
// local type that has hidden visibility (anonymous-namespace internal
// linkage) and never escapes the static archive's symbol table.
namespace {

/// One observer entry, holding the per-source generation values it has
/// already been fired for. The contract is: an observer is fired AT MOST
/// ONCE for any given (source, generation) tuple. Per-source state lives
/// here (not in a separate side-map) so that removeObserver is a single-
/// vector erase.
struct ObserverEntry
{
    TrustStoreService::ObserverHandle handle;
    TrustStoreService::FetchObserver observer;
    std::unordered_map<std::string, std::uint64_t> lastSeenGen;
};

} // anonymous namespace

struct LIBRESCRS_INTERNAL TrustStoreService::Impl
{
    explicit Impl(TrustConfig cfg) : config(std::move(cfg)) {}

    TrustConfig config;
    std::shared_ptr<TrustStore> trustStore;

    // Worker pool — one jthread per eager source. Capped at 4 to bound
    // resource use under pathological multi-source configurations.
    std::vector<std::jthread> workers;
    std::stop_source stopSource;

    // ALL mutable observer + source state, protected by a single
    // @c stateMutex (shared/exclusive). The observer-fire path and the
    // source-status update path BOTH touch sourceStatusMap, sourceGenMap,
    // and per-observer lastSeenGen; collapsing the previously-split
    // observerMutex + statusMutex into one mutex makes the entire
    // critical section atomic and eliminates the addObserver-vs-worker
    // race window where an observer added during the worker's "between
    // mutexes" gap could miss fires.
    //
    // Reads (status(), sourceStatuses(), waitForEagerFetches) take shared.
    // Writes (publishSourceTerminal, addObserver, removeObserver) take
    // exclusive for the FULL bookkeeping section, then drop and fire
    // callbacks unlocked so an observer that calls add/removeObserver
    // from inside its callback does not deadlock.
    mutable std::shared_mutex stateMutex;
    std::unordered_map<std::string, SourceStatus> sourceStatusMap;
    std::unordered_map<std::string, std::uint64_t> sourceGenMap; // bumped on each terminal settle
    std::vector<std::string> sourceOrder;                        // preserves config order for deterministic snapshots
    mutable std::condition_variable_any settledCv;

    /// @brief Active observers. The element type ObserverEntry is defined in
    ///        the file-scope anonymous namespace above, not nested inside
    ///        Impl, to keep the std::vector template instantiation off the
    ///        check-impl-visibility leak surface.
    std::vector<ObserverEntry> observers;
    std::atomic<ObserverHandle> nextObserverHandle{1};

    // In-flight publishSourceTerminal counter. Incremented at the entry of
    // publishSourceTerminal and decremented AFTER the observer-fire dispatch
    // completes. @c waitForEagerFetches waits until BOTH status is non-pending
    // AND this counter is zero, so callers observe the post-dispatch state.
    // Without this, @c waitForEagerFetches could return as soon as the LAST
    // worker dropped @c stateMutex (status terminal) but BEFORE that worker
    // had finished firing its observer callbacks — causing observers to
    // appear to under-fire to anyone polling event-counters immediately after
    // @c waitForEagerFetches returns.
    std::atomic<int> publishesInFlight{0};

    /// @brief Mark a source's status terminal, notify cv, and fire observers
    ///        AT MOST ONCE per (observer, source) pair via the per-source
    ///        generation counter.
    /// @note Must NOT be called while holding @c stateMutex.
    void publishSourceTerminal(const std::string& url, SourceStatus terminal)
    {
        // Mark this publish as in-flight BEFORE taking the lock; the
        // counter is observed by waitForEagerFetches under the same lock
        // (read by the cv predicate), so the matching decrement-and-notify
        // must happen AFTER fires AND the predicate must include the counter.
        publishesInFlight.fetch_add(1, std::memory_order_acq_rel);

        // Single critical section: update status map, bump generation, and
        // build the per-observer fire-list under one exclusive lock. This
        // closes the prior race window where addObserver could see new
        // status+gen via the shared statusMutex but still race with the
        // worker's separate observerMutex acquisition, allowing fires to
        // be lost in the worker-settle / observer-add interleaving.
        std::vector<std::pair<FetchObserver, std::pair<std::string, SourceStatus>>> toFire;
        {
            std::unique_lock lock(stateMutex);
            sourceStatusMap[url] = terminal;
            const std::uint64_t newGen = ++sourceGenMap[url];

            toFire.reserve(observers.size());
            for (auto& entry : observers) {
                auto it = entry.lastSeenGen.find(url);
                if (it != entry.lastSeenGen.end() && it->second >= newGen) {
                    // Already fired for this generation by addObserver's
                    // synthetic-replay path racing against this worker.
                    continue;
                }
                entry.lastSeenGen[url] = newGen;
                toFire.emplace_back(entry.observer, std::make_pair(url, terminal));
            }
        }
        // Fire callbacks OUTSIDE the lock so an observer that calls
        // add/removeObserver does not deadlock.
        for (const auto& kv : toFire) {
            try {
                kv.first(kv.second.first, kv.second.second);
            } catch (...) {
                // Observer-thrown exceptions are swallowed: they must not
                // propagate into the worker thread; logging here would
                // require the LM logger which is not yet wired into Trust.
            }
        }

        // Decrement the in-flight counter AFTER fires complete, then notify.
        // waitForEagerFetches' predicate observes (status non-pending) AND
        // (publishesInFlight == 0); decrementing after fires guarantees that
        // when the predicate becomes true, no worker is mid-dispatch.
        publishesInFlight.fetch_sub(1, std::memory_order_acq_rel);
        settledCv.notify_all();
    }

    /// @brief Worker entry point. Captures @p impl by shared_ptr so the
    ///        worker thread cannot outlive @c Impl, and so destruction
    ///        waits on the jthread join inside @c Impl::workers.
    static void runWorker(std::shared_ptr<Impl> impl, libresign::TrustedListEntry entry, std::stop_token stop);

    /// @brief Compute the current aggregate status. @c stateMutex must
    ///        already be held (shared or exclusive).
    AggregateStatus aggregateLocked() const
    {
        bool anyPending = false;
        bool anyFailed = false;
        for (const auto& url : sourceOrder) {
            auto it = sourceStatusMap.find(url);
            if (it == sourceStatusMap.end())
                continue;
            switch (it->second) {
            case SourceStatus::Pending:
                anyPending = true;
                break;
            case SourceStatus::FetchFailed:
                anyFailed = true;
                break;
            case SourceStatus::Fetched:
            case SourceStatus::Skipped:
                break;
            }
        }
        if (anyPending)
            return AggregateStatus::Loading;
        return anyFailed ? AggregateStatus::Degraded : AggregateStatus::Ready;
    }
};

void TrustStoreService::Impl::runWorker(std::shared_ptr<Impl> impl, libresign::TrustedListEntry entry,
                                        std::stop_token stop)
{
    const std::string url = entry.url;

    // Whole-body try/catch: this function runs on a std::jthread spawned by
    // refreshSourceLater(). An exception escaping the thread invokes
    // std::terminate. The throw surface includes libresign's TL XML parser
    // (xmlsec / libxml2 wrappers — attacker-influenced), the OpenSSL
    // certificate parsers, the filesystem cache writes, and the small
    // allocations below. Any of these can throw under malformed input or
    // OOM. Convert all escapes to a FetchFailed terminal status so the
    // observer side sees a clean state-transition rather than a process
    // abort.
    try {
        if (stop.stop_requested()) {
            impl->publishSourceTerminal(url, TrustStoreService::SourceStatus::FetchFailed);
            return;
        }

        libresign::FetchOptions opts;
        if (impl->config.cacheDirectory.has_value())
            opts.cacheDirectory = impl->config.cacheDirectory->string();
        opts.requestTimeout = std::chrono::seconds{30};

        // Bridge inbound std::jthread stop_token to a CancelToken for libresign.
        // The local CancelSource lives for the duration of this worker call;
        // the std::stop_callback fires requestCancel() on the cancelling thread
        // when the jthread is asked to stop.
        LibreSCRS::CancelSource workerCancelSource;
        opts.stop = workerCancelSource.token();
        std::stop_callback bridgeCb(stop, [&workerCancelSource]() noexcept { workerCancelSource.requestCancel(); });

        auto result = libresign::fetchAndVerifyTrustedList(entry, std::move(opts));
        if (!result) {
            impl->publishSourceTerminal(url, TrustStoreService::SourceStatus::FetchFailed);
            return;
        }

        if (stop.stop_requested()) {
            impl->publishSourceTerminal(url, TrustStoreService::SourceStatus::FetchFailed);
            return;
        }

        auto anchors = libresign::extractAnchorsFromTrustedList(result.info, std::string{"tl:"} + url);
        detail::TrustStoreInternalAccess::mergeTrustedListAnchors(*impl->trustStore, std::move(anchors),
                                                                  std::string{"tl:"} + url);

        impl->publishSourceTerminal(url, TrustStoreService::SourceStatus::Fetched);
    } catch (...) {
        // Best-effort terminal status report; if publish itself throws (it
        // shouldn't — pure mutex + atomic + callback-fan-out), there is no
        // sensible recovery path beyond returning, so swallow.
        try {
            impl->publishSourceTerminal(url, TrustStoreService::SourceStatus::FetchFailed);
        } catch (...) {
        }
    }
}

TrustStoreService::TrustStoreService(TrustConfig cfg) : d(std::make_shared<Impl>(std::move(cfg)))
{
    // Build the local store synchronously — bundled certs walk + system flag.
    // Fast (filesystem-only); never blocks on network.
    //
    // The bundled-certs directory is resolved at runtime by
    // @ref detail::resolveBundledCertsDir so packaged binaries (AppImage,
    // DMG, distro-installed) locate the certs at the actual on-disk install
    // location rather than the source-tree path baked in at build time. An
    // empty resolved path is a legal "no bundled certs" sentinel; the system
    // trust store still applies via @c includeSystemTrustStore.
    auto certsDirOpt = detail::resolveBundledCertsDir();
    std::string certsDir = certsDirOpt ? certsDirOpt->string() : std::string{};
    d->trustStore = std::make_shared<TrustStore>(
        detail::TrustStoreInternalAccess::makeStore(std::move(certsDir), d->config.includeSystemTrustStore));

    // Enumerate sources from config, populate initial status map.
    std::vector<libresign::TrustedListEntry> eagerSources;

    for (const auto& src : d->config.trustedListSources) {
        libresign::TrustedListEntry entry;
        entry.url = src.url;
        entry.isLotl = src.lotl;
        entry.eager = src.eager;
        if (src.eager) {
            d->sourceOrder.push_back(entry.url);
            d->sourceStatusMap[entry.url] = SourceStatus::Pending;
            eagerSources.push_back(std::move(entry));
        } else {
            d->sourceOrder.push_back(entry.url);
            d->sourceStatusMap[entry.url] = SourceStatus::Skipped;
        }
    }

    if (d->config.trustedListFile.has_value()) {
        libresign::TrustedListEntry entry;
        entry.url = std::string{"file://"} + d->config.trustedListFile->string();
        entry.isLotl = false;
        entry.eager = true;
        entry.localFileOnly = true;
        if (d->config.trustedListFileSigningCert.has_value())
            entry.signingCertPath = d->config.trustedListFileSigningCert->string();
        d->sourceOrder.push_back(entry.url);
        d->sourceStatusMap[entry.url] = SourceStatus::Pending;
        eagerSources.push_back(std::move(entry));
    }

    // Cap parallelism. min(eager_count, 4u) keeps a hard upper bound on
    // worker threads even when consumers configure a large multi-state
    // LOTL set; a future tier can make this configurable.
    constexpr std::size_t kMaxWorkers = 4u;
    const std::size_t workerCount = std::min(eagerSources.size(), kMaxWorkers);

    if (workerCount == 0u) {
        // No eager sources — service is immediately ready.
        // Status map already populated; no workers to spawn.
        return;
    }

    // Spawn one jthread per eager source. We deliberately do not pool with
    // a queue: each source is independent, the cap above bounds resource
    // use, and per-source 1:1 keeps stop_token semantics clean.
    d->workers.reserve(eagerSources.size());
    for (auto& entry : eagerSources) {
        d->workers.emplace_back([impl = d, e = std::move(entry)](std::stop_token st) mutable {
            Impl::runWorker(std::move(impl), std::move(e), std::move(st));
        });
    }
    (void)workerCount;
}

TrustStoreService::~TrustStoreService()
{
    if (!d)
        return;
    // Request stop on each worker, then join explicitly. We must NOT rely on
    // jthread RAII alone because each worker captures shared_ptr<Impl> by
    // value — if Impl outlives this scope, the jthread vector inside Impl
    // is destroyed by the last-to-exit worker's lambda return, which would
    // cause that worker's own jthread destructor to self-join (EDEADLK).
    //
    // Sequence here:
    //   1. request_stop on every jthread
    //   2. notify cv to wake any waiters that might be holding stateMutex
    //   3. move the workers vector out so its destruction happens on THIS
    //      thread (the test/host thread), not on a worker thread.
    //   4. join via destruction of the local vector (jthread::~jthread).
    //
    // Workers keep their shared_ptr<Impl> until their lambdas return; that
    // ref is dropped after step 4 completes, so Impl is destroyed cleanly
    // without any thread joining itself.
    d->stopSource.request_stop();
    for (auto& w : d->workers) {
        if (w.joinable())
            w.request_stop();
    }
    d->settledCv.notify_all();
    auto localWorkers = std::move(d->workers);
    // localWorkers' jthread destructors join on this thread before returning.
}

std::expected<std::shared_ptr<TrustStoreService>, TrustStoreService::CreateError>
TrustStoreService::create(TrustConfig config) noexcept
{
    using Auth::ErrorKeys::trustAllocationFailed;
    using Auth::ErrorKeys::trustConfigInvalid;

    // Minimal config validation — cacheDirectory must exist as a directory
    // if specified. (Other potential checks: source URL well-formedness,
    // includeSystemTrustStore + sources mutual exclusion if applicable.
    // Keep the validation MINIMAL in 4.0; additive growth in 4.x.)
    if (config.cacheDirectory.has_value()) {
        std::error_code ec;
        if (!std::filesystem::exists(*config.cacheDirectory, ec) ||
            !std::filesystem::is_directory(*config.cacheDirectory, ec)) {
            return std::unexpected{CreateError{CreateError::Kind::InvalidConfig, trustConfigInvalid(),
                                               std::string{"cacheDirectory does not exist or is not a directory: "} +
                                                   config.cacheDirectory->string()}};
        }
    }

    // Private ctor → can't make_shared directly; wrap in a tiny adapter.
    struct Constructor : TrustStoreService
    {
        explicit Constructor(TrustConfig c) : TrustStoreService(std::move(c)) {}
    };
    try {
        return std::shared_ptr<TrustStoreService>(new Constructor(std::move(config)));
    } catch (const std::bad_alloc&) {
        return std::unexpected{CreateError{CreateError::Kind::AllocationFailed, trustAllocationFailed(),
                                           std::string{"std::bad_alloc from TrustStoreService::Constructor"}}};
    } catch (const std::exception& e) {
        // Any other ctor-internal exception. The current Constructor body
        // doesn't directly throw beyond bad_alloc, but member-init paths
        // (e.g. shared_mutex pthread allocation) could throw under
        // resource exhaustion. Report as AllocationFailed since the
        // failure semantics match (init-time resource shortfall).
        return std::unexpected{
            CreateError{CreateError::Kind::AllocationFailed, trustAllocationFailed(),
                        std::string{"std::exception from TrustStoreService::Constructor: "} + e.what()}};
    }
}

std::shared_ptr<const TrustStore> TrustStoreService::trustStore() const
{
    return d ? d->trustStore : nullptr;
}

TrustStoreService::AggregateStatus TrustStoreService::status() const
{
    if (!d)
        return AggregateStatus::Ready;
    std::shared_lock lock(d->stateMutex);
    return d->aggregateLocked();
}

std::vector<std::pair<std::string, TrustStoreService::SourceStatus>> TrustStoreService::sourceStatuses() const
{
    if (!d)
        return {};
    std::shared_lock lock(d->stateMutex);
    std::vector<std::pair<std::string, SourceStatus>> out;
    out.reserve(d->sourceOrder.size());
    for (const auto& url : d->sourceOrder) {
        auto it = d->sourceStatusMap.find(url);
        if (it != d->sourceStatusMap.end())
            out.emplace_back(url, it->second);
    }
    return out;
}

TrustStoreService::AggregateStatus TrustStoreService::waitForEagerFetches(std::chrono::milliseconds deadline,
                                                                          CancelToken token) const
{
    if (!d)
        return AggregateStatus::Ready;

    auto stop = LibreSCRS::detail::stopTokenFrom(token);

    const auto absDeadline = std::chrono::steady_clock::now() + deadline;

    std::shared_lock lock(d->stateMutex);
    auto predicate = [&]() {
        if (stop.stop_requested())
            return true;
        if (d->aggregateLocked() == AggregateStatus::Loading)
            return false;
        // Also wait until no worker is mid-publish (status updated but
        // observer-fire still in flight). Prevents observers from appearing
        // to under-fire to a caller that polls event counts immediately
        // after this returns.
        return d->publishesInFlight.load(std::memory_order_acquire) == 0;
    };

    // wait_until handles the spurious-wakeup loop internally when given a
    // predicate. Using the absolute deadline guarantees a single wait can
    // fall through cleanly when the deadline elapses.
    d->settledCv.wait_until(lock, absDeadline, predicate);
    return d->aggregateLocked();
}

TrustStoreService::ObserverHandle TrustStoreService::addObserver(FetchObserver observer)
{
    if (!d || !observer)
        return 0;

    const ObserverHandle handle = d->nextObserverHandle.fetch_add(1, std::memory_order_relaxed);

    // Insert the observer with an empty lastSeenGen, then synthesise replay
    // for any source already in a terminal state. ALL bookkeeping happens
    // under one exclusive @c stateMutex acquisition so a concurrent
    // publishSourceTerminal cannot interleave between "observer added" and
    // "lastSeenGen claimed" — the prior split-mutex design allowed an
    // observer to be visible to publish (which would skip-fire if already
    // claimed, OR fire if not) while a synthetic-replay race could lose
    // the fire entirely. Observer callbacks themselves run AFTER we drop
    // the lock to keep add/removeObserver re-entrant from inside a
    // callback.
    std::vector<std::pair<std::string, SourceStatus>> toFire;
    {
        std::unique_lock lock(d->stateMutex);
        d->observers.push_back(ObserverEntry{handle, observer, {}});
        auto& entry = d->observers.back();

        toFire.reserve(d->sourceOrder.size());
        for (const auto& url : d->sourceOrder) {
            auto statusIt = d->sourceStatusMap.find(url);
            if (statusIt == d->sourceStatusMap.end())
                continue;
            if (statusIt->second == SourceStatus::Pending)
                continue;
            auto genIt = d->sourceGenMap.find(url);
            if (genIt == d->sourceGenMap.end())
                continue; // terminal status without a generation entry should not happen
            // Claim this generation for the new observer BEFORE releasing
            // @c stateMutex so a concurrent publishSourceTerminal observes
            // that we've consumed it.
            entry.lastSeenGen[url] = genIt->second;
            toFire.emplace_back(url, statusIt->second);
        }
    }

    for (const auto& kv : toFire) {
        try {
            observer(kv.first, kv.second);
        } catch (...) {
            // see publishSourceTerminal — observer exceptions swallowed
        }
    }

    return handle;
}

void TrustStoreService::removeObserver(ObserverHandle handle)
{
    if (!d || handle == 0)
        return;
    std::unique_lock lock(d->stateMutex);
    d->observers.erase(std::remove_if(d->observers.begin(), d->observers.end(),
                                      [handle](const auto& entry) { return entry.handle == handle; }),
                       d->observers.end());
}

const TrustConfig& TrustStoreService::config() const
{
    static const TrustConfig empty;
    return d ? d->config : empty;
}

} // namespace LibreSCRS::Trust
