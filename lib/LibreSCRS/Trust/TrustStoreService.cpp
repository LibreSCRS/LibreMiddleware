// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <LibreSCRS/Trust/TrustStoreService.h>

#include <LibreSCRS/Auth/ErrorKeys.h>
#include <LibreSCRS/CancelToken.h>
#include <LibreSCRS/Logging.h>

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
#include <chrono>
#include <filesystem>
#include <stop_token>
#include <thread>
#include <utility>
#include <vector>

namespace LibreSCRS::Trust {

struct LIBRESCRS_INTERNAL TrustStoreService::Impl
{
    explicit Impl(TrustConfig cfg) : config(std::move(cfg)) {}

    TrustConfig config;
    std::shared_ptr<TrustStore> trustStore;

    // Worker pool — one jthread per eager source.
    std::vector<std::jthread> workers;

    /// @brief Worker entry point. Captures @p impl by shared_ptr so the
    ///        worker thread cannot outlive @c Impl, and so destruction
    ///        waits on the jthread join inside @c Impl::workers.
    static void runWorker(std::shared_ptr<Impl> impl, libresign::TrustedListEntry entry, std::stop_token stop);
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
    // OOM. An escape leaves the list's anchors out of the store, as a failed
    // fetch does, rather than aborting the process.
    try {
        if (stop.stop_requested())
            return;

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

        // The same walk the signing engine runs: the list and, for a List of
        // Trusted Lists, every list it points to. Each verified list's
        // anchors are merged under its own source tag.
        const auto onList = [&impl, &stop](const std::string& listUrl, const libresign::TrustedListInfo& info) {
            if (stop.stop_requested())
                return;
            detail::TrustStoreInternalAccess::mergeTrustedListAnchors(*impl->trustStore,
                                                                      libresign::extractAnchorsFromTrustedList(info));
        };
        const auto onFailure = [](const std::string& listUrl, const std::string& error) {
            LibreSCRS::log::warnf("Trusted List {} skipped: {}", listUrl, error);
        };
        auto result = libresign::fetchTrustedListTree(entry, opts, onList, onFailure);
        if (!result)
            onFailure(url, result.error);
    } catch (...) {
        // The logging facade may itself throw; nothing is left to report to.
        try {
            LibreSCRS::log::warnf("Trusted List {} skipped: the fetch threw", url);
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
    // trust store still applies.
    auto certsDirOpt = detail::resolveBundledCertsDir();
    std::string certsDir = certsDirOpt ? certsDirOpt->string() : std::string{};
    d->trustStore = std::make_shared<TrustStore>(
        detail::TrustStoreInternalAccess::makeStore(std::move(certsDir), /*includeSystemTrustStore=*/true));

    // Lazy sources are left to the signing engine, which fetches them when a
    // signature first needs them.
    std::vector<libresign::TrustedListEntry> eagerSources;

    for (const auto& src : d->config.trustedListSources) {
        if (!src.eager)
            continue;
        libresign::TrustedListEntry entry;
        entry.url = src.url;
        entry.isLotl = src.lotl;
        entry.eager = true;
        eagerSources.push_back(std::move(entry));
    }

    // Cap parallelism. min(eager_count, 4u) keeps a hard upper bound on
    // worker threads even when consumers configure a large multi-state
    // LOTL set; a future tier can make this configurable.
    constexpr std::size_t kMaxWorkers = 4u;
    const std::size_t workerCount = std::min(eagerSources.size(), kMaxWorkers);

    if (workerCount == 0u)
        return;

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
    //   2. move the workers vector out so its destruction happens on THIS
    //      thread (the test/host thread), not on a worker thread.
    //   3. join via destruction of the local vector (jthread::~jthread).
    //
    // Workers keep their shared_ptr<Impl> until their lambdas return; that
    // ref is dropped after step 3 completes, so Impl is destroyed cleanly
    // without any thread joining itself.
    for (auto& w : d->workers) {
        if (w.joinable())
            w.request_stop();
    }
    auto localWorkers = std::move(d->workers);
    // localWorkers' jthread destructors join on this thread before returning.
}

std::expected<std::shared_ptr<TrustStoreService>, TrustStoreService::CreateError>
TrustStoreService::create(TrustConfig config) noexcept
{
    using Auth::ErrorKeys::trustAllocationFailed;
    using Auth::ErrorKeys::trustConfigInvalid;

    // Minimal config validation — cacheDirectory must exist as a directory
    // if specified.
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

const TrustConfig& TrustStoreService::config() const
{
    static const TrustConfig empty;
    return d ? d->config : empty;
}

} // namespace LibreSCRS::Trust
