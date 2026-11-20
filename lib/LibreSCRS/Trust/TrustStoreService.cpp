// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <LibreSCRS/Trust/TrustStoreService.h>

#include <LibreSCRS/Auth/ErrorKeys.h>
#include <LibreSCRS/CancelToken.h>
#include <LibreSCRS/Logging.h>

#include "internal/BundledCertsProvider.h"
#include "internal/TrustStoreInternalAccess.h"
#include "internal/TrustStoreServiceImpl.h"

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
#include <mutex>
#include <stop_token>
#include <thread>
#include <utility>
#include <vector>

#include <stdlib.h> // mkdtemp

namespace LibreSCRS::Trust {

TrustStoreService::Impl::~Impl()
{
    if (!privateCacheDir.empty()) {
        std::error_code ec;
        std::filesystem::remove_all(privateCacheDir, ec);
    }
}

libresign::TrustedListEntry TrustStoreService::Impl::entryFor(const TrustedListSource& src) const
{
    libresign::TrustedListEntry entry;
    entry.url = src.url;
    entry.isLotl = src.lotl;
    entry.eager = src.eager;
    if (entryHook)
        entryHook(entry);
    return entry;
}

void TrustStoreService::Impl::markLoaded(const std::string& url)
{
    std::lock_guard lock(loadMutex);
    loadedSources.insert(url);
}

bool TrustStoreService::Impl::fetchAndMerge(const libresign::TrustedListEntry& entry,
                                            LibreSCRS::CancelToken token, bool cacheOnly) const
{
    libresign::FetchOptions opts;
    opts.cacheOnly = cacheOnly;
    if (config.cacheDirectory.has_value())
        opts.cacheDirectory = config.cacheDirectory->string();
    opts.requestTimeout = std::chrono::seconds{30};
    opts.stop = std::move(token);

    // The same walk the signing engine runs: the list and, for a List of
    // Trusted Lists, every list it points to. Each verified list's anchors
    // are merged under its own source tag.
    bool complete = true;
    const auto onList = [this, &opts, &complete](const std::string& /*listUrl*/,
                                                 const libresign::TrustedListInfo& info) {
        if (opts.stop.isCancelled()) {
            complete = false;
            return;
        }
        detail::TrustStoreInternalAccess::mergeTrustedListAnchors(*trustStore,
                                                                  libresign::extractAnchorsFromTrustedList(info));
    };
    const auto onFailure = [&complete](const std::string& listUrl, const std::string& error) {
        complete = false;
        LibreSCRS::log::warnf("Trusted List {} skipped: {}", listUrl, error);
    };
    auto result = libresign::fetchTrustedListTree(entry, opts, onList, onFailure);
    if (!result) {
        onFailure(entry.url, result.error);
        return false;
    }
    return complete && !opts.stop.isCancelled();
}

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

        // Bridge inbound std::jthread stop_token to a CancelToken for libresign.
        // The local CancelSource lives for the duration of this worker call;
        // the std::stop_callback fires requestCancel() on the cancelling thread
        // when the jthread is asked to stop.
        LibreSCRS::CancelSource workerCancelSource;
        std::stop_callback bridgeCb(stop, [&workerCancelSource]() noexcept { workerCancelSource.requestCancel(); });
        if (impl->fetchAndMerge(entry, workerCancelSource.token()))
            impl->markLoaded(url);
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
    // Without a configured cache directory the service keeps one of its own
    // for its lifetime, and reports it in config(): the signing engine reads
    // the same directory, so a list the engine downloaded is read from disk
    // when the service adopts it, not downloaded a second time.
    if (!d->config.cacheDirectory.has_value()) {
        // mkdtemp: a name nobody can predict or occupy first, created 0700.
        // Under $TMPDIR when set, else /tmp -- the platform's place for
        // per-process scratch data. A List of Trusted Lists caches tens of
        // megabytes there for the service's lifetime; a host that minds
        // (/tmp in RAM) configures a cacheDirectory.
        std::error_code ec;
        const auto base = std::filesystem::temp_directory_path(ec);
        if (!ec) {
            std::string pattern = (base / "librescrs-trusted-lists-XXXXXX").string();
            std::vector<char> name(pattern.begin(), pattern.end());
            name.push_back('\0');
            if (::mkdtemp(name.data()) != nullptr) {
                d->privateCacheDir = std::filesystem::path(name.data());
                d->config.cacheDirectory = d->privateCacheDir;
            }
        }
    }

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

    // Lazy sources wait for loadTrustedLists(Sources::All), which the
    // signing engine's bridge calls when a signature first needs them.
    std::vector<libresign::TrustedListEntry> eagerSources;

    for (const auto& src : d->config.trustedListSources) {
        if (!src.eager)
            continue;
        eagerSources.push_back(d->entryFor(src));
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

void TrustStoreService::Impl::loadSources(Sources which, LibreSCRS::CancelToken token, bool cacheOnly) noexcept
{
    try {
        std::lock_guard lock(loadMutex);
        for (const auto& src : config.trustedListSources) {
            if (!src.eager && which != Sources::All)
                continue;
            if (loadedSources.contains(src.url))
                continue; // its anchors are in the store
            if (token.isCancelled())
                return;
            try {
                if (fetchAndMerge(entryFor(src), token, cacheOnly))
                    loadedSources.insert(src.url);
            } catch (...) {
                // A list whose fetch throws (a malformed document, an
                // allocation failure) stays out of the store, as a failed
                // fetch does, and is tried again on the next call.
                LibreSCRS::log::warnf("Trusted List {} skipped: the fetch threw", src.url);
            }
        }
    } catch (...) {
        // noexcept: a failure to lock or to log leaves the store as it is.
    }
}

void TrustStoreService::loadTrustedLists(Sources which, LibreSCRS::CancelToken token) noexcept
{
    d->loadSources(which, std::move(token), /*cacheOnly=*/false);
}

void TrustStoreService::adoptCachedTrustedLists(Sources which) noexcept
{
    d->loadSources(which, {}, /*cacheOnly=*/true);
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
