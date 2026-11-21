// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "Trust/internal/TrustStoreServiceImpl.h is internal to LibreMiddleware."
#endif

#pragma once

#include <LibreSCRS/CancelToken.h>
#include <LibreSCRS/Export.h>
#include <LibreSCRS/Trust/TrustConfig.h>
#include <LibreSCRS/Trust/TrustStore.h>
#include <LibreSCRS/Trust/TrustStoreService.h>

#include "types.h" // libresign::TrustedListEntry

#include <filesystem>
#include <memory>
#include <mutex>
#include <set>
#include <stop_token>
#include <string>
#include <thread>
#include <vector>

namespace LibreSCRS::Trust {

/// @brief Private state of @ref TrustStoreService. In an internal header so
///        the service's tests can reach it through
///        @ref detail::TrustStoreServiceAccess.
struct LIBRESCRS_INTERNAL TrustStoreService::Impl
{
    explicit Impl(TrustConfig cfg) : config(std::move(cfg)) {}
    ~Impl();

    Impl(const Impl&) = delete;
    Impl& operator=(const Impl&) = delete;

    /// The configuration in effect: as given, with cacheDirectory filled in
    /// with @ref privateCacheDir when none was given.
    TrustConfig config;
    std::shared_ptr<TrustStore> trustStore;

    /// A cache directory the service created because none was configured,
    /// shared with the signing engine through @ref config so a list is
    /// downloaded once; removed with the service. Empty when one was given.
    std::filesystem::path privateCacheDir;

    // Worker pool — one jthread per eager source.
    std::vector<std::jthread> workers;

    /// The configured sources (by URL) whose list, and for a List of Trusted
    /// Lists every list it points to, have been fetched, verified and merged.
    /// A source not in it is fetched again on the next loadTrustedLists().
    std::mutex loadMutex;
    std::set<std::string> loadedSources;

    /// The fetch entry of @p src (TrustStoreServiceEntry.cpp).
    [[nodiscard]] libresign::TrustedListEntry entryFor(const TrustedListSource& src) const;

    /// @brief Worker entry point. Captures @p impl by shared_ptr so the
    ///        worker thread cannot outlive @c Impl, and so destruction
    ///        waits on the jthread join inside @c Impl::workers.
    static void runWorker(std::shared_ptr<Impl> impl, libresign::TrustedListEntry entry, std::stop_token stop);

    /// @brief Fetch @p entry (and, for a List of Trusted Lists, every list it
    ///        points to) and merge the anchors of each list that verifies.
    ///        A list that fails is logged and skipped. True only when every
    ///        list of the walk was merged. Throws what the fetch throws.
    bool fetchAndMerge(const libresign::TrustedListEntry& entry, LibreSCRS::CancelToken token,
                       bool cacheOnly = false) const;

    /// loadTrustedLists() and adoptCachedTrustedLists(): every source of
    /// @p which not loaded yet, from the cache alone when @p cacheOnly.
    void loadSources(Sources which, LibreSCRS::CancelToken token, bool cacheOnly) noexcept;

    /// @brief Records @p url as loaded.
    void markLoaded(const std::string& url);
};

namespace detail {

/// @brief Test access to a service's private state.
struct TrustStoreServiceAccess
{
    static TrustStoreService::Impl& impl(TrustStoreService& service) noexcept
    {
        return *service.d;
    }
};

} // namespace detail

} // namespace LibreSCRS::Trust
