// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware."
#endif

#pragma once

#include "TrustAnchorProvider.h"

#include <LibreSCRS/Trust/TrustStore.h>

#include <cstdint>
#include <memory>
#include <shared_mutex>
#include <span>
#include <string>
#include <vector>

namespace LibreSCRS::Trust {

struct TrustStore::Impl
{
    mutable std::shared_mutex mtx;
    std::vector<std::shared_ptr<detail::TrustAnchorProvider>> providers;
    bool includeSystemStore = true;
};

namespace detail {

struct TrustStoreInternalAccess
{
    static TrustStore makeStore(std::string bundledCertDir, bool includeSystemTrustStore);
    static void addProvider(TrustStore& store, std::shared_ptr<TrustAnchorProvider> provider);

    /// @brief Merge a set of pre-extracted DER-encoded trust anchors into
    ///        @p store as a single provider tagged with @p sourceLabel.
    ///        DER-byte-equality dedupe is performed against existing
    ///        providers' anchors so re-merging the same anchor list is
    ///        idempotent. The anchor span is consumed; @p store retains
    ///        its own copy of the bytes.
    ///
    /// Used by both:
    ///   - @ref TrustStoreService eager-fetch worker threads, and
    ///   - @c libresign::NativeSigningService lazy-fetch path during sign().
    ///
    /// The TL→DER extraction lives upstream (libresign's
    /// @c TrustedListProvider mapping) so this entrypoint stays free of
    /// libresign types and the cross-target link stays one-way.
    ///
    /// @par Thread-safety
    /// Takes an exclusive lock on the store's internal mutex.
    static void mergeTrustedListAnchors(TrustStore& store, std::vector<TrustAnchor> anchors,
                                        const std::string& sourceLabel);
};

} // namespace detail
} // namespace LibreSCRS::Trust
