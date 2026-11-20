// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware."
#endif

#pragma once

#include "TrustAnchorProvider.h"

#include <LibreSCRS/Export.h>
#include <LibreSCRS/Trust/TrustStore.h>

#include <cstdint>
#include <memory>
#include <shared_mutex>
#include <span>
#include <string>
#include <vector>

namespace LibreSCRS::Trust {

struct LIBRESCRS_INTERNAL TrustStore::Impl
{
    mutable std::shared_mutex mtx;
    std::vector<std::shared_ptr<detail::TrustAnchorProvider>> providers;
    bool includeSystemStore = true;
};

namespace detail {

struct TrustStoreInternalAccess
{
    // Intra-LibreSCRS_Trust callers only — no LIBRESCRS_PUBLIC_API marker
    // keeps the symbols hidden in the SHARED-build .so.
    static TrustStore makeStore(std::string bundledCertDir, bool includeSystemTrustStore);

    /// @brief Merge a set of pre-extracted DER-encoded trust anchors into
    ///        @p store as a single provider.
    ///        DER-byte-equality dedupe is performed against existing
    ///        providers' anchors so re-merging the same anchor list is
    ///        idempotent. The anchor span is consumed; @p store retains
    ///        its own copy of the bytes.
    ///
    /// Called only by @ref TrustStoreService (its eager workers and
    /// loadTrustedLists), inside LibreSCRS_Trust: hidden, like
    /// @ref makeStore. No other library adds an anchor to a store.
    ///
    /// @par Thread-safety
    /// Takes an exclusive lock on the store's internal mutex.
    static void mergeTrustedListAnchors(TrustStore& store, std::vector<TrustAnchor> anchors);
};

} // namespace detail
} // namespace LibreSCRS::Trust
