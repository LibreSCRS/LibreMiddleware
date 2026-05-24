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
    static void addProvider(TrustStore& store, std::shared_ptr<TrustAnchorProvider> provider);

    /// @brief Merge a set of pre-extracted DER-encoded trust anchors into
    ///        @p store as a single provider tagged with @p sourceLabel.
    ///        DER-byte-equality dedupe is performed against existing
    ///        providers' anchors so re-merging the same anchor list is
    ///        idempotent. The anchor span is consumed; @p store retains
    ///        its own copy of the bytes.
    ///
    /// Used by both:
    ///   - @ref TrustStoreService eager-fetch worker threads
    ///     (intra-LibreSCRS_Trust), and
    ///   - the LibreSCRS::Signing bridge's anchor-emit lambda
    ///     (LibreSCRS_Signing → LibreSCRS_Trust, cross-`.so` under SHARED).
    ///
    /// The cross-`.so` call site is the only reason this symbol is
    /// exported via @ref LIBRESCRS_PUBLIC_API; the surrounding
    /// `internal/` header path + LIBRESCRS_INTERNAL_BUILD #error guard
    /// keep external consumers from including it. Sibling
    /// `makeStore`/`addProvider` are NOT marked because their callers all
    /// live inside LibreSCRS_Trust itself; exporting them would widen
    /// the visible symbol set without a use case.
    ///
    /// @par Thread-safety
    /// Takes an exclusive lock on the store's internal mutex.
    LIBRESCRS_PUBLIC_API static void mergeTrustedListAnchors(TrustStore& store, std::vector<TrustAnchor> anchors,
                                                             const std::string& sourceLabel);
};

} // namespace detail
} // namespace LibreSCRS::Trust
