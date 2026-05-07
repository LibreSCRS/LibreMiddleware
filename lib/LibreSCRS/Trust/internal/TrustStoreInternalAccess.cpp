// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "TrustStoreInternalAccess.h"
#include "BundledCertsProvider.h"

#include <algorithm>
#include <mutex>
#include <utility>

namespace LibreSCRS::Trust::detail {

namespace {

/// @brief Trivial concrete provider for an already-materialised anchor list.
/// Used by @ref mergeTrustedListAnchors to wrap the DER bytes received from
/// libresign without exposing libresign types in this translation unit.
class StaticAnchorProvider final : public TrustAnchorProvider
{
public:
    explicit StaticAnchorProvider(std::vector<TrustAnchor> anchors) : cached(std::move(anchors)) {}

    [[nodiscard]] std::vector<TrustAnchor> anchors() const override
    {
        return cached;
    }

private:
    std::vector<TrustAnchor> cached;
};

} // namespace

TrustStore TrustStoreInternalAccess::makeStore(std::string bundledCertDir, bool includeSystemTrustStore)
{
    auto impl = std::make_unique<TrustStore::Impl>();
    impl->includeSystemStore = includeSystemTrustStore;
    if (!bundledCertDir.empty()) {
        impl->providers.push_back(std::make_shared<BundledCertsProvider>(std::move(bundledCertDir)));
    }
    return TrustStore(std::move(impl));
}

void TrustStoreInternalAccess::addProvider(TrustStore& store, std::shared_ptr<TrustAnchorProvider> provider)
{
    if (!store.d || !provider)
        return;
    std::unique_lock lock(store.d->mtx);
    store.d->providers.push_back(std::move(provider));
}

void TrustStoreInternalAccess::mergeTrustedListAnchors(TrustStore& store, std::vector<TrustAnchor> anchors,
                                                       const std::string& sourceLabel)
{
    if (!store.d || anchors.empty())
        return;

    std::unique_lock lock(store.d->mtx);

    // Collect existing DER bytes once so dedupe is O(N*M) at worst — fine
    // for the small N (typically <100 anchors per TL) we deal with.
    std::vector<std::vector<std::uint8_t>> existing;
    for (const auto& provider : store.d->providers) {
        for (auto& a : provider->anchors()) {
            existing.push_back(std::move(a.certificateDer));
        }
    }

    auto isDuplicate = [&existing](const std::vector<std::uint8_t>& der) {
        return std::any_of(existing.begin(), existing.end(),
                           [&der](const std::vector<std::uint8_t>& e) { return e == der; });
    };

    std::vector<TrustAnchor> deduped;
    deduped.reserve(anchors.size());
    for (auto& a : anchors) {
        if (a.certificateDer.empty())
            continue;
        if (isDuplicate(a.certificateDer))
            continue;
        if (a.sourceLabel.empty())
            a.sourceLabel = sourceLabel;
        deduped.push_back(std::move(a));
    }

    if (deduped.empty())
        return;

    store.d->providers.push_back(std::make_shared<StaticAnchorProvider>(std::move(deduped)));
}

} // namespace LibreSCRS::Trust::detail
