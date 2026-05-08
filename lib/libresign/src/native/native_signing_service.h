// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

#include "signing_service.h"

#include <map>
#include <memory>

// Forward-declare the public Trust types for the optional setter.
namespace LibreSCRS::Trust {
class TrustStore;
}

namespace libresign {

class TlCache;
class TlSignatureVerifier;

class NativeSigningService : public SigningService
{
public:
    bool configure(const TrustConfig& config) override;

    SigningResult sign(const SigningRequest& request, const std::string& pkcs11ModulePath, std::span<const uint8_t> pin,
                       const std::string& keyAlias, const std::string& readerName) override;

    bool isAvailable() const override;

    /// True if configure() was called (even if some TLs failed — degraded mode).
    bool isConfigured() const
    {
        return configured;
    }

    /// True if all eager TLs loaded successfully (no degraded mode).
    bool isFullyConfigured() const
    {
        return configured && fullyConfigured;
    }

    /// Set the public TrustStore that receives TL-derived certificates as a
    /// TrustedListProvider. this is the lazy-fetch path;
    /// eager fetches are owned by Trust::TrustStoreService. The store
    /// pointer typically aliases the same shared_ptr the TrustStoreService
    /// hands out via trustStore().
    void setPublicTrustStore(std::shared_ptr<LibreSCRS::Trust::TrustStore> store)
    {
        publicTrustStore = std::move(store);
    }

private:
    TrustConfig trustConfig;
    std::map<std::string, std::vector<uint8_t>> lotlDerivedCerts; // URL -> signing cert DER
    bool configured = false;
    bool fullyConfigured = false;
    std::shared_ptr<LibreSCRS::Trust::TrustStore> publicTrustStore;

    void loadTrustList(const std::string& url, bool isLotl, TlCache& cache, TlSignatureVerifier& verifier, int depth);
};

} // namespace libresign
