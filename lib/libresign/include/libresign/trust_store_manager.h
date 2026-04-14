// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

#include <memory>
#include <string>
#include <vector>

// Forward declare to avoid OpenSSL headers in public API
typedef struct x509_store_st X509_STORE;

namespace libresign {

// RAII wrapper for X509_STORE — defined here (separately from openssl_raii.h)
// because this is a public header that must not include internal OpenSSL headers.
// The deleter body lives in the .cpp file so we don't need <openssl/x509.h> here.
// openssl_raii.h has an identical alias for internal use; they are ABI-compatible.
struct X509StoreDeleter
{
    void operator()(X509_STORE* p) const;
};
using X509StorePtr = std::unique_ptr<X509_STORE, X509StoreDeleter>;

enum class StoreScope {
    CARD_VERIFICATION,  // Tier 2 only — bundled certs (rs-eid card data verification)
    CHAIN_DISPLAY,      // Tier 1 + 2 — system + bundled (certificate viewer)
    EMRTD_PASSIVE_AUTH, // Tier 3 only — user CSCA store
    SIGNING,            // Tier 1 + 2 + 3 — all available trust anchors
};

// NOT thread-safe: do not mutate (addUserStorePath, setCscaStorePath) while
// reading (buildStore, certPathsForScope) from another thread.
class TrustStoreManager
{
public:
    explicit TrustStoreManager(const std::string& bundledCertDir);

    // Build an OpenSSL X509_STORE for the given scope.
    X509StorePtr buildStore(StoreScope scope) const;

    // All certificate directory paths for the given scope (for DSS trust store setup).
    std::vector<std::string> certPathsForScope(StoreScope scope) const;

    void addUserStorePath(const std::string& path);
    void setCscaStorePath(const std::string& path);

    const std::string& bundledDir() const
    {
        return bundledCertDir;
    }

private:
    void loadDirectoryIntoStore(X509_STORE* store, const std::string& dirPath) const;
    void loadBundledCerts(X509_STORE* store) const;

    std::string bundledCertDir;
    std::string cscaPath;
    std::vector<std::string> userPaths;
};

} // namespace libresign
