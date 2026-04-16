// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "libresign/trust_store_manager.h"

#include <filesystem>
#include <memory>
#include <mutex>

#include <openssl/x509.h>
#include <openssl/pem.h>

namespace fs = std::filesystem;

namespace libresign {

void X509StoreDeleter::operator()(X509_STORE* p) const
{
    X509_STORE_free(p);
}

TrustStoreManager::TrustStoreManager(const std::string& bundledCertDir) : bundledCertDir(bundledCertDir) {}

void TrustStoreManager::loadDirectoryIntoStore(X509_STORE* store, const std::string& dirPath) const
{
    if (!fs::exists(dirPath) || !fs::is_directory(dirPath))
        return;

    for (const auto& entry : fs::directory_iterator(dirPath)) {
        if (!entry.is_regular_file())
            continue;
        auto ext = entry.path().extension().string();
        if (ext != ".cer" && ext != ".crt" && ext != ".pem")
            continue;

        std::unique_ptr<FILE, decltype(&fclose)> fp(fopen(entry.path().c_str(), "rb"), &fclose);
        if (!fp)
            continue;

        // Try DER first, then PEM. Wrap in a unique_ptr so an allocator
        // throw (or any future code) between acquisition and the explicit
        // X509_free can't leak. X509_STORE_add_cert up-refs internally, so
        // the RAII wrapper still needs to drop our copy on scope exit.
        struct X509Free { void operator()(X509* p) const { X509_free(p); } };
        std::unique_ptr<X509, X509Free> cert(d2i_X509_fp(fp.get(), nullptr));
        if (!cert) {
            rewind(fp.get());
            cert.reset(PEM_read_X509(fp.get(), nullptr, nullptr, nullptr));
        }

        if (cert)
            X509_STORE_add_cert(store, cert.get());
    }
}

void TrustStoreManager::loadBundledCerts(X509_STORE* store) const
{
    if (!fs::exists(bundledCertDir) || !fs::is_directory(bundledCertDir))
        return;
    for (const auto& entry : fs::directory_iterator(bundledCertDir)) {
        if (entry.is_directory())
            loadDirectoryIntoStore(store, entry.path().string());
    }
    // Also load certs directly in bundled dir (flat files)
    loadDirectoryIntoStore(store, bundledCertDir);
}

X509StorePtr TrustStoreManager::buildStore(StoreScope scope) const
{
    std::shared_lock lock(mtx);

    switch (scope) {
    case StoreScope::EMRTD_PASSIVE_AUTH: {
        if (cscaPath.empty() || !fs::exists(cscaPath))
            return nullptr;
        X509StorePtr store(X509_STORE_new());
        if (!store)
            return nullptr;
        loadDirectoryIntoStore(store.get(), cscaPath);
        return store;
    }
    case StoreScope::CARD_VERIFICATION: {
        X509StorePtr store(X509_STORE_new());
        if (!store)
            return nullptr;
        loadBundledCerts(store.get());
        return store;
    }
    case StoreScope::CHAIN_DISPLAY: {
        X509StorePtr store(X509_STORE_new());
        if (!store)
            return nullptr;
        // System trust store
        X509_STORE_set_default_paths(store.get());
        loadBundledCerts(store.get());
        return store;
    }
    case StoreScope::SIGNING: {
        X509StorePtr store(X509_STORE_new());
        if (!store)
            return nullptr;
        // System trust store
        X509_STORE_set_default_paths(store.get());
        loadBundledCerts(store.get());
        // User paths
        for (const auto& userPath : userPaths)
            loadDirectoryIntoStore(store.get(), userPath);
        // CSCA path
        if (!cscaPath.empty())
            loadDirectoryIntoStore(store.get(), cscaPath);
        // Trust List derived certificates
        loadTlCerts(store.get());
        return store;
    }
    }
    return nullptr;
}

std::vector<std::string> TrustStoreManager::certPathsForScope(StoreScope scope) const
{
    std::shared_lock lock(mtx);

    std::vector<std::string> paths;

    auto addBundledSubdirs = [&]() {
        if (!fs::exists(bundledCertDir) || !fs::is_directory(bundledCertDir))
            return;
        for (const auto& entry : fs::directory_iterator(bundledCertDir)) {
            if (entry.is_directory())
                paths.push_back(entry.path().string());
        }
    };

    switch (scope) {
    case StoreScope::CARD_VERIFICATION:
        addBundledSubdirs();
        break;
    case StoreScope::CHAIN_DISPLAY:
        addBundledSubdirs();
        // System store paths are implicit (OpenSSL default)
        break;
    case StoreScope::EMRTD_PASSIVE_AUTH:
        if (!cscaPath.empty())
            paths.push_back(cscaPath);
        break;
    case StoreScope::SIGNING:
        addBundledSubdirs();
        for (const auto& p : userPaths)
            paths.push_back(p);
        if (!cscaPath.empty())
            paths.push_back(cscaPath);
        break;
    }

    return paths;
}

void TrustStoreManager::addUserStorePath(const std::string& path)
{
    std::unique_lock lock(mtx);
    userPaths.push_back(path);
}

void TrustStoreManager::setCscaStorePath(const std::string& path)
{
    std::unique_lock lock(mtx);
    cscaPath = path;
}

void TrustStoreManager::addTlCertificate(std::span<const uint8_t> certDer)
{
    if (certDer.empty())
        return;

    std::unique_lock lock(mtx);
    tlCerts.emplace_back(certDer.begin(), certDer.end());
}

void TrustStoreManager::loadTlCerts(X509_STORE* store) const
{
    struct X509Free { void operator()(X509* p) const { X509_free(p); } };
    for (const auto& der : tlCerts) {
        const unsigned char* p = der.data();
        std::unique_ptr<X509, X509Free> cert(d2i_X509(nullptr, &p, static_cast<long>(der.size())));
        if (cert)
            X509_STORE_add_cert(store, cert.get());
    }
}

} // namespace libresign
