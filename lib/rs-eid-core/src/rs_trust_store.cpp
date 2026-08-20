// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "rs_trust_store.h"

#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#include <filesystem>
#include <fstream>
#include <iterator>
#include <vector>

namespace LibreSCRS::RsEId::Core {

struct TrustStore::Impl
{
    X509_STORE* store = nullptr;
    int certCount = 0;

    Impl()
    {
        store = X509_STORE_new();
    }

    ~Impl()
    {
        if (store) {
            X509_STORE_free(store);
        }
    }

    void add(X509* cert)
    {
        X509_STORE_add_cert(store, cert);
        X509_free(cert); // add_cert took its own reference
        ++certCount;
    }
};

TrustStore::TrustStore() : impl(std::make_unique<Impl>()) {}

TrustStore::~TrustStore() = default;

void TrustStore::addCertificate(std::span<const std::uint8_t> derCert)
{
    if (!impl->store || derCert.empty()) {
        return;
    }
    const std::uint8_t* p = derCert.data();
    if (X509* cert = d2i_X509(nullptr, &p, static_cast<long>(derCert.size()))) {
        impl->add(cert);
    }
}

void TrustStore::loadFromFolder(const std::string& folderPath)
{
    if (!impl->store || folderPath.empty()) {
        return;
    }
    // Folder-loaded anchors skip the validity window, matching the reference
    // implementation. Anchors added byte-wise deliberately do not: that split is
    // long-standing behaviour on shipped cards and is not this refactor's to change.
    X509_STORE_set_flags(impl->store, X509_V_FLAG_NO_CHECK_TIME);

    std::error_code ec;
    if (!std::filesystem::exists(folderPath, ec) || ec) {
        return;
    }

    for (const auto& entry : std::filesystem::directory_iterator(folderPath, ec)) {
        if (ec) {
            break;
        }
        if (!entry.is_regular_file()) {
            continue;
        }
        const auto ext = entry.path().extension().string();
        if (ext != ".cer" && ext != ".crt" && ext != ".pem") {
            continue;
        }

        std::ifstream ifs(entry.path(), std::ios::binary);
        if (!ifs) {
            continue;
        }
        const std::vector<std::uint8_t> data((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
        if (data.empty()) {
            continue;
        }

        const std::uint8_t* p = data.data();
        X509* cert = d2i_X509(nullptr, &p, static_cast<long>(data.size()));
        if (!cert) {
            if (BIO* bio = BIO_new_mem_buf(data.data(), static_cast<int>(data.size()))) {
                cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
                BIO_free(bio);
            }
        }
        if (cert) {
            impl->add(cert);
        }
    }
}

int TrustStore::certificateCount() const noexcept
{
    return impl->certCount;
}

X509_STORE* TrustStore::native() const noexcept
{
    return impl->store;
}

} // namespace LibreSCRS::RsEId::Core
