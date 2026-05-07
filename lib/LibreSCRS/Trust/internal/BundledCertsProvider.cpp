// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "BundledCertsProvider.h"

#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <filesystem>
#include <fstream>
#include <iterator>

namespace LibreSCRS::Trust::detail {

namespace fs = std::filesystem;

namespace {

bool hasCertExtension(const fs::path& p)
{
    auto ext = p.extension().string();
    return ext == ".cer" || ext == ".crt" || ext == ".pem";
}

std::vector<std::uint8_t> readFile(const fs::path& p)
{
    std::ifstream f(p, std::ios::binary);
    if (!f)
        return {};
    return {std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>()};
}

// Convert PEM-encoded bytes to DER. Returns empty vector if parse fails.
std::vector<std::uint8_t> pemToDer(const std::vector<std::uint8_t>& bytes)
{
    BIO* bio = BIO_new_mem_buf(bytes.data(), static_cast<int>(bytes.size()));
    if (!bio)
        return {};
    X509* cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!cert)
        return {};
    int len = i2d_X509(cert, nullptr);
    if (len <= 0) {
        X509_free(cert);
        return {};
    }
    std::vector<std::uint8_t> der(static_cast<std::size_t>(len));
    std::uint8_t* p = der.data();
    i2d_X509(cert, &p);
    X509_free(cert);
    return der;
}

bool isValidDer(const std::vector<std::uint8_t>& bytes)
{
    const std::uint8_t* p = bytes.data();
    X509* cert = d2i_X509(nullptr, &p, static_cast<long>(bytes.size()));
    if (cert) {
        X509_free(cert);
        return true;
    }
    return false;
}

void loadDirectoryInto(std::vector<TrustAnchor>& out, const fs::path& dir, const std::string& bundleRoot)
{
    std::error_code ec;
    if (!fs::exists(dir, ec) || !fs::is_directory(dir, ec))
        return;
    for (const auto& entry : fs::directory_iterator(dir, ec)) {
        if (!entry.is_regular_file() || !hasCertExtension(entry.path()))
            continue;
        auto raw = readFile(entry.path());
        if (raw.empty())
            continue;
        std::vector<std::uint8_t> der = isValidDer(raw) ? raw : pemToDer(raw);
        if (der.empty())
            continue;

        TrustAnchor a;
        a.certificateDer = std::move(der);
        a.sourceLabel = "bundled:" + fs::relative(entry.path(), bundleRoot, ec).string();
        out.push_back(std::move(a));
    }
}

} // namespace

BundledCertsProvider::BundledCertsProvider(std::string dir) : bundledCertDir(std::move(dir))
{
    std::error_code ec;
    fs::path root(bundledCertDir);
    if (!fs::exists(root, ec) || !fs::is_directory(root, ec)) {
        return; // empty cache; anchors() will return empty vector
    }

    // Recurse one level into subdirectories (rs-mup, rs-mup-format, rs-pks, ...)
    for (const auto& sub : fs::directory_iterator(root, ec)) {
        if (sub.is_directory()) {
            loadDirectoryInto(cached, sub.path(), bundledCertDir);
        }
    }
    // Also load flat .cer/.crt/.pem files directly in the root.
    loadDirectoryInto(cached, root, bundledCertDir);
}

std::vector<TrustAnchor> BundledCertsProvider::anchors() const
{
    return cached; // copy — caller owns; cache itself is immutable post-ctor
}

} // namespace LibreSCRS::Trust::detail
