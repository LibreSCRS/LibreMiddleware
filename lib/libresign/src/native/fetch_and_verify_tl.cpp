// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "native/fetch_and_verify_tl.h"

#include "native/native_utils.h"
#include "native/pinned_tl_certs.h"
#include "native/tl_cache.h"
#include "native/tl_signature_verifier.h"

#include <openssl/pem.h>
#include <openssl/x509.h>

#include <fstream>
#include <iterator>
#include <string_view>

namespace libresign {

namespace {

// Load a certificate from a file (DER or PEM). Returns DER bytes.
// Mirror of the same helper in native_signing_service.cpp; lives here too so
// the extracted helper is self-contained.
std::vector<std::uint8_t> loadCertFromFile(const std::string& path)
{
    std::ifstream file(path, std::ios::binary);
    if (!file)
        return {};

    std::vector<std::uint8_t> data((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    if (data.empty())
        return {};

    {
        const unsigned char* p = data.data();
        X509Ptr cert(d2i_X509(nullptr, &p, static_cast<long>(data.size())));
        if (cert)
            return data; // already DER
    }

    BioPtr bio(BIO_new_mem_buf(data.data(), static_cast<int>(data.size())));
    if (!bio)
        return {};

    X509Ptr cert(PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr));
    if (!cert)
        return {};

    return native_utils::derEncode(static_cast<int (*)(const X509*, unsigned char**)>(i2d_X509), cert.get());
}

} // namespace

FetchResult fetchAndVerifyTrustedList(const TrustedListEntry& entry, FetchOptions opts)
{
    constexpr std::string_view kFileScheme = "file://";

    if (opts.stop.isCancelled())
        return FetchResult::failure("cancelled before fetch");

    // 1. Fetch raw XML bytes.
    std::vector<std::uint8_t> xmlData;
    bool freshlyFetched = false;
    std::string responseEtag;
    std::string responseLastModified;

    const bool localFileBranch = entry.localFileOnly && entry.url.compare(0, kFileScheme.size(), kFileScheme) == 0;

    if (localFileBranch) {
        const std::string path(entry.url.substr(kFileScheme.size()));
        std::ifstream is(path, std::ios::binary);
        if (!is)
            return FetchResult::failure("failed to read local TL file: " + path);
        std::vector<std::uint8_t> buffer((std::istreambuf_iterator<char>(is)), std::istreambuf_iterator<char>());
        if (buffer.empty())
            return FetchResult::failure("local TL file is empty: " + path);
        xmlData = std::move(buffer);
    } else {
        TlCache cache(opts.cacheDirectory);
        auto cached = cache.load(entry.url);
        if (cached) {
            xmlData = std::move(cached->data);
        } else {
            auto staleMeta = cache.loadMeta(entry.url);
            auto fetchResult = TrustedListParser::fetchRawConditional(
                entry.url, staleMeta ? staleMeta->etag : std::string{},
                staleMeta ? staleMeta->lastModified : std::string{}, static_cast<int>(opts.requestTimeout.count()));

            if (fetchResult.notModified) {
                cache.refreshTimestamp(entry.url);
                auto refreshed = cache.load(entry.url);
                if (refreshed) {
                    xmlData = std::move(refreshed->data);
                } else {
                    return FetchResult::failure("cache refresh failed for TL: " + entry.url);
                }
            } else if (!fetchResult.data.empty()) {
                xmlData = std::move(fetchResult.data);
                responseEtag = std::move(fetchResult.etag);
                responseLastModified = std::move(fetchResult.lastModified);
                freshlyFetched = true;
            } else {
                return FetchResult::failure("failed to fetch TL from " + entry.url);
            }
        }

        if (freshlyFetched) {
            // Cache write is best-effort; failures are tolerated and won't
            // block this fetch result.
            cache.store(entry.url, xmlData, responseEtag, responseLastModified);
        }
    }

    if (opts.stop.isCancelled())
        return FetchResult::failure("cancelled after fetch");

    // 2. Resolve verification certificate.
    std::vector<std::uint8_t> verificationCertOwned;
    std::span<const std::uint8_t> signingCert;

    if (!entry.signingCertPath.empty()) {
        verificationCertOwned = loadCertFromFile(entry.signingCertPath);
        if (!verificationCertOwned.empty())
            signingCert = verificationCertOwned;
    }

    if (signingCert.empty()) {
        auto pinnedCert = pinned_certs::pinnedCertForUrl(entry.url);
        if (!pinnedCert.empty()) {
            signingCert = pinnedCert;
        } else {
            return FetchResult::failure("no verification cert available for TL: " + entry.url);
        }
    }

    // 3. Verify XML-DSig.
    TlSignatureVerifier verifier;
    if (!verifier.verify(xmlData, signingCert))
        return FetchResult::failure("TL signature verification failed for " + entry.url + ": " + verifier.lastError());

    if (opts.stop.isCancelled())
        return FetchResult::failure("cancelled after verify");

    // 4. Parse authenticated TL.
    auto info = TrustedListParser::parse(xmlData);
    return FetchResult::success(std::move(info));
}

} // namespace libresign
