// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "native/fetch_and_verify_tl.h"

#include "native/native_utils.h"
#include "native/pinned_tl_certs.h"
#include "native/tl_cache.h"
#include "native/tl_signature_verifier.h"

#include <openssl/pem.h>
#include <openssl/x509.h>

#include <cstdio>
#include <ctime>
#include <exception>
#include <expected>
#include <fstream>
#include <iterator>
#include <optional>
#include <string_view>
#include <LibreSCRS_internal/Crypto/OpenSslPtr.h>

using LibreSCRS::Internal::Crypto::BioPtr;
using LibreSCRS::Internal::Crypto::X509Ptr;

namespace libresign {

namespace {

// Load a certificate from a file (DER or PEM). Returns DER bytes.
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

// An ETSI TS 119 612 dateTime ("2026-11-19T01:00:00Z") as UTC seconds;
// nothing for anything else.
std::optional<std::time_t> parseTlDateTime(const std::string& text)
{
    std::tm tm{};
    char zone = 0;
    if (std::sscanf(text.c_str(), "%4d-%2d-%2dT%2d:%2d:%2d%c", &tm.tm_year, &tm.tm_mon, &tm.tm_mday, &tm.tm_hour,
                    &tm.tm_min, &tm.tm_sec, &zone) != 7 ||
        zone != 'Z')
        return std::nullopt;
    tm.tm_year -= 1900;
    tm.tm_mon -= 1;
    return timegm(&tm);
}

} // namespace

namespace {

// The list's bytes: from the local file, else from the cache while its copy
// is within its lifetime, else from the server (conditionally, when the
// cache still knows the copy's validators).
struct ListBytes
{
    std::vector<std::uint8_t> data;
    bool fromCache = false;
};

std::expected<ListBytes, std::string> obtainListBytes(const TrustedListEntry& entry, const FetchOptions& opts)
{
    constexpr std::string_view kFileScheme = "file://";
    const bool localFileBranch = entry.localFileOnly && entry.url.compare(0, kFileScheme.size(), kFileScheme) == 0;

    if (localFileBranch) {
        const std::string path(entry.url.substr(kFileScheme.size()));
        std::ifstream is(path, std::ios::binary);
        if (!is)
            return std::unexpected("failed to read local TL file: " + path);
        std::vector<std::uint8_t> buffer((std::istreambuf_iterator<char>(is)), std::istreambuf_iterator<char>());
        if (buffer.empty())
            return std::unexpected("local TL file is empty: " + path);
        return ListBytes{std::move(buffer), false};
    }

    TlCache cache(opts.cacheDirectory);
    if (auto cached = cache.load(entry.url))
        return ListBytes{std::move(cached->data), true};

    auto staleMeta = cache.loadMeta(entry.url);
    auto fetchResult = TrustedListParser::fetchRawConditional(entry.url, staleMeta ? staleMeta->etag : std::string{},
                                                              staleMeta ? staleMeta->lastModified : std::string{},
                                                              static_cast<int>(opts.requestTimeout.count()));

    if (fetchResult.notModified) {
        cache.refreshTimestamp(entry.url);
        auto refreshed = cache.load(entry.url);
        if (!refreshed)
            return std::unexpected("cache refresh failed for TL: " + entry.url);
        return ListBytes{std::move(refreshed->data), false};
    }
    if (fetchResult.data.empty())
        return std::unexpected("failed to fetch TL from " + entry.url);

    // Cache write is best-effort; failures are tolerated and won't block
    // this fetch result.
    cache.store(entry.url, fetchResult.data, fetchResult.etag, fetchResult.lastModified);
    return ListBytes{std::move(fetchResult.data), false};
}

// The verification certificates: the caller's override, else the pinned
// one, else those the pointing LOTL names.
std::vector<std::vector<std::uint8_t>> verificationCandidates(const TrustedListEntry& entry)
{
    std::vector<std::vector<std::uint8_t>> candidates;
    if (!entry.signingCertPath.empty()) {
        auto owned = loadCertFromFile(entry.signingCertPath);
        if (!owned.empty())
            candidates.push_back(std::move(owned));
    }
    if (candidates.empty()) {
        auto pinnedCert = pinned_certs::pinnedCertForUrl(entry.url);
        if (!pinnedCert.empty())
            candidates.emplace_back(pinnedCert.begin(), pinnedCert.end());
    }
    if (candidates.empty()) {
        for (const auto& der : entry.signingCertsDer) {
            if (!der.empty())
                candidates.push_back(der);
        }
    }
    return candidates;
}

// Verify, parse, and refuse a stale list. @p stale is set when the list
// verified but is past its NextUpdate.
FetchResult verifyAndParse(const TrustedListEntry& entry, const std::vector<std::uint8_t>& xmlData,
                           const std::vector<std::vector<std::uint8_t>>& candidates, const FetchOptions& opts,
                           bool& stale)
{
    stale = false;
    TlSignatureVerifier verifier;
    bool verified = false;
    for (const auto& cert : candidates) {
        if (verifier.verify(xmlData, cert)) {
            verified = true;
            break;
        }
    }
    if (!verified)
        return FetchResult::failure("TL signature verification failed for " + entry.url + ": " + verifier.lastError());

    if (opts.stop.isCancelled())
        return FetchResult::failure("cancelled after verify");

    auto info = TrustedListParser::parse(xmlData);

    // A list past its NextUpdate is stale: its operator promised a new one
    // by then, and an anchor it no longer names may still be in it. A day of
    // tolerance absorbs publication lag and clock skew.
    if (const auto nextUpdate = parseTlDateTime(info.nextUpdate)) {
        constexpr std::time_t kTolerance = 24 * 60 * 60;
        if (std::time(nullptr) > *nextUpdate + kTolerance) {
            stale = true;
            return FetchResult::failure("TL is past its NextUpdate (" + info.nextUpdate + "): " + entry.url);
        }
    }
    return FetchResult::success(std::move(info));
}

} // namespace

FetchResult fetchAndVerifyTrustedList(const TrustedListEntry& entry, FetchOptions opts)
{
    if (opts.stop.isCancelled())
        return FetchResult::failure("cancelled before fetch");

    auto bytes = obtainListBytes(entry, opts);
    if (!bytes)
        return FetchResult::failure(std::move(bytes.error()));

    if (opts.stop.isCancelled())
        return FetchResult::failure("cancelled after fetch");

    const auto candidates = verificationCandidates(entry);
    if (candidates.empty())
        return FetchResult::failure("no verification cert available for TL: " + entry.url);

    bool stale = false;
    auto result = verifyAndParse(entry, bytes->data, candidates, opts, stale);
    if (result || !stale || !bytes->fromCache)
        return result;

    // The cached copy went stale within the cache's lifetime: the operator
    // has published its successor by now. Ask once more; a list still stale
    // after that is refused.
    TlCache(opts.cacheDirectory).expire(entry.url);
    if (opts.stop.isCancelled())
        return FetchResult::failure("cancelled before refetch");
    bytes = obtainListBytes(entry, opts);
    if (!bytes)
        return FetchResult::failure(std::move(bytes.error()));
    return verifyAndParse(entry, bytes->data, candidates, opts, stale);
}

FetchResult fetchTrustedListTree(const TrustedListEntry& root, const FetchOptions& opts,
                                 const std::function<void(const std::string&, const TrustedListInfo&)>& onList,
                                 const std::function<void(const std::string&, const std::string&)>& onFailure)
{
    auto rootResult = fetchAndVerifyTrustedList(root, opts);
    if (!rootResult)
        return rootResult;
    onList(root.url, rootResult.info);
    if (!root.isLotl)
        return rootResult;

    // A LOTL points at lists, never at further LOTLs: one level is followed.
    std::size_t followed = 0;
    for (const auto& pointer : rootResult.info.pointersToOtherTSL) {
        if (followed >= kMaxTslPointers)
            break;
        if (opts.stop.isCancelled())
            break;
        if (!TrustedListParser::isSafeTslUrl(pointer.url)) {
            onFailure(pointer.url, "refused: not a safe Trusted List URL");
            continue;
        }
        ++followed;
        TrustedListEntry child;
        child.url = pointer.url;
        child.signingCertsDer = pointer.signingCertsDer;
        try {
            auto childResult = fetchAndVerifyTrustedList(child, opts);
            if (childResult)
                onList(child.url, childResult.info);
            else
                onFailure(child.url, childResult.error);
        } catch (const std::exception& e) {
            onFailure(child.url, e.what());
        }
    }
    return rootResult;
}

} // namespace libresign
