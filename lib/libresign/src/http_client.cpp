// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "http_client.h"

#include <LibreSCRS/Export.h>
#include <LibreSCRS_internal/Crypto/SystemCaStore.h>

#include <curl/curl.h>

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <limits>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace libresign {

namespace {

// Thread-safe one-time initialization of libcurl globals.
// curl_easy_init() auto-calls curl_global_init() but that is not thread-safe.
std::once_flag curlInitFlag;
void ensureCurlInit()
{
    std::call_once(curlInitFlag, []() { curl_global_init(CURL_GLOBAL_DEFAULT); });
}

// Maximum bytes accepted for a single HTTP response body: caps memory use if
// a malicious or compromised endpoint returns a huge body.
constexpr size_t kDefaultMaxResponseBytes = 256 * 1024 * 1024;

struct WriteContext
{
    std::string body;
    size_t maxBytes = kDefaultMaxResponseBytes;
    bool exceeded = false;
};

size_t writeCallback(char* ptr, size_t size, size_t nmemb, void* userdata)
{
    auto* ctx = static_cast<WriteContext*>(userdata);
    size_t incoming = size * nmemb;
    if (ctx->body.size() + incoming > ctx->maxBytes) {
        ctx->exceeded = true;
        return 0; // abort transfer
    }
    ctx->body.append(ptr, incoming);
    return incoming;
}

// Capture response headers into a map (lowercase keys for easy lookup).
size_t headerCallback(char* buffer, size_t size, size_t nitems, void* userdata)
{
    size_t totalSize = size * nitems;
    auto* headers = static_cast<std::map<std::string, std::string>*>(userdata);

    std::string line(buffer, totalSize);
    // Trim trailing \r\n
    while (!line.empty() && (line.back() == '\r' || line.back() == '\n'))
        line.pop_back();

    auto colon = line.find(':');
    if (colon != std::string::npos) {
        std::string key = line.substr(0, colon);
        std::transform(key.begin(), key.end(), key.begin(), [](unsigned char c) { return std::tolower(c); });
        std::string value = line.substr(colon + 1);
        // Trim leading whitespace from value
        size_t start = value.find_first_not_of(" \t");
        if (start != std::string::npos)
            value = value.substr(start);
        else
            value.clear();
        (*headers)[std::move(key)] = std::move(value);
    }
    return totalSize;
}

} // namespace

struct LIBRESCRS_INTERNAL HttpClient::Impl
{
    void* curl = nullptr;

    // Reset curl handle and apply common options shared by all methods.
    // Returns the typed CURL* handle, or nullptr if curl is not initialized.
    CURL* setupCommon(const std::string& url, int timeoutSeconds, WriteContext* writeCtx)
    {
        if (!curl)
            return nullptr;

        auto* c = static_cast<CURL*>(curl);
        curl_easy_reset(c);

        // TLS chain validation is pinned PER REQUEST: curl_easy_reset() above
        // clears every option, so a constructor-time setopt would not survive.
        // Pinning here means an attacker who flips a libcurl global default
        // cannot weaken validation for any request this client issues.
        curl_easy_setopt(c, CURLOPT_SSL_VERIFYPEER, 1L);
        curl_easy_setopt(c, CURLOPT_SSL_VERIFYHOST, 2L);
        // CA trust store for the statically-vendored libcurl: the one chain
        // validation and time-stamp verification use too, found on the host
        // the process runs on. curl's own default is the build host's path,
        // which another distribution, an AppImage or macOS does not share.
        // Nothing found leaves curl's default. Verification stays ON.
        if (const auto ca = LibreSCRS::Internal::Crypto::findSystemCaStore();
            !ca.file.empty() || !ca.directory.empty()) {
            if (!ca.file.empty())
                curl_easy_setopt(c, CURLOPT_CAINFO, ca.file.c_str());
            if (!ca.directory.empty())
                curl_easy_setopt(c, CURLOPT_CAPATH, ca.directory.c_str());
        }

        curl_easy_setopt(c, CURLOPT_URL, url.c_str());
        curl_easy_setopt(c, CURLOPT_TIMEOUT, static_cast<long>(timeoutSeconds));
        curl_easy_setopt(c, CURLOPT_NOSIGNAL, 1L);
        curl_easy_setopt(c, CURLOPT_CONNECTTIMEOUT, static_cast<long>(timeoutSeconds));
        curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, writeCallback);
        curl_easy_setopt(c, CURLOPT_WRITEDATA, writeCtx);

        // Restrict to http(s) — OCSP, CRL and TSA URLs are extracted from
        // certificate AIA/CDP extensions, which are attacker-influenceable
        // through a malicious cert. Without this, a bad actor could point
        // at file://, gopher://, dict:// or another smuggled scheme.
        // CURLOPT_PROTOCOLS_STR was added in curl 7.85.0 (= 0x075500), and
        // the older long-bitmask CURLOPT_PROTOCOLS / CURLOPT_REDIR_PROTOCOLS
        // are deprecated since the same release. Note that
        // CURLOPT_PROTOCOLS_STR is an enum value, not a #define, so an
        // `#ifdef` guard would always evaluate false even on modern libcurl
        // — the version-number compare is the only correct shape.
#if LIBCURL_VERSION_NUM >= 0x075500
        curl_easy_setopt(c, CURLOPT_PROTOCOLS_STR, "http,https");
        curl_easy_setopt(c, CURLOPT_REDIR_PROTOCOLS_STR, "http,https");
#else
        curl_easy_setopt(c, CURLOPT_PROTOCOLS, static_cast<long>(CURLPROTO_HTTP | CURLPROTO_HTTPS));
        curl_easy_setopt(c, CURLOPT_REDIR_PROTOCOLS, static_cast<long>(CURLPROTO_HTTP | CURLPROTO_HTTPS));
#endif

        return c;
    }
};

HttpClient::HttpClient() : impl(std::make_unique<Impl>())
{
    ensureCurlInit();
    impl->curl = curl_easy_init();
    // NB: TLS chain validation (CURLOPT_SSL_VERIFYPEER/VERIFYHOST) and the CA
    // trust store (CURLOPT_CAINFO/CAPATH, see findSystemCaStore) are
    // pinned PER REQUEST in Impl::configureHandle, because every request begins
    // with curl_easy_reset() which clears any handle-level options set here.
}

HttpClient::~HttpClient()
{
    if (impl && impl->curl)
        curl_easy_cleanup(static_cast<CURL*>(impl->curl));
}

HttpClient::HttpClient(HttpClient&&) noexcept = default;
HttpClient& HttpClient::operator=(HttpClient&&) noexcept = default;

HttpResponse HttpClient::get(const std::string& url, int timeoutSeconds) const
{
    HttpResponse resp;
    WriteContext writeCtx;
    auto* c = impl->setupCommon(url, timeoutSeconds, &writeCtx);
    if (!c) {
        resp.errorMessage = "curl not initialized";
        return resp;
    }

    CURLcode res = curl_easy_perform(c);
    if (writeCtx.exceeded) {
        resp.statusCode = 0;
        resp.errorMessage = "response body exceeded maxBytes";
        return resp;
    }
    if (res != CURLE_OK) {
        resp.errorMessage = curl_easy_strerror(res);
        return resp;
    }

    long statusCode = 0;
    curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &statusCode);
    resp.statusCode = static_cast<int>(statusCode);
    resp.body = std::move(writeCtx.body);
    return resp;
}

HttpResponse HttpClient::getWithHeaders(const std::string& url, const std::vector<std::string>& requestHeaders,
                                        int timeoutSeconds) const
{
    HttpResponse resp;
    WriteContext writeCtx;
    auto* c = impl->setupCommon(url, timeoutSeconds, &writeCtx);
    if (!c) {
        resp.errorMessage = "curl not initialized";
        return resp;
    }

    // Set custom request headers
    struct curl_slist* headers = nullptr;
    for (const auto& h : requestHeaders)
        headers = curl_slist_append(headers, h.c_str());
    if (headers)
        curl_easy_setopt(c, CURLOPT_HTTPHEADER, headers);

    // Capture response headers
    curl_easy_setopt(c, CURLOPT_HEADERFUNCTION, headerCallback);
    curl_easy_setopt(c, CURLOPT_HEADERDATA, &resp.headers);

    CURLcode res = curl_easy_perform(c);
    curl_slist_free_all(headers);

    if (writeCtx.exceeded) {
        resp.statusCode = 0;
        resp.errorMessage = "response body exceeded maxBytes";
        return resp;
    }
    if (res != CURLE_OK) {
        resp.errorMessage = curl_easy_strerror(res);
        return resp;
    }

    long statusCode = 0;
    curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &statusCode);
    resp.statusCode = static_cast<int>(statusCode);
    resp.body = std::move(writeCtx.body);
    return resp;
}

HttpResponse HttpClient::postBinary(const std::string& url, const std::string& body, const std::string& contentType,
                                    int timeoutSeconds) const
{
    HttpResponse resp;

    // Body-size guard. CURLOPT_POSTFIELDSIZE takes `long`; on LLP64
    // (Windows) `long` is 32-bit, so static_cast<long>(size_t) would
    // truncate for >2 GiB bodies and libcurl would send the wrong
    // Content-Length. On LP64 platforms (Linux, macOS) the condition is
    // effectively unreachable but the check is cheap and platform-portable.
    if (body.size() > static_cast<std::size_t>(std::numeric_limits<long>::max())) {
        resp.errorMessage = "Body size exceeds long max — cannot fit CURLOPT_POSTFIELDSIZE";
        return resp;
    }

    WriteContext writeCtx;
    auto* c = impl->setupCommon(url, timeoutSeconds, &writeCtx);
    if (!c) {
        resp.errorMessage = "curl not initialized";
        return resp;
    }

    curl_easy_setopt(c, CURLOPT_POSTFIELDS, body.data());
    curl_easy_setopt(c, CURLOPT_POSTFIELDSIZE, static_cast<long>(body.size()));

    std::string header = "Content-Type: " + contentType;
    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, header.c_str());
    curl_easy_setopt(c, CURLOPT_HTTPHEADER, headers);

    CURLcode res = curl_easy_perform(c);
    curl_slist_free_all(headers);

    if (writeCtx.exceeded) {
        resp.statusCode = 0;
        resp.errorMessage = "response body exceeded maxBytes";
        return resp;
    }
    if (res != CURLE_OK) {
        resp.errorMessage = curl_easy_strerror(res);
        return resp;
    }

    long statusCode = 0;
    curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &statusCode);
    resp.statusCode = static_cast<int>(statusCode);
    resp.body = std::move(writeCtx.body);
    return resp;
}

} // namespace libresign
