// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "libresign/http_client.h"

#include <curl/curl.h>

#include <memory>
#include <mutex>

namespace libresign {

namespace {

// Thread-safe one-time initialization of libcurl globals.
// curl_easy_init() auto-calls curl_global_init() but that is not thread-safe.
std::once_flag curlInitFlag;
void ensureCurlInit()
{
    std::call_once(curlInitFlag, []() { curl_global_init(CURL_GLOBAL_DEFAULT); });
}

// Maximum bytes accepted for a single HTTP response body. Matches the
// Spring Boot service's multipart limit (256 MiB) and caps memory use
// if a malicious/compromised endpoint returns a huge body.
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

struct CurlMimeDeleter { void operator()(curl_mime* p) const { if (p) curl_mime_free(p); } };
using CurlMimePtr = std::unique_ptr<curl_mime, CurlMimeDeleter>;

} // namespace

struct HttpClient::Impl
{
    void* curl = nullptr;

    // Reset curl handle and apply common options shared by all methods.
    // Returns the typed CURL* handle, or nullptr if curl is not initialized.
    CURL* setupCommon(const std::string& url, int timeoutSeconds, const std::string& unixSocketPath,
                      WriteContext* writeCtx)
    {
        if (!curl)
            return nullptr;

        auto* c = static_cast<CURL*>(curl);
        curl_easy_reset(c);
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
        // CURLOPT_PROTOCOLS_STR was added in curl 7.85; older builds will
        // silently ignore the setopt — guard with the version macro.
#ifdef CURLOPT_PROTOCOLS_STR
        curl_easy_setopt(c, CURLOPT_PROTOCOLS_STR, "http,https");
        curl_easy_setopt(c, CURLOPT_REDIR_PROTOCOLS_STR, "http,https");
#else
        curl_easy_setopt(c, CURLOPT_PROTOCOLS, static_cast<long>(CURLPROTO_HTTP | CURLPROTO_HTTPS));
        curl_easy_setopt(c, CURLOPT_REDIR_PROTOCOLS, static_cast<long>(CURLPROTO_HTTP | CURLPROTO_HTTPS));
#endif

        if (!unixSocketPath.empty())
            curl_easy_setopt(c, CURLOPT_UNIX_SOCKET_PATH, unixSocketPath.c_str());

        return c;
    }
};

HttpClient::HttpClient() : impl(std::make_unique<Impl>())
{
    ensureCurlInit();
    impl->curl = curl_easy_init();
}

HttpClient::~HttpClient()
{
    if (impl && impl->curl)
        curl_easy_cleanup(static_cast<CURL*>(impl->curl));
}

HttpClient::HttpClient(HttpClient&&) noexcept = default;
HttpClient& HttpClient::operator=(HttpClient&&) noexcept = default;

HttpResponse HttpClient::get(const std::string& url, int timeoutSeconds, const std::string& unixSocketPath) const
{
    HttpResponse resp;
    WriteContext writeCtx;
    auto* c = impl->setupCommon(url, timeoutSeconds, unixSocketPath, &writeCtx);
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

HttpResponse HttpClient::post(const std::string& url, const std::string& jsonBody, int timeoutSeconds,
                              const std::string& unixSocketPath) const
{
    HttpResponse resp;
    WriteContext writeCtx;
    auto* c = impl->setupCommon(url, timeoutSeconds, unixSocketPath, &writeCtx);
    if (!c) {
        resp.errorMessage = "curl not initialized";
        return resp;
    }

    curl_easy_setopt(c, CURLOPT_POSTFIELDS, jsonBody.c_str());

    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");
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

HttpResponse HttpClient::postBinary(const std::string& url, const std::string& body, const std::string& contentType,
                                    int timeoutSeconds, const std::string& unixSocketPath) const
{
    HttpResponse resp;
    WriteContext writeCtx;
    auto* c = impl->setupCommon(url, timeoutSeconds, unixSocketPath, &writeCtx);
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

HttpResponse HttpClient::postMultipart(const std::string& url, std::span<const uint8_t> docData,
                                       const std::string& fileName, const std::string& jsonMeta, int timeoutSeconds,
                                       const std::string& unixSocketPath) const
{
    HttpResponse resp;
    WriteContext writeCtx;
    auto* c = impl->setupCommon(url, timeoutSeconds, unixSocketPath, &writeCtx);
    if (!c) {
        resp.errorMessage = "curl not initialized";
        return resp;
    }

    CurlMimePtr mime(curl_mime_init(c));

    // Binary document part
    curl_mimepart* part = curl_mime_addpart(mime.get());
    curl_mime_name(part, "document");
    curl_mime_data(part, reinterpret_cast<const char*>(docData.data()), docData.size());
    curl_mime_filename(part, fileName.c_str());
    curl_mime_type(part, "application/octet-stream");

    // JSON metadata part
    part = curl_mime_addpart(mime.get());
    curl_mime_name(part, "metadata");
    curl_mime_data(part, jsonMeta.c_str(), CURL_ZERO_TERMINATED);
    curl_mime_type(part, "application/json");

    curl_easy_setopt(c, CURLOPT_MIMEPOST, mime.get());

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

HttpResponse HttpClient::postMultipartValidation(const std::string& url, std::span<const uint8_t> signedDoc,
                                                 const std::string& fileName, const std::string& jsonMeta,
                                                 std::span<const uint8_t> originalDoc, int timeoutSeconds,
                                                 const std::string& unixSocketPath) const
{
    HttpResponse resp;
    WriteContext writeCtx;
    auto* c = impl->setupCommon(url, timeoutSeconds, unixSocketPath, &writeCtx);
    if (!c) {
        resp.errorMessage = "curl not initialized";
        return resp;
    }

    CurlMimePtr mime(curl_mime_init(c));

    // Signed document part
    curl_mimepart* part = curl_mime_addpart(mime.get());
    curl_mime_name(part, "document");
    curl_mime_data(part, reinterpret_cast<const char*>(signedDoc.data()), signedDoc.size());
    curl_mime_filename(part, fileName.c_str());
    curl_mime_type(part, "application/octet-stream");

    // JSON metadata part
    part = curl_mime_addpart(mime.get());
    curl_mime_name(part, "metadata");
    curl_mime_data(part, jsonMeta.c_str(), CURL_ZERO_TERMINATED);
    curl_mime_type(part, "application/json");

    // Optional original document part
    if (!originalDoc.empty()) {
        part = curl_mime_addpart(mime.get());
        curl_mime_name(part, "originalDocument");
        curl_mime_data(part, reinterpret_cast<const char*>(originalDoc.data()), originalDoc.size());
        curl_mime_filename(part, "original");
        curl_mime_type(part, "application/octet-stream");
    }

    curl_easy_setopt(c, CURLOPT_MIMEPOST, mime.get());

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

} // namespace libresign
