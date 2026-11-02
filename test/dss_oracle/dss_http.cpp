// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "dss_oracle/dss_http.h"

#include <curl/curl.h>

#include <memory>
#include <mutex>

namespace libresign::dss_http {

namespace {

struct EasyDeleter
{
    void operator()(CURL* c) const
    {
        curl_easy_cleanup(c);
    }
};
using EasyPtr = std::unique_ptr<CURL, EasyDeleter>;

struct MimeDeleter
{
    void operator()(curl_mime* m) const
    {
        curl_mime_free(m);
    }
};
using MimePtr = std::unique_ptr<curl_mime, MimeDeleter>;

struct SlistDeleter
{
    void operator()(curl_slist* l) const
    {
        curl_slist_free_all(l);
    }
};
using SlistPtr = std::unique_ptr<curl_slist, SlistDeleter>;

size_t appendBody(char* ptr, size_t size, size_t nmemb, void* userdata)
{
    static_cast<std::string*>(userdata)->append(ptr, size * nmemb);
    return size * nmemb;
}

EasyPtr open(const std::string& socketPath, const std::string& url, int timeoutSeconds, std::string& body)
{
    static std::once_flag init;
    std::call_once(init, [] { curl_global_init(CURL_GLOBAL_DEFAULT); });

    EasyPtr c(curl_easy_init());
    if (!c)
        return c;
    curl_easy_setopt(c.get(), CURLOPT_UNIX_SOCKET_PATH, socketPath.c_str());
    curl_easy_setopt(c.get(), CURLOPT_URL, url.c_str());
    curl_easy_setopt(c.get(), CURLOPT_TIMEOUT, static_cast<long>(timeoutSeconds));
    curl_easy_setopt(c.get(), CURLOPT_CONNECTTIMEOUT, static_cast<long>(timeoutSeconds));
    curl_easy_setopt(c.get(), CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(c.get(), CURLOPT_WRITEFUNCTION, appendBody);
    curl_easy_setopt(c.get(), CURLOPT_WRITEDATA, &body);
    return c;
}

HttpResponse perform(CURL* c, std::string& body)
{
    HttpResponse resp;
    if (!c) {
        resp.errorMessage = "curl not initialized";
        return resp;
    }
    if (const CURLcode res = curl_easy_perform(c); res != CURLE_OK) {
        resp.errorMessage = curl_easy_strerror(res);
        return resp;
    }
    long statusCode = 0;
    curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &statusCode);
    resp.statusCode = static_cast<int>(statusCode);
    resp.body = std::move(body);
    return resp;
}

void addPart(curl_mime* mime, const char* name, std::span<const uint8_t> bytes, const char* fileName, const char* type)
{
    curl_mimepart* part = curl_mime_addpart(mime);
    curl_mime_name(part, name);
    curl_mime_data(part, reinterpret_cast<const char*>(bytes.data()), bytes.size());
    if (fileName)
        curl_mime_filename(part, fileName);
    curl_mime_type(part, type);
}

} // namespace

HttpResponse get(const std::string& socketPath, const std::string& url, int timeoutSeconds)
{
    std::string body;
    auto c = open(socketPath, url, timeoutSeconds, body);
    return perform(c.get(), body);
}

HttpResponse postJson(const std::string& socketPath, const std::string& url, const std::string& jsonBody,
                      int timeoutSeconds)
{
    std::string body;
    auto c = open(socketPath, url, timeoutSeconds, body);
    SlistPtr headers(curl_slist_append(nullptr, "Content-Type: application/json"));
    if (c) {
        curl_easy_setopt(c.get(), CURLOPT_POSTFIELDS, jsonBody.c_str());
        curl_easy_setopt(c.get(), CURLOPT_HTTPHEADER, headers.get());
    }
    return perform(c.get(), body);
}

HttpResponse postMultipart(const std::string& socketPath, const std::string& url, std::span<const uint8_t> document,
                           const std::string& fileName, const std::string& jsonMeta,
                           std::span<const uint8_t> originalDocument, int timeoutSeconds)
{
    std::string body;
    auto c = open(socketPath, url, timeoutSeconds, body);
    MimePtr mime(c ? curl_mime_init(c.get()) : nullptr);
    if (mime) {
        addPart(mime.get(), "document", document, fileName.c_str(), "application/octet-stream");
        const std::span meta(reinterpret_cast<const uint8_t*>(jsonMeta.data()), jsonMeta.size());
        addPart(mime.get(), "metadata", meta, nullptr, "application/json");
        if (!originalDocument.empty())
            addPart(mime.get(), "originalDocument", originalDocument, "original", "application/octet-stream");
        curl_easy_setopt(c.get(), CURLOPT_MIMEPOST, mime.get());
    }
    return perform(c.get(), body);
}

} // namespace libresign::dss_http
