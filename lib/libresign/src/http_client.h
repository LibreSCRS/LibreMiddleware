// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

#include <map>
#include <memory>
#include <string>
#include <vector>

namespace libresign {

struct HttpResponse
{
    int statusCode = 0;
    std::string body;
    std::string errorMessage;
    std::map<std::string, std::string> headers; // lowercase header name -> value
};

// NOT thread-safe: one curl handle per instance, so each thread uses its own.
class HttpClient
{
public:
    HttpClient();
    ~HttpClient();

    HttpClient(HttpClient&&) noexcept;
    HttpClient& operator=(HttpClient&&) noexcept;

    HttpClient(const HttpClient&) = delete;
    HttpClient& operator=(const HttpClient&) = delete;

    HttpResponse get(const std::string& url, int timeoutSeconds = 10) const;

    /// GET with custom request headers and response header capture.
    /// requestHeaders: list of "Header: value" strings to send.
    /// Response headers are returned in HttpResponse::headers (lowercase keys).
    HttpResponse getWithHeaders(const std::string& url, const std::vector<std::string>& requestHeaders,
                                int timeoutSeconds = 10) const;

    // Binary POST with custom Content-Type (for TSA, OCSP).
    HttpResponse postBinary(const std::string& url, const std::string& body, const std::string& contentType,
                            int timeoutSeconds = 60) const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl;
};

} // namespace libresign
