// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

#include <cstdint>
#include <map>
#include <memory>
#include <span>
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

// NOT thread-safe. Each thread must use its own HttpClient instance.
// DSSServiceManager serializes access via its recursive_mutex.
class HttpClient
{
public:
    HttpClient();
    ~HttpClient();

    HttpClient(HttpClient&&) noexcept;
    HttpClient& operator=(HttpClient&&) noexcept;

    HttpClient(const HttpClient&) = delete;
    HttpClient& operator=(const HttpClient&) = delete;

    HttpResponse get(const std::string& url, int timeoutSeconds = 10, const std::string& unixSocketPath = {}) const;

    /// GET with custom request headers and response header capture.
    /// requestHeaders: list of "Header: value" strings to send.
    /// Response headers are returned in HttpResponse::headers (lowercase keys).
    HttpResponse getWithHeaders(const std::string& url,
                                const std::vector<std::string>& requestHeaders,
                                int timeoutSeconds = 10,
                                const std::string& unixSocketPath = {}) const;

    HttpResponse post(const std::string& url, const std::string& jsonBody, int timeoutSeconds = 60,
                      const std::string& unixSocketPath = {}) const;

    // Binary POST with custom Content-Type (for TSA, OCSP).
    HttpResponse postBinary(const std::string& url, const std::string& body, const std::string& contentType,
                            int timeoutSeconds = 60, const std::string& unixSocketPath = {}) const;

    // Multipart POST: binary document + JSON metadata. Response body is raw bytes.
    HttpResponse postMultipart(const std::string& url, std::span<const uint8_t> docData, const std::string& fileName,
                               const std::string& jsonMeta, int timeoutSeconds = 120,
                               const std::string& unixSocketPath = {}) const;

    // Multipart POST for validation: signed document + JSON metadata + optional original document.
    HttpResponse postMultipartValidation(const std::string& url, std::span<const uint8_t> signedDoc,
                                         const std::string& fileName, const std::string& jsonMeta,
                                         std::span<const uint8_t> originalDoc = {}, int timeoutSeconds = 120,
                                         const std::string& unixSocketPath = {}) const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl;
};

} // namespace libresign
