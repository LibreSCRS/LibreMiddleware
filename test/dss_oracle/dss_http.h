// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

#include "http_client.h"

#include <cstdint>
#include <span>
#include <string>

/// HTTP to the DSS Java service over its Unix socket. The oracle is the only
/// thing that speaks JSON and multipart or reaches a socket, so this lives with
/// it rather than in the signing library's HttpClient. Each call uses its own
/// curl handle, so these are safe to call from any thread.
namespace libresign::dss_http {

HttpResponse get(const std::string& socketPath, const std::string& url, int timeoutSeconds);

HttpResponse postJson(const std::string& socketPath, const std::string& url, const std::string& jsonBody,
                      int timeoutSeconds);

/// Multipart POST: the document as `document`, @p jsonMeta as `metadata`, and
/// @p originalDocument as `originalDocument` when it is not empty.
HttpResponse postMultipart(const std::string& socketPath, const std::string& url, std::span<const uint8_t> document,
                           const std::string& fileName, const std::string& jsonMeta,
                           std::span<const uint8_t> originalDocument, int timeoutSeconds);

} // namespace libresign::dss_http
