// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

#include "credentials.h"
#include "types.h"

#include <cstdint>
#include <string>
#include <vector>

namespace libresign {

/// @brief Result of a single TSA request.
///
/// On success @ref token holds the DER-encoded RFC 3161 `TimeStampToken`
/// (PKCS#7 SignedData) as returned by the authority. On failure @ref
/// errorMessage carries a human-readable diagnostic; @ref token is empty.
struct TSAResult
{
    bool success = false;
    /// @brief DER-encoded RFC 3161 `TimeStampToken` (PKCS#7).
    std::vector<uint8_t> token;
    /// @brief Human-readable error when @ref success is false.
    std::string errorMessage;
};

/// @brief Full TSA request: URL plus transport-layer credentials.
///
/// Internal mirror of @c LibreSCRS::Signing::TsaRequest carrying the
/// extra knob @ref timeoutSeconds that only the internal client cares
/// about. The public struct is copied into this one at the API bridge.
struct TSARequest
{
    /// @brief Target TSA endpoint URL (http/https).
    std::string url;
    /// @brief Credentials applied to requests against @ref url.
    TransportCredentials credentials;
    /// @brief Per-request network timeout (seconds). Default 10s.
    int timeoutSeconds = 10;
};

/// @brief Narrow a @ref TSAConfig to the @ref TSARequest subset consumed
///        by @ref TSAClient. The revocation-data toggles (`crlEnabled`,
///        `ocspEnabled`) are dropped because they do not affect the TSA
///        HTTP request itself — they are consumed by @ref RevocationClient.
inline TSARequest toTsaRequest(const TSAConfig& cfg)
{
    // Aggregate copy-construction, not member-wise copy-ASSIGNMENT: the
    // assignment form runs std::optional's destroy-then-construct payload
    // path for `credentials`, which GCC 16.2 misanalyses at -O3 into a
    // -Wmaybe-uninitialized false positive inside the inlined
    // variant/shared_ptr storage (breaking -Werror builds).
    return TSARequest{cfg.url, cfg.credentials, cfg.timeoutSeconds};
}

/// @brief RFC 3161 Time-Stamp Protocol client.
///
/// Stateless — one instance may issue any number of requests. Not
/// thread-safe: each thread owns its own instance (same contract as
/// @ref HttpClient; the underlying cURL easy-handle is per-instance).
class TSAClient
{
public:
    /// @brief Request a timestamp token for the given SHA-256 hash.
    /// @param hash    32-byte SHA-256 digest of the content to timestamp.
    /// @param request Endpoint URL, credentials, and timeout.
    /// @return @ref TSAResult. `success == false` on transport failure,
    ///         non-success TSA status, nonce mismatch, or imprint
    ///         mismatch (RFC 3161 §2.4.2 replay / substitution checks).
    TSAResult timestamp(const std::vector<uint8_t>& hash, const TSARequest& request);
};

} // namespace libresign
