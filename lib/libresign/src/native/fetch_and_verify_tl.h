// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

#include "trusted_list_parser.h"
#include "types.h"

#include <LibreSCRS/CancelToken.h>

#include <chrono>
#include <string>
#include <variant>

namespace libresign {

/// @brief Options controlling a single Trusted-List fetch+verify cycle.
struct FetchOptions
{
    /// @brief Optional cache directory; when empty, no cache is used.
    std::string cacheDirectory;
    /// @brief HTTP(S) timeout for the GET / conditional GET.
    std::chrono::seconds requestTimeout{30};
    /// @brief Cancellation token honoured at coarse-grained checkpoints
    ///        (between fetch and verify, between verify and parse).
    LibreSCRS::CancelToken stop;
};

/// @brief Result of @ref fetchAndVerifyTrustedList.
///
/// Mirrors the SOTA-2026 @c std::expected<T,E> shape (success xor error
/// string) without the C++23 standard-library dependency, since the
/// project ships against C++20. @c hasValue() short-circuits the success
/// path; on failure @c error carries a human-readable diagnostic.
struct FetchResult
{
    bool ok = false;
    TrustedListInfo info;
    std::string error;

    [[nodiscard]] bool hasValue() const noexcept
    {
        return ok;
    }
    explicit operator bool() const noexcept
    {
        return ok;
    }

    static FetchResult success(TrustedListInfo i)
    {
        FetchResult r;
        r.ok = true;
        r.info = std::move(i);
        return r;
    }
    static FetchResult failure(std::string e)
    {
        FetchResult r;
        r.ok = false;
        r.error = std::move(e);
        return r;
    }
};

/// @brief Fetch (or read locally), signature-verify, and parse a single
///        Trusted List @p entry. Self-contained: does not recurse into
///        LOTL pointers, does not mutate global engine state.
///
/// @return On success, a @ref FetchResult holding the parsed @ref
///         TrustedListInfo. On failure, @ref FetchResult::error carries a
///         human-readable diagnostic.
///
/// @par Verification cert resolution
///  - If @p entry.signingCertPath is non-empty, that file (DER or PEM)
///    is the verification anchor.
///  - Otherwise the pinned-cert table (@ref pinned_certs::pinnedCertForUrl)
///    is consulted.
///  - If no candidate is available, the call fails with a descriptive
///    error message rather than silently accepting.
///
/// @par file:// branch
/// When @p entry.localFileOnly is set and @p entry.url begins with
/// @c "file://", the body is read directly from disk via @c std::ifstream
/// and the cache is bypassed. Defense-in-depth: HttpClient itself
/// continues to reject the @c file:// scheme via @c CURLOPT_PROTOCOLS_STR.
[[nodiscard]] FetchResult fetchAndVerifyTrustedList(const TrustedListEntry& entry, FetchOptions opts);

} // namespace libresign
