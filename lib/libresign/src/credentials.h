// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

#if !defined(LIBRESCRS_INTERNAL_BUILD)
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/Signing/TsaProvider.h>"
#endif

#include <LibreSCRS/Secure/Buffer.h>
#include <LibreSCRS/Secure/String.h>

#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <variant>
#include <vector>

namespace libresign {

/// @brief Transport-layer credential bundle.
///
/// Single struct carrying auth material for HTTP-backed transports.
/// Consumed by @c lib/libresign/src/http_client.h (applyCredentials) and
/// @c lib/libresign/src/native/tsa_client.h (timestamp with auth).
///
/// Layering invariant: this header MUST NOT include anything from the
/// signing domain (SigningRequest, TsaProvider, pades/cades/xades/jades).
/// It is a pure transport primitive.
///
/// Fields:
/// - basicAuth (user + password): HTTP Basic (RFC 7617). Pair-invariant
///   type-enforced (both halves required together).
/// - bearerToken: HTTP Bearer (RFC 6750).
/// - clientCert + clientCertKey: mTLS (TLS-level); each is a variant of
///   `std::filesystem::path` OR in-memory PEM bytes.
/// - extraHeaders: non-secret metadata (User-Agent, X-Request-Id, …).
/// - extraSecretHeaders: secret custom-scheme headers (X-Api-Key, …).
///
/// @note basicAuth.password + bearerToken + extraSecretHeaders values
///       zero-on-destruction via Secure::String. Usernames + extraHeaders
///       values + cert paths are plain strings/paths.
struct TransportCredentials
{
    /// @brief HTTP Basic auth material. The pair invariant (user + password
    ///        both present or both absent) is type-enforced by the struct.
    struct BasicAuth
    {
        std::string user;
        LibreSCRS::Secure::String password;
    };

    /// @brief HTTP Basic credentials. Encoded as
    ///        `Authorization: Basic <base64(user:pass)>` via libcurl
    ///        `CURLOPT_USERPWD` + `CURLAUTH_BASIC`.
    std::optional<BasicAuth> basicAuth;
    /// @brief Bearer token, sent as `Authorization: Bearer <token>`.
    ///        No libcurl helper exists for this — set manually as a
    ///        custom header. Cleansed on destruction.
    std::optional<LibreSCRS::Secure::String> bearerToken;
    /// @brief Variant alternative: PEM material loaded from disk OR carried
    ///        in-memory. Mirrors the public @ref LibreSCRS::Signing::TsaCredentials::PemSource
    ///        (file path OR PEM bytes) but stores the in-memory alternative
    ///        through a @c std::shared_ptr<Secure::Buffer> so the enclosing
    ///        @ref TransportCredentials remains copyable — each
    ///        sign-module's @c toTsaRequest() narrows TSAConfig to TSARequest
    ///        by copying. The shared_ptr keeps the cleansing @ref Secure::Buffer
    ///        alive across those copies without duplicating key material.
    using PemSource = std::variant<std::filesystem::path, std::shared_ptr<LibreSCRS::Secure::Buffer>>;

    /// @brief Client certificate for mTLS (libcurl `CURLOPT_SSLCERT` or
    ///        `CURLOPT_SSLCERT_BLOB`).
    std::optional<PemSource> clientCert;
    /// @brief Client private key for mTLS (libcurl `CURLOPT_SSLKEY` or
    ///        `CURLOPT_SSLKEY_BLOB`).
    std::optional<PemSource> clientCertKey;
    /// @brief Additional non-secret request headers. Names are stored
    ///        as-given; HTTP treats them case-insensitively. A
    ///        `std::vector<std::pair<…>>` preserves insertion order and
    ///        allows the same name to appear multiple times (some
    ///        enterprise TSAs rely on this).
    ///        Values are NOT cleansed — use @ref extraSecretHeaders for
    ///        secret material.
    std::vector<std::pair<std::string, std::string>> extraHeaders;
    /// @brief Additional secret-bearing request headers (e.g. bespoke
    ///        `X-Api-Key` / `X-Hmac-Signature` schemes). Values are
    ///        cleansed on destruction via @ref LibreSCRS::Secure::String.
    std::vector<std::pair<std::string, LibreSCRS::Secure::String>> extraSecretHeaders;
};

} // namespace libresign
