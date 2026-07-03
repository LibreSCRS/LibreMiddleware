// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

/// @file
/// @brief TSA integration surface — @ref LibreSCRS::Signing::TsaContext,
///        @ref LibreSCRS::Signing::TsaCredentials,
///        @ref LibreSCRS::Signing::TsaRequest, and
///        @ref LibreSCRS::Signing::TsaProvider runtime-secret callback.
/// @since 4.0

#include <LibreSCRS/Export.h>
#include <LibreSCRS/Secure/Buffer.h>
#include <LibreSCRS/Secure/String.h>
#include <LibreSCRS/Signing/Enums.h>
#include <LibreSCRS/SyncProvider.h>

#include <chrono>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

namespace LibreSCRS::Signing {

/// @brief Context supplied to a `TsaProvider` when the engine requests a
///        timestamp-authority configuration.
///
/// Uniform callback shape with `LibreSCRS::Auth::CredentialProvider`:
/// runtime secrets are never stored in config, only produced on demand.
///
/// @par Thread-safety
/// thread-compatible (see API-POLICY §8).
struct TsaContext
{
    /// @brief Signature format requested by the engine.
    SignatureFormat format = SignatureFormat::Pades;
    /// @brief Signature level requested by the engine.
    SignatureLevel level = SignatureLevel::B_T;
    /// @brief When the signing operation is taking place.
    ///
    /// Empty if the caller did not supply a time; enterprise TSAs using
    /// time-based key/algorithm selection should treat absence as "use
    /// current wall-clock time".
    std::optional<std::chrono::system_clock::time_point> signingTime;
};

/// @brief Credentials applied to outbound TSA HTTP requests.
///
/// @note Secret fields (@ref BasicAuth::password, @ref bearerToken,
///       @ref extraSecretHeaders values) use @ref LibreSCRS::Secure::String,
///       which cleanses its bytes on destruction and on assignment.
///       @ref BasicAuth::user is plain `std::string` (usernames are not
///       secret) and @ref extraHeaders is a
///       `std::vector<std::pair<std::string, std::string>>` for non-secret
///       request metadata (User-Agent, X-Request-Id, …).
///
/// @note The `BasicAuth` struct supersedes an earlier flat
///       `basicAuthUser` / `basicAuthPassword` pair — the "both-or-neither"
///       invariant is now type-enforced rather than bridge-validated.
///
/// @note All credential values are checked for CR, LF, and NUL bytes at
///       transport time; values containing these control characters are
///       rejected before any network I/O. This prevents HTTP header
///       injection (libcurl delegates CR/LF sanitisation to the
///       application per its own security docs).
/// @note @ref extraHeaders and @ref extraSecretHeaders carrying an
///       `Authorization` entry (case-insensitive) are rejected at transport
///       time when @ref basicAuth or @ref bearerToken is set. The
///       combination would silently downgrade the configured primary
///       authentication to whatever the extra header carries, which is a
///       misconfiguration footgun. Emitting an `Authorization` entry in
///       @ref extraHeaders / @ref extraSecretHeaders with no primary auth
///       set is still allowed as an explicit escape hatch for bespoke
///       schemes (HMAC, AWS SigV4, …).
struct TsaCredentials
{
    /// @brief HTTP Basic auth material. Username + password are either both
    ///        present (struct engaged) or both absent (optional disengaged);
    ///        the pair invariant is type-enforced.
    struct BasicAuth
    {
        /// @brief HTTP Basic username (plain `std::string` — not secret).
        std::string user;
        /// @brief HTTP Basic password. Held in a cleansing @ref Secure::String.
        Secure::String password;
    };

    /// @brief HTTP Basic credentials. Disengaged means no Basic auth.
    std::optional<BasicAuth> basicAuth;
    /// @brief Bearer token (sent as `Authorization: Bearer <token>`).
    ///        Held in a cleansing @ref Secure::String.
    std::optional<Secure::String> bearerToken;
    /// @brief Variant alternative: client credential sourced from one of
    ///        a PEM-encoded file on disk or a PEM-encoded byte buffer held
    ///        in memory. Used by both @ref clientCert and @ref clientCertKey.
    ///
    /// When the alternative is @c std::filesystem::path, the transport
    /// passes the path to libcurl (which reads the file at request time).
    /// When the alternative is @ref LibreSCRS::Secure::Buffer, the transport
    /// loads the PEM-encoded bytes directly — useful for consumers that keep
    /// credentials in a secrets manager and never touch disk, or for unit
    /// tests that inject synthetic material.
    using PemSource = std::variant<std::filesystem::path, LibreSCRS::Secure::Buffer>;

    /// @brief Client certificate for mTLS. File path OR PEM bytes.
    std::optional<PemSource> clientCert;
    /// @brief Client certificate private key for mTLS. File path OR PEM
    ///        bytes. Held in a cleansing @ref Secure::Buffer when supplied
    ///        in-memory so the key material is zeroised on destruction.
    std::optional<PemSource> clientCertKey;
    /// Additional non-secret HTTP headers to include with TSA requests.
    /// Header names are stored as-given; the transport layer compares them
    /// case-insensitively (per RFC 7230 §3.2) when enforcing the
    /// Authorization-conflict check against @ref basicAuth and
    /// @ref bearerToken.
    ///
    /// @note A `std::vector<std::pair<…>>` rather than a `std::map` so the
    ///       caller can emit the same header name repeatedly (some
    ///       enterprise TSAs use this for audit-trail markers) and so
    ///       insertion order is preserved on the wire. Deduplication is
    ///       not performed — the transport layer forwards entries verbatim
    ///       in order.
    ///
    /// @warning Values are NOT cleansed on destruction. Never place secret
    ///          material (tokens, passwords, API keys) here — use
    ///          @ref bearerToken, @ref basicAuth, or @ref extraSecretHeaders
    ///          instead.
    std::vector<std::pair<std::string, std::string>> extraHeaders;
    /// Additional HTTP headers carrying secret material — e.g. bespoke
    /// `X-Api-Key` or `X-Hmac-Signature` schemes. Values are held in
    /// @ref LibreSCRS::Secure::String and cleansed on destruction; names
    /// are plain strings (not secret). Same RFC 7230 case-insensitivity +
    /// duplicate-allowed semantics as @ref extraHeaders. At transport time,
    /// entries from both containers are combined into the outbound header
    /// list; values in either container are subject to the CR/LF/NUL and
    /// Authorization-conflict checks.
    std::vector<std::pair<std::string, Secure::String>> extraSecretHeaders;
};

/// @brief Output of a `TsaProvider`: URL + credentials to contact the TSA.
struct TsaRequest
{
    /// @brief Target TSA endpoint URL.
    std::string url;
    /// @brief Credentials applied to requests against @ref url.
    TsaCredentials credentials;
};

/// @brief Host-supplied callback producing a @ref LibreSCRS::Signing::TsaRequest on demand.
///
/// @par See LibreSCRS::SyncProvider
/// The invocation, thread-safety, empty-callable, and `CopyConstructible`
/// contracts are documented once on the generic alias. The signing engine
/// translates an empty `TsaProvider` to
/// @ref LibreSCRS::Signing::SigningResult::Status::TsaUnreachable
/// rather than letting `std::bad_function_call` propagate.
using TsaProvider = SyncProvider<TsaRequest, TsaContext>;

/// @brief Convenience factory: fixed URL, no authentication.
/// @param url TSA endpoint URL. Accepted as-is — no syntactic validation.
/// @return A `TsaProvider` that returns @p url with empty credentials,
///         ignoring the @ref LibreSCRS::Signing::TsaContext.
/// @note Permissive of non-http TSA transports and unusual URL syntaxes;
///       use `staticTsaChecked` when you want the factory to reject
///       obviously malformed URLs up-front.
[[nodiscard]] LIBRESCRS_PUBLIC_API TsaProvider staticTsa(std::string url);

/// @brief Validating variant of `staticTsa`.
///
/// Performs a basic syntactic check on @p url:
///   - non-empty;
///   - begins with `http://` or `https://`;
///   - the scheme is followed by a non-empty authority (host token).
///
/// This is a lightweight pre-flight filter — it catches "forgot the scheme"
/// / empty-string / "http://" configuration mistakes before they reach the
/// signing engine, without attempting full RFC 3986 validation. Rigorous
/// URL parsing is delegated to libcurl at transport time.
///
/// @param url TSA endpoint URL.
/// @throws std::invalid_argument if @p url fails any of the checks above.
///         See API-POLICY §5.1.
/// @return A `TsaProvider` that returns @p url with empty credentials,
///         ignoring the @ref LibreSCRS::Signing::TsaContext.
[[nodiscard]] LIBRESCRS_PUBLIC_API TsaProvider staticTsaChecked(std::string_view url);

} // namespace LibreSCRS::Signing
