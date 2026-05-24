// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "http_client.h"

#include <LibreSCRS/Export.h>

#include <curl/curl.h>
#include <openssl/crypto.h>

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <limits>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <type_traits>
#include <variant>
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

struct CurlMimeDeleter
{
    void operator()(curl_mime* p) const
    {
        if (p)
            curl_mime_free(p);
    }
};
using CurlMimePtr = std::unique_ptr<curl_mime, CurlMimeDeleter>;

// Reject credential values that would cause HTTP header injection
// (CR/LF/NUL) or silently override our own Authorization header.
//
// Returns an empty string on success. Non-empty return is a
// human-readable reason that callers surface via
// HttpResponse::errorMessage.
//
// Rationale (4.0 design review):
//   * libcurl's security docs (CURLOPT_HTTPHEADER, CURLOPT_USERPWD)
//     explicitly delegate CR/LF sanitisation to the application.
//     A value like `"valid\r\nHost: evil"` smuggles a second header.
//   * Extra headers containing "Authorization" silently win over our
//     Basic/Bearer configuration ("libcurl added header is used
//     instead"). A misconfigured or malicious TsaProvider can use
//     that to downgrade auth. We reject the combination instead of
//     documenting the footgun.
//
// extraHeaders["Authorization"] is still ALLOWED when no primary auth
// is set — this is an explicit escape hatch for custom schemes (HMAC,
// AWS SigV4, …) where callers precompute the Authorization header.
[[nodiscard]] std::string validateCredentials(const TransportCredentials& creds) noexcept
{
    using namespace std::string_view_literals;
    // CR / LF / NUL: any of these in a header value smuggles a new
    // header or truncates the current one once libcurl hands the
    // C-string to a write syscall.
    static constexpr auto kForbidden = "\r\n"sv; // NUL handled separately (string_view::find
                                                 // over a literal stops at the NUL)
    auto hasControlChars = [](std::string_view v) noexcept -> bool {
        if (v.find_first_of(kForbidden) != std::string_view::npos)
            return true;
        // Explicit NUL scan: string_view supports embedded NULs, but
        // using them as a separator in find_first_of(const char*) does
        // not — passing a literal makes the "needles" string terminate
        // at the first NUL. Scan manually instead.
        for (char c : v) {
            if (c == '\0')
                return true;
        }
        return false;
    };

    if (creds.basicAuth) {
        if (hasControlChars(creds.basicAuth->user)) {
            return "basicAuthUser contains CR/LF/NUL";
        }
        if (hasControlChars(creds.basicAuth->password.view())) {
            return "basicAuthPassword contains CR/LF/NUL";
        }
    }
    if (creds.bearerToken && hasControlChars(creds.bearerToken->view())) {
        return "bearerToken contains CR/LF/NUL";
    }
    for (const auto& [name, value] : creds.extraHeaders) {
        if (hasControlChars(name)) {
            return "extraHeader name contains CR/LF/NUL";
        }
        if (hasControlChars(value)) {
            return "extraHeader value contains CR/LF/NUL";
        }
    }
    for (const auto& [name, value] : creds.extraSecretHeaders) {
        if (hasControlChars(name)) {
            return "extraSecretHeader name contains CR/LF/NUL";
        }
        if (hasControlChars(value.view())) {
            return "extraSecretHeader value contains CR/LF/NUL";
        }
    }

    // Authorization-conflict check. A helper that treats `name` as
    // case-insensitively equal to "authorization".
    auto isAuthorization = [](std::string_view name) noexcept -> bool {
        static constexpr auto kAuthorization = "authorization"sv;
        if (name.size() != kAuthorization.size())
            return false;
        for (std::size_t i = 0; i < kAuthorization.size(); ++i) {
            if (std::tolower(static_cast<unsigned char>(name[i])) != kAuthorization[i]) {
                return false;
            }
        }
        return true;
    };

    const bool hasPrimaryAuth = creds.basicAuth.has_value() || creds.bearerToken.has_value();
    if (hasPrimaryAuth) {
        for (const auto& [name, _value] : creds.extraHeaders) {
            if (isAuthorization(name)) {
                return "extraHeaders contains 'Authorization' while basicAuth/bearerToken is set";
            }
        }
        for (const auto& [name, _value] : creds.extraSecretHeaders) {
            if (isAuthorization(name)) {
                return "extraSecretHeaders contains 'Authorization' while basicAuth/bearerToken is set";
            }
        }
    }

    return {}; // OK
}

// Apply a TransportCredentials bundle to an already-configured CURL handle.
//
// Returns the pre-existing `curl_slist*` (may be null) augmented with
// any Authorization / extra-header entries the credentials imply; the
// caller owns the list and must free it with curl_slist_free_all().
// The caller must also call CURLOPT_HTTPHEADER with the returned list
// AFTER this function returns (so that appended entries take effect).
curl_slist* applyCredentials(CURL* c, const TransportCredentials& creds, curl_slist* headers)
{
    // HTTP Basic: libcurl handles the base64 + Authorization-header
    // dance itself when CURLOPT_HTTPAUTH = CURLAUTH_BASIC. The
    // @ref TransportCredentials::BasicAuth struct makes the
    // both-or-neither pair invariant type-enforced, so a separate
    // AND-gate against two optionals is unnecessary.
    if (creds.basicAuth.has_value()) {
        const auto& user = creds.basicAuth->user;
        const auto passView = creds.basicAuth->password.view();
        // libcurl's CURLOPT_PASSWORD expects a null-terminated string;
        // materialise the Secure::String view into a std::string only
        // for the duration of the setopt call. libcurl internally
        // duplicates the value (CURLOPTTYPE_STRINGPOINT), so the local
        // goes out of scope safely here.
        //
        // Caveat: that libcurl-internal copy is NOT cleansed. Reducing
        // libcurl's exposure window further would require CURLOPT_XFERINFO
        // / auth-builder hooks that don't exist today; tracked as a
        // Secure::String design note.
        std::string passStr(passView);
        curl_easy_setopt(c, CURLOPT_HTTPAUTH, static_cast<long>(CURLAUTH_BASIC));
        curl_easy_setopt(c, CURLOPT_USERNAME, user.c_str());
        curl_easy_setopt(c, CURLOPT_PASSWORD, passStr.c_str());
        OPENSSL_cleanse(passStr.data(), passStr.size());
    }

    // Bearer: libcurl has no first-class option, so we inject a custom
    // Authorization header. If caller ALSO supplied Basic, Basic wins
    // (libcurl will overwrite our Authorization entry); the API-layer
    // contract forbids setting both, and the transport-level
    // @ref validateCredentials check (invoked from
    // postBinaryWithCredentials before any curl_* call) rejects the
    // related "extraHeaders carries Authorization while primary auth
    // is set" footgun.
    //
    // Header values are also pre-checked for CR/LF/NUL there, so the
    // curl_slist_append calls below cannot smuggle extra headers.
    //
    // As with Basic above, the concatenated header string is not itself
    // a Secure::String; cleanse it manually after curl_slist_append
    // duplicates it.
    if (creds.bearerToken.has_value()) {
        std::string hdr = "Authorization: Bearer ";
        hdr.append(creds.bearerToken->view());
        headers = curl_slist_append(headers, hdr.c_str());
        OPENSSL_cleanse(hdr.data(), hdr.size());
    }

    // mTLS: either a PEM file on disk (CURLOPT_SSLCERT + CURLOPT_SSLCERTTYPE)
    // or PEM bytes held in a @ref LibreSCRS::Secure::Buffer
    // (CURLOPT_SSLCERT_BLOB + CURLOPT_SSLCERTTYPE). The 4.0 unified variant
    // lets consumers keep credentials in a secrets manager without ever
    // touching disk. We don't tighten CURLOPT_SSLKEYTYPE / CURLOPT_SSLCERTTYPE
    // beyond "PEM" since the public API documents PEM.
    //
    // `std::filesystem::path::c_str()` is `const wchar_t*` on Windows
    // and `const char*` on POSIX; libcurl expects a narrow UTF-8
    // string. Use `.string()` which normalises to UTF-8-native text on
    // POSIX (no-op on this platform) — keep a local for lifetime.
    std::string certPath;
    std::string keyPath;
    curl_blob certBlob{};
    curl_blob keyBlob{};
    if (creds.clientCert.has_value()) {
        std::visit(
            [&](const auto& alt) {
                using Alt = std::decay_t<decltype(alt)>;
                if constexpr (std::is_same_v<Alt, std::filesystem::path>) {
                    certPath = alt.string();
                    curl_easy_setopt(c, CURLOPT_SSLCERT, certPath.c_str());
                    curl_easy_setopt(c, CURLOPT_SSLCERTTYPE, "PEM");
                } else {
                    // shared_ptr<Secure::Buffer> alternative — in-memory PEM
                    // bytes. The TransportCredentials value is copyable
                    // because the shared_ptr lets copies share one cleansing
                    // buffer; each `alt` here is the shared_ptr, deref to
                    // reach the underlying bytes.
                    if (!alt)
                        return;
                    certBlob.data = const_cast<std::uint8_t*>(alt->data());
                    certBlob.len = alt->size();
                    certBlob.flags = CURL_BLOB_COPY;
                    curl_easy_setopt(c, CURLOPT_SSLCERT_BLOB, &certBlob);
                    curl_easy_setopt(c, CURLOPT_SSLCERTTYPE, "PEM");
                }
            },
            *creds.clientCert);
    }
    if (creds.clientCertKey.has_value()) {
        std::visit(
            [&](const auto& alt) {
                using Alt = std::decay_t<decltype(alt)>;
                if constexpr (std::is_same_v<Alt, std::filesystem::path>) {
                    keyPath = alt.string();
                    curl_easy_setopt(c, CURLOPT_SSLKEY, keyPath.c_str());
                    curl_easy_setopt(c, CURLOPT_SSLKEYTYPE, "PEM");
                } else {
                    if (!alt)
                        return;
                    keyBlob.data = const_cast<std::uint8_t*>(alt->data());
                    keyBlob.len = alt->size();
                    // CURL_BLOB_COPY: libcurl takes its own copy; the
                    // libcurl-owned copy isn't cleansed — this is the same
                    // caveat as Basic-auth password above, and is tracked
                    // with the Secure::String design note.
                    keyBlob.flags = CURL_BLOB_COPY;
                    curl_easy_setopt(c, CURLOPT_SSLKEY_BLOB, &keyBlob);
                    curl_easy_setopt(c, CURLOPT_SSLKEYTYPE, "PEM");
                }
            },
            *creds.clientCertKey);
    }

    // Extra headers. Appended after any we just set so callers can
    // override `Content-Type` if they need to. Overriding
    // `Authorization` is blocked up-front by @ref validateCredentials
    // when primary auth (basicAuth / bearerToken) is set — when there
    // is no primary auth, callers MAY use
    // extraHeaders["Authorization"] / extraSecretHeaders["Authorization"]
    // to carry a bespoke scheme (HMAC, AWS SigV4, …). Names and values
    // have already passed the CR/LF/NUL check in
    // @ref validateCredentials, so curl_slist_append cannot smuggle
    // secondary headers here.
    for (const auto& [name, value] : creds.extraHeaders) {
        std::string line = name + ": " + value;
        headers = curl_slist_append(headers, line.c_str());
    }
    // Secret-bearing headers. libcurl internally duplicates the appended
    // C-string (CURLOPTTYPE_STRINGPOINT), so the local `line` goes out of
    // scope safely — we additionally OPENSSL_cleanse the local before
    // returning so the secret value does not linger in the caller's stack
    // frame. The libcurl-internal copy is NOT cleansed (same caveat as
    // basicAuth.password above, tracked as a Secure::String design note).
    for (const auto& [name, value] : creds.extraSecretHeaders) {
        std::string line = name + ": ";
        line.append(value.view());
        headers = curl_slist_append(headers, line.c_str());
        OPENSSL_cleanse(line.data(), line.size());
    }

    return headers;
}

} // namespace

struct LIBRESCRS_INTERNAL HttpClient::Impl
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

        if (!unixSocketPath.empty())
            curl_easy_setopt(c, CURLOPT_UNIX_SOCKET_PATH, unixSocketPath.c_str());

        return c;
    }
};

HttpClient::HttpClient() : impl(std::make_unique<Impl>())
{
    ensureCurlInit();
    impl->curl = curl_easy_init();
    if (impl->curl) {
        // Defense-in-depth: pin TLS chain validation per-handle. libcurl
        // defaults CURLOPT_SSL_VERIFYPEER=1 and CURLOPT_SSL_VERIFYHOST=2,
        // but a future global setopt override or environment carry-over
        // could quietly relax those. Setting them explicitly per-handle
        // pins TLS chain validation for every request issued by this client
        // — an attacker who flips a global default cannot weaken our path.
        curl_easy_setopt(static_cast<CURL*>(impl->curl), CURLOPT_SSL_VERIFYPEER, 1L);
        curl_easy_setopt(static_cast<CURL*>(impl->curl), CURLOPT_SSL_VERIFYHOST, 2L);
    }
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

HttpResponse HttpClient::getWithHeaders(const std::string& url, const std::vector<std::string>& requestHeaders,
                                        int timeoutSeconds, const std::string& unixSocketPath) const
{
    HttpResponse resp;
    WriteContext writeCtx;
    auto* c = impl->setupCommon(url, timeoutSeconds, unixSocketPath, &writeCtx);
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

HttpResponse HttpClient::postBinaryWithCredentials(const std::string& url, const std::string& body,
                                                   const std::string& contentType,
                                                   const TransportCredentials& credentials, int timeoutSeconds,
                                                   const std::string& unixSocketPath) const
{
    HttpResponse resp;

    // Pre-flight credential validation (Finding I1 + I2). Reject
    // CR/LF/NUL in any header value and reject extraHeaders-based
    // Authorization override of a configured primary auth. No
    // network I/O happens on failure.
    if (auto reason = validateCredentials(credentials); !reason.empty()) {
        resp.errorMessage = "Credential validation failed: " + reason;
        return resp;
    }

    // Body-size guard. CURLOPT_POSTFIELDSIZE takes
    // `long`; on LLP64 (Windows) `long` is 32-bit, so
    // static_cast<long>(size_t) would truncate for >2 GiB bodies and
    // libcurl would send the wrong Content-Length. Mirror the
    // response-side check in tsa_client.cpp. On LP64 platforms
    // (Linux, macOS) the condition is effectively unreachable but the
    // check is cheap and platform-portable.
    if (body.size() > static_cast<std::size_t>(std::numeric_limits<long>::max())) {
        resp.errorMessage = "Body size exceeds long max — cannot fit CURLOPT_POSTFIELDSIZE";
        return resp;
    }

    WriteContext writeCtx;
    auto* c = impl->setupCommon(url, timeoutSeconds, unixSocketPath, &writeCtx);
    if (!c) {
        resp.errorMessage = "curl not initialized";
        return resp;
    }

    curl_easy_setopt(c, CURLOPT_POSTFIELDS, body.data());
    curl_easy_setopt(c, CURLOPT_POSTFIELDSIZE, static_cast<long>(body.size()));

    std::string ctHeader = "Content-Type: " + contentType;
    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, ctHeader.c_str());
    headers = applyCredentials(c, credentials, headers);
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
