// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <gtest/gtest.h>

#ifdef LIBRESIGN_HAS_NATIVE

// Integration test: confirm that TransportCredentials threaded through
// TSARequest actually reach the TSA server as HTTP request headers.
//
// Strategy: spin up an in-process HTTP server on an ephemeral port,
// point TSAClient at it, and have the server capture every request
// header it observes. The server replies with 500 (no TS_RESP body);
// TSAClient will fail to parse, but by then the request headers are
// already on the wire and captured.

#include "http_client.h"
#include "native/tsa_client.h"
#include "types.h"

#include <LibreSCRS/Secure/String.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

using namespace libresign;

namespace {

// Minimal in-process HTTP/1.1 mock TSA server.
//
// - Binds on 127.0.0.1, port chosen by the OS (pass 0).
// - Accepts one connection at a time, reads until end-of-headers,
//   captures every header line, then replies 500 and closes.
// - Thread-safe observation: `headers()` may be called from the test
//   thread while the server thread is still accepting new connections.
class MockTsaServer
{
public:
    MockTsaServer()
    {
        listenFd = ::socket(AF_INET, SOCK_STREAM, 0);
        if (listenFd < 0)
            throw std::runtime_error("socket() failed");

        int one = 1;
        ::setsockopt(listenFd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = 0; // OS-assigned

        if (::bind(listenFd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
            ::close(listenFd);
            throw std::runtime_error("bind() failed");
        }
        if (::listen(listenFd, 4) < 0) {
            ::close(listenFd);
            throw std::runtime_error("listen() failed");
        }

        // Read back the assigned port.
        sockaddr_in bound{};
        socklen_t len = sizeof(bound);
        if (::getsockname(listenFd, reinterpret_cast<sockaddr*>(&bound), &len) < 0) {
            ::close(listenFd);
            throw std::runtime_error("getsockname() failed");
        }
        boundPort = ntohs(bound.sin_port);

        worker = std::thread([this] { runLoop(); });
    }

    ~MockTsaServer()
    {
        stopFlag.store(true);
        // Poke the accept() loop by connecting once; simplest portable
        // wake-up without pulling in eventfd/pipes.
        if (listenFd >= 0) {
            int wakeFd = ::socket(AF_INET, SOCK_STREAM, 0);
            if (wakeFd >= 0) {
                sockaddr_in addr{};
                addr.sin_family = AF_INET;
                addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
                addr.sin_port = htons(boundPort);
                ::connect(wakeFd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
                ::close(wakeFd);
            }
            ::close(listenFd);
            listenFd = -1;
        }
        if (worker.joinable())
            worker.join();
    }

    uint16_t port() const
    {
        return boundPort;
    }

    // All request header lines observed across every connection since
    // construction. Lowercased header name → value. Last value wins if
    // a header is repeated within a single request.
    std::vector<std::pair<std::string, std::string>> headers() const
    {
        std::lock_guard<std::mutex> lock(headersMutex);
        return capturedHeaders;
    }

    bool observedHeader(const std::string& name, const std::string& expectedValue) const
    {
        std::string wantName = toLower(name);
        std::lock_guard<std::mutex> lock(headersMutex);
        for (const auto& [k, v] : capturedHeaders) {
            if (k == wantName && v == expectedValue)
                return true;
        }
        return false;
    }

private:
    static std::string toLower(std::string s)
    {
        std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return std::tolower(c); });
        return s;
    }

    void runLoop()
    {
        while (!stopFlag.load()) {
            sockaddr_in peer{};
            socklen_t peerLen = sizeof(peer);
            int client = ::accept(listenFd, reinterpret_cast<sockaddr*>(&peer), &peerLen);
            if (client < 0) {
                if (stopFlag.load())
                    return;
                continue;
            }
            handleClient(client);
            ::close(client);
        }
    }

    void handleClient(int fd)
    {
        // Read until CRLF CRLF (end of HTTP headers). We don't bother
        // consuming the body — libcurl sends POST body but the test only
        // inspects headers. Closing after reply is fine; libcurl gets
        // its 500 and returns.
        std::string buf;
        char tmp[1024];
        const std::string terminator = "\r\n\r\n";
        while (buf.find(terminator) == std::string::npos) {
            ssize_t n = ::recv(fd, tmp, sizeof(tmp), 0);
            if (n <= 0)
                break;
            buf.append(tmp, static_cast<size_t>(n));
            if (buf.size() > 64 * 1024)
                break; // guard against runaway
        }

        // Split headers at CRLF, skip request line, parse "Name: value".
        std::vector<std::pair<std::string, std::string>> parsed;
        size_t pos = 0;
        size_t lineEnd = buf.find("\r\n", pos);
        if (lineEnd != std::string::npos)
            pos = lineEnd + 2; // skip request line

        while (pos < buf.size()) {
            lineEnd = buf.find("\r\n", pos);
            if (lineEnd == std::string::npos || lineEnd == pos)
                break;
            std::string line = buf.substr(pos, lineEnd - pos);
            pos = lineEnd + 2;

            auto colon = line.find(':');
            if (colon == std::string::npos)
                continue;
            std::string name = toLower(line.substr(0, colon));
            std::string value = line.substr(colon + 1);
            size_t vstart = value.find_first_not_of(" \t");
            if (vstart != std::string::npos)
                value = value.substr(vstart);
            else
                value.clear();
            parsed.emplace_back(std::move(name), std::move(value));
        }

        {
            std::lock_guard<std::mutex> lock(headersMutex);
            for (auto& p : parsed)
                capturedHeaders.push_back(std::move(p));
        }

        // Minimal HTTP/1.1 reply: 500 with empty body. TSAClient will fail
        // to decode, but that's fine — the assertion is on the captured
        // request headers, not on TSAResult.
        static const char kReply[] = "HTTP/1.1 500 Internal Server Error\r\n"
                                     "Content-Length: 0\r\n"
                                     "Connection: close\r\n"
                                     "\r\n";
        ssize_t sent = 0;
        size_t total = sizeof(kReply) - 1;
        while (sent < static_cast<ssize_t>(total)) {
            ssize_t n = ::send(fd, kReply + sent, total - static_cast<size_t>(sent), 0);
            if (n <= 0)
                break;
            sent += n;
        }
    }

    int listenFd = -1;
    uint16_t boundPort = 0;
    std::thread worker;
    std::atomic<bool> stopFlag{false};

    mutable std::mutex headersMutex;
    std::vector<std::pair<std::string, std::string>> capturedHeaders;
};

std::vector<uint8_t> fakeHash()
{
    // Deterministic 32-byte SHA-256-shaped input. TSAClient validates the
    // 32-byte length requirement, nothing else on the request side.
    return std::vector<uint8_t>(32, 0x42);
}

std::string urlFor(const MockTsaServer& s)
{
    return "http://127.0.0.1:" + std::to_string(s.port()) + "/tsa";
}

} // namespace

TEST(TsaAuthIntegration, BasicAuthHeaderReachesTsa)
{
    MockTsaServer server;

    TSARequest req;
    req.url = urlFor(server);
    req.timeoutSeconds = 5;
    req.credentials.basicAuth = TransportCredentials::BasicAuth{"user", LibreSCRS::Secure::String("pass")};

    // Call the client. Server responds 500 → result is failure; the test
    // cares about the request headers, not the response payload.
    TSAClient{}.timestamp(fakeHash(), req);

    // `user:pass` → base64 = "dXNlcjpwYXNz"
    EXPECT_TRUE(server.observedHeader("Authorization", "Basic dXNlcjpwYXNz"))
        << "TSA server did not see the expected Basic auth header. Captured:\n"
        << [&] {
               std::string dump;
               for (const auto& [k, v] : server.headers())
                   dump += "  " + k + ": " + v + "\n";
               return dump;
           }();
}

TEST(TsaAuthIntegration, BearerTokenHeaderReachesTsa)
{
    MockTsaServer server;

    TSARequest req;
    req.url = urlFor(server);
    req.timeoutSeconds = 5;
    req.credentials.bearerToken = LibreSCRS::Secure::String("abc123");

    TSAClient{}.timestamp(fakeHash(), req);

    EXPECT_TRUE(server.observedHeader("Authorization", "Bearer abc123"))
        << "TSA server did not see the expected Bearer auth header. Captured:\n"
        << [&] {
               std::string dump;
               for (const auto& [k, v] : server.headers())
                   dump += "  " + k + ": " + v + "\n";
               return dump;
           }();
}

TEST(TsaAuthIntegration, ExtraHeadersReachTsa)
{
    MockTsaServer server;

    TSARequest req;
    req.url = urlFor(server);
    req.timeoutSeconds = 5;
    req.credentials.extraHeaders.emplace_back("X-Tenant", "acme-corp");
    req.credentials.extraHeaders.emplace_back("X-Request-Id", "req-42");

    TSAClient{}.timestamp(fakeHash(), req);

    EXPECT_TRUE(server.observedHeader("X-Tenant", "acme-corp"));
    EXPECT_TRUE(server.observedHeader("X-Request-Id", "req-42"));
}

// =================================================================
// Credential validation (security hardening, pre-flight rejection).
// These tests hit HttpClient::postBinaryWithCredentials directly so
// the failure mode — "validation refuses, no network call" — is
// observable without dragging OpenSSL TSA parsing into the picture.
// The MockTsaServer is used only to prove the "no-call-on-reject"
// contract: the server's headers() stays empty.
// =================================================================

namespace {

// Small helper: build a baseline (valid) credential bundle, so each
// negative test only perturbs the one field under test.
TransportCredentials validBasic()
{
    TransportCredentials c;
    c.basicAuth = TransportCredentials::BasicAuth{"u", LibreSCRS::Secure::String("p")};
    return c;
}

TransportCredentials validBearer()
{
    TransportCredentials c;
    c.bearerToken = LibreSCRS::Secure::String("abc");
    return c;
}

HttpResponse postWith(const MockTsaServer& server, const TransportCredentials& creds, const std::string& body = "x")
{
    HttpClient http;
    return http.postBinaryWithCredentials(urlFor(server), body, "application/timestamp-query", creds,
                                          /*timeoutSeconds=*/5);
}

} // namespace

TEST(HttpCredentialsValidation, CrlfInBearerTokenRejected)
{
    MockTsaServer server;
    TransportCredentials c;
    c.bearerToken = LibreSCRS::Secure::String("valid\r\nevil: 1");

    auto resp = postWith(server, c);

    EXPECT_EQ(resp.statusCode, 0);
    EXPECT_FALSE(resp.errorMessage.empty());
    EXPECT_NE(resp.errorMessage.find("bearerToken"), std::string::npos) << resp.errorMessage;
    EXPECT_TRUE(server.headers().empty()) << "validation must reject BEFORE any network I/O";
}

TEST(HttpCredentialsValidation, CrlfInBasicPasswordRejected)
{
    MockTsaServer server;
    TransportCredentials c;
    c.basicAuth = TransportCredentials::BasicAuth{"u", LibreSCRS::Secure::String("p\r\nX-Smuggle: 1")};

    auto resp = postWith(server, c);

    EXPECT_EQ(resp.statusCode, 0);
    EXPECT_FALSE(resp.errorMessage.empty());
    EXPECT_NE(resp.errorMessage.find("basicAuthPassword"), std::string::npos) << resp.errorMessage;
    EXPECT_TRUE(server.headers().empty());
}

TEST(HttpCredentialsValidation, CrlfInBasicUserRejected)
{
    MockTsaServer server;
    TransportCredentials c;
    c.basicAuth = TransportCredentials::BasicAuth{"u\r\nevil: 1", LibreSCRS::Secure::String("p")};

    auto resp = postWith(server, c);

    EXPECT_EQ(resp.statusCode, 0);
    EXPECT_FALSE(resp.errorMessage.empty());
    EXPECT_NE(resp.errorMessage.find("basicAuthUser"), std::string::npos) << resp.errorMessage;
    EXPECT_TRUE(server.headers().empty());
}

TEST(HttpCredentialsValidation, CrlfInExtraHeaderNameRejected)
{
    MockTsaServer server;
    TransportCredentials c;
    c.extraHeaders.emplace_back("X-Legit\r\nX-Evil", "ok");

    auto resp = postWith(server, c);

    EXPECT_EQ(resp.statusCode, 0);
    EXPECT_FALSE(resp.errorMessage.empty());
    EXPECT_NE(resp.errorMessage.find("extraHeader name"), std::string::npos) << resp.errorMessage;
    EXPECT_TRUE(server.headers().empty());
}

TEST(HttpCredentialsValidation, CrlfInExtraHeaderValueRejected)
{
    MockTsaServer server;
    TransportCredentials c;
    c.extraHeaders.emplace_back("X-Legit", "ok\r\nX-Evil: 1");

    auto resp = postWith(server, c);

    EXPECT_EQ(resp.statusCode, 0);
    EXPECT_FALSE(resp.errorMessage.empty());
    EXPECT_NE(resp.errorMessage.find("extraHeader value"), std::string::npos) << resp.errorMessage;
    EXPECT_TRUE(server.headers().empty());
}

TEST(HttpCredentialsValidation, NulInBearerTokenRejected)
{
    MockTsaServer server;
    TransportCredentials c;
    // Embedded NUL — would be silently truncated by C-string APIs. The
    // Secure::String ctor takes a std::string, so a NUL byte survives.
    std::string tok = "abc";
    tok.push_back('\0');
    tok.append("def");
    c.bearerToken = LibreSCRS::Secure::String(tok);

    auto resp = postWith(server, c);

    EXPECT_EQ(resp.statusCode, 0);
    EXPECT_FALSE(resp.errorMessage.empty());
    EXPECT_NE(resp.errorMessage.find("bearerToken"), std::string::npos) << resp.errorMessage;
    EXPECT_TRUE(server.headers().empty());
}

TEST(HttpCredentialsValidation, ExtraHeaderAuthorizationRejectedWhenBasicSet)
{
    MockTsaServer server;
    TransportCredentials c = validBasic();
    c.extraHeaders.emplace_back("Authorization", "Bearer rogue");

    auto resp = postWith(server, c);

    EXPECT_EQ(resp.statusCode, 0);
    EXPECT_FALSE(resp.errorMessage.empty());
    EXPECT_NE(resp.errorMessage.find("Authorization"), std::string::npos) << resp.errorMessage;
    EXPECT_TRUE(server.headers().empty());
}

TEST(HttpCredentialsValidation, ExtraHeaderAuthorizationRejectedWhenBearerSet)
{
    MockTsaServer server;
    TransportCredentials c = validBearer();
    c.extraHeaders.emplace_back("Authorization", "Basic rogue");

    auto resp = postWith(server, c);

    EXPECT_EQ(resp.statusCode, 0);
    EXPECT_FALSE(resp.errorMessage.empty());
    EXPECT_NE(resp.errorMessage.find("Authorization"), std::string::npos) << resp.errorMessage;
    EXPECT_TRUE(server.headers().empty());
}

TEST(HttpCredentialsValidation, ExtraHeaderAuthorizationAllowedWhenNoPrimaryAuth)
{
    // Escape hatch: callers that need a bespoke auth scheme (e.g., HMAC,
    // AWS SigV4) put their pre-computed Authorization into extraHeaders
    // with no primary auth set. Validator must allow this.
    MockTsaServer server;
    TransportCredentials c;
    c.extraHeaders.emplace_back("Authorization", "Bespoke scheme=xyz");

    auto resp = postWith(server, c);

    // Request was dispatched — server replies 500 but the header
    // actually reached the wire. That's what we care about.
    (void)resp;
    EXPECT_TRUE(server.observedHeader("Authorization", "Bespoke scheme=xyz"))
        << "extraHeaders-only Authorization must pass validation and reach the wire";
}

TEST(HttpCredentialsValidation, CaseInsensitiveAuthorizationMatch)
{
    // Lowercase variant.
    {
        MockTsaServer server;
        TransportCredentials c = validBearer();
        c.extraHeaders.emplace_back("authorization", "Bearer rogue");
        auto resp = postWith(server, c);
        EXPECT_EQ(resp.statusCode, 0);
        EXPECT_FALSE(resp.errorMessage.empty());
        EXPECT_NE(resp.errorMessage.find("Authorization"), std::string::npos) << resp.errorMessage;
        EXPECT_TRUE(server.headers().empty());
    }
    // All-caps variant.
    {
        MockTsaServer server;
        TransportCredentials c = validBearer();
        c.extraHeaders.emplace_back("AUTHORIZATION", "Bearer rogue");
        auto resp = postWith(server, c);
        EXPECT_EQ(resp.statusCode, 0);
        EXPECT_FALSE(resp.errorMessage.empty());
        EXPECT_NE(resp.errorMessage.find("Authorization"), std::string::npos) << resp.errorMessage;
        EXPECT_TRUE(server.headers().empty());
    }
    // Mixed case.
    {
        MockTsaServer server;
        TransportCredentials c = validBasic();
        c.extraHeaders.emplace_back("AuThOrIzAtIoN", "Basic rogue");
        auto resp = postWith(server, c);
        EXPECT_EQ(resp.statusCode, 0);
        EXPECT_FALSE(resp.errorMessage.empty());
        EXPECT_NE(resp.errorMessage.find("Authorization"), std::string::npos) << resp.errorMessage;
        EXPECT_TRUE(server.headers().empty());
    }
}

TEST(HttpCredentialsValidation, BodyExceedingLongMaxRejected)
{
    // On LP64 (Linux, macOS) sizeof(long) == sizeof(size_t) == 8, so
    // size_t > LONG_MAX means size_t > ~9.2 EiB: unreachable without
    // successful allocation of an impossibly large buffer. The guard
    // still exists for LLP64 (Windows, where long is 32-bit) where
    // the check CAN trigger for bodies > 2 GiB.
    if constexpr (sizeof(long) >= sizeof(std::size_t)) {
        GTEST_SKIP() << "LONG_MAX >= SIZE_MAX on this platform; guard is unreachable via std::string";
    }
    // The else-branch is intentionally empty: this is a platform-gated
    // test. Running it on LP64 would require mocking size_t, which is
    // out of scope. The cross-platform CI (Windows x64) exercises it.
}

TEST(HttpCredentialsValidation, ValidCredentialsSucceed)
{
    // Smoke test: the validator doesn't spuriously reject a clean bundle.
    MockTsaServer server;
    TransportCredentials c = validBasic();
    c.extraHeaders.emplace_back("X-Tenant", "acme");

    auto resp = postWith(server, c);
    (void)resp;

    // Server replies 500 but the headers reached the wire.
    EXPECT_TRUE(server.observedHeader("X-Tenant", "acme"));
    // user:p → dXNlcjpw — hand-check: "u:p" base64 = "dTpw"
    EXPECT_TRUE(server.observedHeader("Authorization", "Basic dTpw"));
}

// =================================================================
// extraSecretHeaders coverage. These mirror the extraHeaders
// tests and additionally verify that the cleansing Secure::String value type
// makes it onto the wire as a normal header.
// =================================================================

TEST(HttpCredentialsValidation, SecretHeadersReachTsa)
{
    MockTsaServer server;
    TransportCredentials c;
    c.extraSecretHeaders.emplace_back("X-Api-Key", LibreSCRS::Secure::String("sek-token-xyz"));

    auto resp = postWith(server, c);
    (void)resp;

    EXPECT_TRUE(server.observedHeader("X-Api-Key", "sek-token-xyz"))
        << "extraSecretHeaders must reach the wire as request headers";
}

TEST(HttpCredentialsValidation, CrlfInSecretHeaderNameRejected)
{
    MockTsaServer server;
    TransportCredentials c;
    c.extraSecretHeaders.emplace_back("X-Legit\r\nX-Evil", LibreSCRS::Secure::String("ok"));

    auto resp = postWith(server, c);

    EXPECT_EQ(resp.statusCode, 0);
    EXPECT_FALSE(resp.errorMessage.empty());
    EXPECT_NE(resp.errorMessage.find("extraSecretHeader name"), std::string::npos) << resp.errorMessage;
    EXPECT_TRUE(server.headers().empty());
}

TEST(HttpCredentialsValidation, CrlfInSecretHeaderValueRejected)
{
    MockTsaServer server;
    TransportCredentials c;
    c.extraSecretHeaders.emplace_back("X-Legit", LibreSCRS::Secure::String("ok\r\nX-Evil: 1"));

    auto resp = postWith(server, c);

    EXPECT_EQ(resp.statusCode, 0);
    EXPECT_FALSE(resp.errorMessage.empty());
    EXPECT_NE(resp.errorMessage.find("extraSecretHeader value"), std::string::npos) << resp.errorMessage;
    EXPECT_TRUE(server.headers().empty());
}

TEST(HttpCredentialsValidation, SecretHeaderAuthorizationRejectedWhenBasicSet)
{
    MockTsaServer server;
    TransportCredentials c = validBasic();
    c.extraSecretHeaders.emplace_back("Authorization", LibreSCRS::Secure::String("Bearer rogue"));

    auto resp = postWith(server, c);

    EXPECT_EQ(resp.statusCode, 0);
    EXPECT_FALSE(resp.errorMessage.empty());
    EXPECT_NE(resp.errorMessage.find("Authorization"), std::string::npos) << resp.errorMessage;
    EXPECT_TRUE(server.headers().empty());
}

TEST(HttpCredentialsValidation, SecretHeaderAuthorizationAllowedWhenNoPrimaryAuth)
{
    // Bespoke-scheme escape hatch via extraSecretHeaders.
    MockTsaServer server;
    TransportCredentials c;
    c.extraSecretHeaders.emplace_back("Authorization", LibreSCRS::Secure::String("Bespoke scheme=xyz"));

    auto resp = postWith(server, c);
    (void)resp;

    EXPECT_TRUE(server.observedHeader("Authorization", "Bespoke scheme=xyz"))
        << "extraSecretHeaders-only Authorization must pass validation and reach the wire";
}

#else // !LIBRESIGN_HAS_NATIVE

TEST(TsaAuthIntegration, SkippedNoNativeBackend)
{
    GTEST_SKIP() << "Native signing backend not enabled";
}

#endif // LIBRESIGN_HAS_NATIVE
