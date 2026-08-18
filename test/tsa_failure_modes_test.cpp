// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <gtest/gtest.h>

#ifdef LIBRESIGN_HAS_NATIVE

#include "native/cades_module.h"
#include "native/pkcs11_module_manager.h"
#include "native/pkcs11_token.h"
#include "native/tsa_client.h"
#include "signing_service.h"
#include "signing_test_support/signing_test_support.h"
#include "types.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

using namespace libresign;

namespace {

// Configurable in-process HTTP/1.1 mock for TSA failure-mode tests.
//
// Behaviour matrix is controlled by @ref Mode:
//   - GarbageBody : reply 200 + "not-a-timestamp" body. TSAClient must
//                   fail to parse and return success=false.
//   - HangForever : accept the connection, never write a reply. Lets the
//                   client trip its own request timeout.
//   - Close       : close the connection mid-read so libcurl reports a
//                   transport error.
class MockHttpServer
{
public:
    enum class Mode { GarbageBody, HangForever, Close };

    explicit MockHttpServer(Mode m) : mode(m)
    {
        fd = ::socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0)
            throw std::runtime_error("socket() failed");
        int one = 1;
        ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = 0;
        if (::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
            ::close(fd);
            throw std::runtime_error("bind() failed");
        }
        if (::listen(fd, 4) < 0) {
            ::close(fd);
            throw std::runtime_error("listen() failed");
        }
        sockaddr_in bound{};
        socklen_t len = sizeof(bound);
        if (::getsockname(fd, reinterpret_cast<sockaddr*>(&bound), &len) < 0) {
            ::close(fd);
            throw std::runtime_error("getsockname() failed");
        }
        boundPort = ntohs(bound.sin_port);
        worker = std::thread([this] { runLoop(); });
    }

    ~MockHttpServer()
    {
        stopFlag.store(true);
        if (fd >= 0) {
            int wakeFd = ::socket(AF_INET, SOCK_STREAM, 0);
            if (wakeFd >= 0) {
                sockaddr_in addr{};
                addr.sin_family = AF_INET;
                addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
                addr.sin_port = htons(boundPort);
                ::connect(wakeFd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
                ::close(wakeFd);
            }
            ::close(fd);
            fd = -1;
        }
        if (worker.joinable())
            worker.join();
        std::lock_guard<std::mutex> lock(heldMutex);
        for (int held : heldClients)
            ::close(held);
        heldClients.clear();
    }

    uint16_t port() const
    {
        return boundPort;
    }

private:
    void runLoop()
    {
        while (!stopFlag.load()) {
            int client = ::accept(fd, nullptr, nullptr);
            if (client < 0) {
                if (stopFlag.load())
                    return;
                continue;
            }
            handle(client);
        }
    }

    void handle(int client)
    {
        // Drain the request headers so libcurl finishes sending.
        char buf[1024];
        std::string acc;
        while (acc.find("\r\n\r\n") == std::string::npos) {
            ssize_t n = ::recv(client, buf, sizeof(buf), 0);
            if (n <= 0)
                break;
            acc.append(buf, static_cast<size_t>(n));
            if (acc.size() > 64 * 1024)
                break;
        }

        switch (mode) {
        case Mode::GarbageBody: {
            const std::string body = "definitely-not-a-timestamp-response";
            std::string reply = "HTTP/1.1 200 OK\r\nContent-Type: application/timestamp-reply\r\n"
                                "Content-Length: " +
                                std::to_string(body.size()) + "\r\nConnection: close\r\n\r\n" + body;
            ::send(client, reply.data(), reply.size(), 0);
            ::close(client);
            break;
        }
        case Mode::HangForever:
            // Keep the connection alive but never write — let the client
            // timeout. The destructor closes any held fds on tear-down.
            {
                std::lock_guard<std::mutex> lock(heldMutex);
                heldClients.push_back(client);
            }
            break;
        case Mode::Close:
            ::close(client);
            break;
        }
    }

    int fd = -1;
    uint16_t boundPort = 0;
    Mode mode;
    std::thread worker;
    std::atomic<bool> stopFlag{false};
    std::mutex heldMutex;
    std::vector<int> heldClients;
};

std::vector<uint8_t> fakeHash()
{
    return std::vector<uint8_t>(32, 0x42);
}

} // namespace

// ---- TSA failure modes ----

TEST(TSAClient, BodyNotTimeStampResp_Fails)
{
    MockHttpServer server(MockHttpServer::Mode::GarbageBody);
    TSARequest req;
    req.url = "http://127.0.0.1:" + std::to_string(server.port()) + "/tsa";
    req.timeoutSeconds = 5;

    TSAClient client;
    auto result = client.timestamp(fakeHash(), req);
    EXPECT_FALSE(result.success) << "TSAClient must reject a non-TimeStampResp body";
    EXPECT_FALSE(result.errorMessage.empty());
}

TEST(TSAClient, UnreachableUrl_ReturnsErrorPromptly)
{
    // 127.0.0.1:1 is reserved (TCPMUX) and almost always unbound on dev
    // machines — libcurl gets immediate ECONNREFUSED rather than hanging.
    TSARequest req;
    req.url = "http://127.0.0.1:1/tsa";
    req.timeoutSeconds = 30;

    auto before = std::chrono::steady_clock::now();
    TSAClient client;
    auto result = client.timestamp(fakeHash(), req);
    auto elapsed = std::chrono::steady_clock::now() - before;

    EXPECT_FALSE(result.success);
    EXPECT_FALSE(result.errorMessage.empty());
    // Must surface the connection-refused failure well below the configured
    // 30-second timeout; loopback ECONNREFUSED is sub-second on Linux.
    EXPECT_LT(std::chrono::duration_cast<std::chrono::seconds>(elapsed).count(), 5)
        << "Unreachable URL must surface immediately, not wait out timeoutSeconds";
}

TEST(TSAClient, Timeout_ExceedsConfigured)
{
    MockHttpServer server(MockHttpServer::Mode::HangForever);
    TSARequest req;
    req.url = "http://127.0.0.1:" + std::to_string(server.port()) + "/tsa";
    req.timeoutSeconds = 2;

    auto before = std::chrono::steady_clock::now();
    TSAClient client;
    auto result = client.timestamp(fakeHash(), req);
    auto elapsed = std::chrono::steady_clock::now() - before;

    EXPECT_FALSE(result.success);
    EXPECT_FALSE(result.errorMessage.empty());
    // Must trip the request timeout within a small margin above the
    // configured ceiling.
    auto seconds = std::chrono::duration_cast<std::chrono::seconds>(elapsed).count();
    EXPECT_GE(seconds, 1) << "Should have waited at least 1 second for a hanging server";
    EXPECT_LT(seconds, 10) << "Should have timed out well before 10 seconds";
}

// ---- OCSP fail-clean placeholder ----
//
// SigningRevocation::OcspUnreachable_BLT_FailsClean requires injecting a
// mock OCSP responder URL into a signer cert's AIA extension AND a live
// PKCS#11 token to drive @c PAdESModule::sign through the LT path; that
// shape needs the same dependency-injection plumbing as the cancellation
// tests (see test/cancellation_test.cpp). Kept as a SKIPPED placeholder so
// the coverage gap stays visible.
TEST(SigningRevocation, OcspUnreachable_BLT_FailsClean)
{
    GTEST_SKIP() << "Requires injecting mock OCSP responder URL into signer cert AIA + "
                    "mockable Pkcs11Token (see test/signing_test_support/pkcs11_token_mock.h)";
}

// ---- Module-level B-T missing-TSA contract ----
//
// @c CAdESModule::addTimestamp throws when @c TSAConfig::url is empty;
// @c PAdESModule::sign delegates to it for B-T+. The standalone tests
// here exercise that contract without going through the full sign path,
// so they don't need a token.

TEST(PAdESModuleStandalone, BTRequiresTSA)
{
    // PAdES B-T delegates the timestamp embed to CAdESModule::addTimestamp,
    // which throws on an empty TSA URL. Without a token we can't drive the
    // full PAdES sign() path, so the contract is exercised at the delegate.
    CAdESModule cades;
    TSAConfig tsa; // empty url
    std::vector<uint8_t> fakeCms{0x30, 0x00};
    EXPECT_THROW(
        { cades.addTimestamp(fakeCms, tsa); }, std::runtime_error)
        << "B-T addTimestamp must throw when TSA URL is empty";
}

TEST(CAdESModuleStandalone, BTRequiresTSA)
{
    CAdESModule cades;
    TSAConfig tsa; // empty url
    std::vector<uint8_t> fakeCms{0x30, 0x00};
    EXPECT_THROW(
        { cades.addTimestamp(fakeCms, tsa); }, std::runtime_error)
        << "B-T addTimestamp must throw when TSA URL is empty";
}

// ---- CAdES sign() failure-kind classification for a failing TSA ----
//
// A reachable-but-failing TSA must surface from CAdESModule::sign as
// SignFailureKind::TsaUnreachable, the same classification the XAdES, JAdES
// and PAdES paths already produce for the equivalent timestamp-step failure.
// MockHttpServer (GarbageBody) replies HTTP 200 with a body that is not a
// TimeStampResp, so TSAClient parses it and reports failure — driving the
// addTimestamp throw inside sign() without any live network. signBB still
// needs a real token, so this is SoftHSM-gated like the other module tests.
TEST(CAdESSignClassification, BT_TsaFailure_IsTsaUnreachable)
{
    const char* softHsmPath = libresign::test::findSoftHsmPath();
    if (!softHsmPath)
        GTEST_SKIP() << "SoftHSM2 not found";

    libresign::Pkcs11ModuleManager manager;
    auto slot = libresign::test::findSoftHsmTestSlot(manager.acquire(softHsmPath));
    if (!slot)
        GTEST_SKIP() << "SoftHSM2 token '" << libresign::test::kSoftHsmTokenLabel << "' not initialised";

    Pkcs11Token token(manager.acquire(softHsmPath), libresign::as_pin("1234"), "test-key",
                      libresign::Pkcs11Token::TestSlotId{*slot});

    MockHttpServer server(MockHttpServer::Mode::GarbageBody);
    TSAConfig tsa;
    tsa.url = "http://127.0.0.1:" + std::to_string(server.port()) + "/tsa";
    tsa.timeoutSeconds = 5;

    CAdESModule cades;
    std::vector<uint8_t> data = {'H', 'e', 'l', 'l', 'o'};
    auto result = cades.sign(data, token, SignatureLevel::B_T, tsa);

    ASSERT_FALSE(result.success);
    EXPECT_EQ(result.failureKind, SignFailureKind::TsaUnreachable)
        << "B-T TSA round-trip failure must classify as TsaUnreachable, got kind="
        << (result.failureKind ? static_cast<int>(*result.failureKind) : -1) << " msg=" << result.errorMessage;
}

// ---- CAdES timestamp-step typed-failure partition ----
//
// CAdESModule::sign discriminates the throws from addTimestamp /
// addArchiveTimestamp by exception TYPE, not by message: a TSA failure (missing
// URL or failed RFC 3161 round-trip) throws SignFailureException carrying a
// precise SignFailureKind (InvalidInput for the missing URL, TsaUnreachable for
// a failed round-trip), which sign()'s typed catch arm maps straight through.
// Every other throw (malformed SignerInfo, CMS parse / encode, OpenSSL) is a
// plain std::runtime_error (NOT a SignFailureException) and falls through to the
// generic arm -> EngineError. These token-free helper-level tests pin that type
// partition so a refactor can't silently mis-classify an internal fault as
// TsaUnreachable (or vice versa). The SoftHSM CI host additionally exercises the
// TSA-failure -> TsaUnreachable branch via
// CAdESSignClassification.BT_TsaFailure_IsTsaUnreachable above.

TEST(CAdESTimestampPartition, MissingUrlThrowsTypedInvalidInput)
{
    CAdESModule cades;
    TSAConfig tsa; // empty url
    std::vector<uint8_t> fakeCms{0x30, 0x00};

    bool threw = false;
    try {
        cades.addTimestamp(fakeCms, tsa);
    } catch (const libresign::SignFailureException& e) {
        threw = true;
        EXPECT_EQ(e.kind, SignFailureKind::InvalidInput)
            << "missing-TSA-URL must throw a typed InvalidInput, msg=" << e.what();
    }
    EXPECT_TRUE(threw) << "addTimestamp must throw SignFailureException on an empty TSA URL";

    threw = false;
    try {
        cades.addArchiveTimestamp(fakeCms, tsa);
    } catch (const libresign::SignFailureException& e) {
        threw = true;
        EXPECT_EQ(e.kind, SignFailureKind::InvalidInput)
            << "missing-TSA-URL must throw a typed InvalidInput, msg=" << e.what();
    }
    EXPECT_TRUE(threw) << "addArchiveTimestamp must throw SignFailureException on an empty TSA URL";
}

TEST(CAdESTimestampPartition, InternalFaultIsNotTypedFailure)
{
    CAdESModule cades;
    TSAConfig tsa;
    tsa.url = "http://127.0.0.1:1/tsa"; // non-empty: get past the URL guard
    // A non-CMS body forces an internal parse fault inside the helper, after
    // the URL guard and before any TSA round-trip — the same shape as the
    // SignerInfo / CMS / OpenSSL throws that must stay EngineError. It must be a
    // plain std::exception, NOT a SignFailureException, so sign()'s generic
    // catch arm maps it to EngineError.
    std::vector<uint8_t> garbageCms{0x01, 0x02, 0x03, 0x04};

    bool threwTyped = false;
    bool threwPlain = false;
    try {
        cades.addTimestamp(garbageCms, tsa);
    } catch (const libresign::SignFailureException&) {
        threwTyped = true;
    } catch (const std::exception&) {
        threwPlain = true;
    }
    EXPECT_FALSE(threwTyped) << "internal (non-TSA) fault must NOT be a typed SignFailureException";
    EXPECT_TRUE(threwPlain) << "addTimestamp must throw a plain exception on a malformed CMS";

    threwTyped = false;
    threwPlain = false;
    try {
        cades.addArchiveTimestamp(garbageCms, tsa);
    } catch (const libresign::SignFailureException&) {
        threwTyped = true;
    } catch (const std::exception&) {
        threwPlain = true;
    }
    EXPECT_FALSE(threwTyped) << "internal (non-TSA) fault must NOT be a typed SignFailureException";
    EXPECT_TRUE(threwPlain) << "addArchiveTimestamp must throw a plain exception on a malformed CMS";
}

#else
TEST(TSAClient, DISABLED_SkippedNativeNotCompiled)
{
    GTEST_SKIP();
}
#endif
