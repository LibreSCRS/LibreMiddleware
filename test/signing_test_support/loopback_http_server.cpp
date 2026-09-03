// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "loopback_http_server.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <cctype>
#include <cstdlib>
#include <stdexcept>
#include <thread>

namespace libresign::test {

namespace {

/// Case-insensitive `Content-Length:` lookup over an HTTP header block.
long parseContentLength(const std::string& headers)
{
    std::string lower;
    lower.reserve(headers.size());
    for (char c : headers)
        lower.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));

    const auto pos = lower.find("content-length:");
    if (pos == std::string::npos)
        return -1;
    const auto valueStart = pos + std::string("content-length:").size();
    const auto lineEnd = lower.find("\r\n", valueStart);
    if (lineEnd == std::string::npos)
        return -1;
    return std::strtol(headers.substr(valueStart, lineEnd - valueStart).c_str(), nullptr, 10);
}

bool sendAll(int fd, const char* data, size_t len)
{
    size_t sent = 0;
    while (sent < len) {
        const ssize_t n = ::send(fd, data + sent, len - sent, 0);
        if (n <= 0)
            return false;
        sent += static_cast<size_t>(n);
    }
    return true;
}

} // namespace

struct LoopbackHttpServer::Impl
{
    int fd = -1;
    uint16_t boundPort = 0;
    std::thread worker;
    std::atomic<bool> stopFlag{false};
    std::atomic<int> served{0};
    std::string contentType;
    Handler handler;

    void handle(int client)
    {
        std::string acc;
        char buf[2048];
        while (acc.find("\r\n\r\n") == std::string::npos) {
            const ssize_t n = ::recv(client, buf, sizeof(buf), 0);
            if (n <= 0)
                return;
            acc.append(buf, static_cast<size_t>(n));
            if (acc.size() > 256 * 1024)
                return;
        }

        const auto headerEnd = acc.find("\r\n\r\n") + 4;
        const std::string headers = acc.substr(0, headerEnd);
        std::string body = acc.substr(headerEnd);

        // A GET carries no Content-Length; treat its absence as an empty body
        // rather than a protocol error, because a list is fetched, not posted.
        long contentLength = parseContentLength(headers);
        if (contentLength < 0)
            contentLength = 0;
        while (body.size() < static_cast<size_t>(contentLength)) {
            const ssize_t n = ::recv(client, buf, sizeof(buf), 0);
            if (n <= 0)
                return;
            body.append(buf, static_cast<size_t>(n));
        }
        body.resize(static_cast<size_t>(contentLength));

        const auto payload =
            handler(std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(body.data()), body.size()));
        if (payload.empty())
            return; // no reply — the client surfaces a transport failure

        // Counted before the write, not after: see servedCount().
        served.fetch_add(1);

        std::string reply = "HTTP/1.1 200 OK\r\nContent-Type: " + contentType +
                            "\r\nContent-Length: " + std::to_string(payload.size()) + "\r\nConnection: close\r\n\r\n";
        if (!sendAll(client, reply.data(), reply.size()))
            return;
        sendAll(client, reinterpret_cast<const char*>(payload.data()), payload.size());
    }

    void runLoop()
    {
        while (!stopFlag.load()) {
            const int client = ::accept(fd, nullptr, nullptr);
            if (client < 0) {
                if (stopFlag.load())
                    return;
                continue;
            }
            handle(client);
            ::close(client);
        }
    }
};

LoopbackHttpServer::LoopbackHttpServer(std::string contentType, Handler handler) : impl(std::make_unique<Impl>())
{
    impl->contentType = std::move(contentType);
    impl->handler = std::move(handler);

    impl->fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (impl->fd < 0)
        throw std::runtime_error("LoopbackHttpServer: socket() failed");
    int one = 1;
    ::setsockopt(impl->fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    if (::bind(impl->fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        ::close(impl->fd);
        throw std::runtime_error("LoopbackHttpServer: bind() failed");
    }
    if (::listen(impl->fd, 4) < 0) {
        ::close(impl->fd);
        throw std::runtime_error("LoopbackHttpServer: listen() failed");
    }

    sockaddr_in bound{};
    socklen_t len = sizeof(bound);
    if (::getsockname(impl->fd, reinterpret_cast<sockaddr*>(&bound), &len) < 0) {
        ::close(impl->fd);
        throw std::runtime_error("LoopbackHttpServer: getsockname() failed");
    }
    impl->boundPort = ntohs(bound.sin_port);

    Impl* raw = impl.get();
    impl->worker = std::thread([raw] { raw->runLoop(); });
}

LoopbackHttpServer::~LoopbackHttpServer()
{
    impl->stopFlag.store(true);
    if (impl->fd >= 0) {
        // Unblock the accept() the worker is parked in.
        const int wakeFd = ::socket(AF_INET, SOCK_STREAM, 0);
        if (wakeFd >= 0) {
            sockaddr_in addr{};
            addr.sin_family = AF_INET;
            addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            addr.sin_port = htons(impl->boundPort);
            ::connect(wakeFd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
            ::close(wakeFd);
        }
    }
    if (impl->worker.joinable())
        impl->worker.join();
    if (impl->fd >= 0) {
        ::close(impl->fd);
        impl->fd = -1;
    }
}

std::string LoopbackHttpServer::url(const std::string& path) const
{
    return "http://127.0.0.1:" + std::to_string(impl->boundPort) + path;
}

uint16_t LoopbackHttpServer::port() const
{
    return impl->boundPort;
}

int LoopbackHttpServer::servedCount() const
{
    return impl->served.load();
}

} // namespace libresign::test
