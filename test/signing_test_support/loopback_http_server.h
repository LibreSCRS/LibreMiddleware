// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <span>
#include <string>
#include <vector>

namespace libresign::test {

/// @brief Single-threaded loopback HTTP responder for tests.
///
/// Binds an ephemeral port on the loopback interface and hands every request
/// body to @p handler, whose return value is sent back verbatim as the
/// response body under @p contentType. An empty return closes the connection
/// without a reply, which the client reports as a transport error. Nothing
/// leaves loopback; one request is served at a time.
///
/// Three responders need exactly this shape — a timestamp authority, a
/// revocation list and a trusted list — so the socket half lives here and each
/// of them keeps only its protocol.
class LoopbackHttpServer
{
public:
    using Handler = std::function<std::vector<uint8_t>(std::span<const uint8_t> requestBody)>;

    /// @throws std::runtime_error when the listener cannot be created.
    LoopbackHttpServer(std::string contentType, Handler handler);
    ~LoopbackHttpServer();

    LoopbackHttpServer(const LoopbackHttpServer&) = delete;
    LoopbackHttpServer& operator=(const LoopbackHttpServer&) = delete;

    /// Endpoint, with @p path appended (leading slash included in @p path).
    [[nodiscard]] std::string url(const std::string& path = "/") const;

    /// Bound loopback port.
    [[nodiscard]] uint16_t port() const;

    /// Requests answered so far. Lets a test prove the responder was actually
    /// reached rather than inferring it from a downstream success.
    ///
    /// Incremented BEFORE the reply is written, deliberately. Counting after
    /// the write is a race the client always wins: it can receive the whole
    /// response, finish the operation and read this counter while the
    /// responder thread has not yet retired the increment. Measured on the
    /// timestamp responder this class was lifted out of: one failure in three
    /// runs, in two different suites.
    [[nodiscard]] int servedCount() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl;
};

} // namespace libresign::test
