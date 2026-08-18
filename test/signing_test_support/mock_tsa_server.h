// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

#include <cstdint>
#include <memory>
#include <string>

namespace libresign::test {

/// @brief In-process RFC 3161 Time-Stamp Authority for tests.
///
/// Binds a loopback listener on an ephemeral port and answers every
/// `application/timestamp-query` POST with a granted, DER-encoded
/// `TimeStampResp` built through OpenSSL's responder API
/// (`TS_RESP_CTX` / `TS_RESP_create_response`). The signing identity is an
/// RSA-2048 self-signed certificate generated in the constructor carrying a
/// critical `id-kp-timeStamping` extended key usage — OpenSSL refuses to
/// install a signer certificate without it — so the harness needs no fixture
/// files and no key material in the tree.
///
/// The responder echoes the request's nonce and message imprint and stamps a
/// serial and genTime, which is what @ref libresign::TSAClient checks before
/// accepting a token (RFC 3161 §2.4.2). The signature is NOT anchored in any
/// trust store: the format modules embed the returned token verbatim, so a
/// self-signed authority is enough to exercise every code path that runs
/// AFTER the timestamp step — which is the point of the class. It is a
/// stand-in for a timestamp service, not for a trusted one.
///
/// Nothing leaves the loopback interface. One request is served at a time.
class MockTsaServer
{
public:
    /// @throws std::runtime_error when the listener or the signing identity
    ///         cannot be created.
    MockTsaServer();
    ~MockTsaServer();

    MockTsaServer(const MockTsaServer&) = delete;
    MockTsaServer& operator=(const MockTsaServer&) = delete;

    /// Endpoint to assign to @c TSAConfig::url.
    [[nodiscard]] std::string url() const;

    /// Bound loopback port.
    [[nodiscard]] uint16_t port() const;

    /// Number of timestamp requests answered so far. Lets a test prove the
    /// responder was actually reached rather than inferring it from a
    /// downstream success.
    [[nodiscard]] int servedCount() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl;
};

} // namespace libresign::test
