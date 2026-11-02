// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace libresign::test {

/// @brief In-process RFC 3161 Time-Stamp Authority for tests.
///
/// Binds a loopback listener on an ephemeral port and answers every
/// `application/timestamp-query` POST with a granted, DER-encoded
/// `TimeStampResp` built through OpenSSL's responder API
/// (`TS_RESP_CTX` / `TS_RESP_create_response`). The responder echoes the
/// request's nonce and message imprint and stamps a serial and genTime.
///
/// Which key signs the token is the constructor's choice:
///
/// - @ref Authority::Anchored (the default): an RSA-2048 certificate issued
///   once per process by the test Trusted-List key
///   (`test/fixtures/trust/test-tl-signing-key.pem`) and shared by every
///   instance. Its tokens verify against @ref trustAnchor, which a test hands
///   to the client directly, and against `test/fixtures/trust/tsa-tl.xml`,
///   which lists that certificate as a qualified time-stamping service.
/// - @ref Authority::Unanchored: a self-signed certificate generated for this
///   instance alone, which no anchor vouches for — an authority the client
///   must refuse even though the nonce and imprint it echoes are right.
///
/// Either certificate carries a critical `id-kp-timeStamping` extended key
/// usage; OpenSSL refuses to install a signer certificate without it.
///
/// Nothing leaves the loopback interface. One request is served at a time.
class MockTsaServer
{
public:
    enum class Authority { Anchored, Unanchored };

    /// @throws std::runtime_error when the listener or the signing identity
    ///         cannot be created.
    explicit MockTsaServer(Authority authority = Authority::Anchored);
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

    /// DER of the certificate that issued the anchored authority's: the
    /// anchor its tokens chain to.
    [[nodiscard]] static std::vector<std::uint8_t> trustAnchor();

    /// DER of the anchored authority's own certificate, for a test that
    /// trusts it as it is, the way a Trusted List can name the unit itself.
    [[nodiscard]] static std::vector<std::uint8_t> anchoredCertificate();

private:
    struct Impl;
    std::unique_ptr<Impl> impl;
};

} // namespace libresign::test
