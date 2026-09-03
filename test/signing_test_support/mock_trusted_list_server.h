// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

#include "loopback_http_server.h"

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace libresign::test {

/// @brief Serves a signed ETSI Trusted List over loopback.
///
/// Answers every request with the bytes of the file it was handed — normally
/// `test/fixtures/trust/synthetic-tl.xml`, which is committed already signed so
/// no test needs xmlsec1 at run time. Pair it with a @c TrustedListEntry whose
/// @c signingCertPath names the matching test certificate: the loopback URL has
/// no pinned entry, so without that field the engine refuses the list before it
/// verifies anything and a fetch-count assertion passes for the wrong reason.
class MockTrustedListServer
{
public:
    /// @param xmlPath Path to a signed Trusted List XML.
    /// @throws std::runtime_error when the file cannot be read or the listener
    ///         cannot be created.
    explicit MockTrustedListServer(const std::string& xmlPath);
    ~MockTrustedListServer();

    MockTrustedListServer(const MockTrustedListServer&) = delete;
    MockTrustedListServer& operator=(const MockTrustedListServer&) = delete;

    /// Endpoint to assign to @c TrustedListEntry::url.
    [[nodiscard]] std::string url() const;

    /// Requests answered so far.
    [[nodiscard]] int servedCount() const;

private:
    std::vector<uint8_t> xml;
    std::unique_ptr<LoopbackHttpServer> http;
};

} // namespace libresign::test
