// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "mock_trusted_list_server.h"

#include <fstream>
#include <iterator>
#include <stdexcept>

namespace libresign::test {

MockTrustedListServer::MockTrustedListServer(const std::string& xmlPath)
{
    std::ifstream in(xmlPath, std::ios::binary);
    if (!in)
        throw std::runtime_error("MockTrustedListServer: cannot open " + xmlPath);
    xml.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
    if (xml.empty())
        throw std::runtime_error("MockTrustedListServer: empty trusted list at " + xmlPath);

    const std::vector<uint8_t>* body = &xml;
    http = std::make_unique<LoopbackHttpServer>("application/xml", [body](std::span<const uint8_t>) { return *body; });
}

MockTrustedListServer::~MockTrustedListServer() = default;

std::string MockTrustedListServer::url() const
{
    return http->url("/tl");
}

int MockTrustedListServer::servedCount() const
{
    return http->servedCount();
}

} // namespace libresign::test
