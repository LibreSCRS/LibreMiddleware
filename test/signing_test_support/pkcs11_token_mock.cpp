// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "pkcs11_token_mock.h"

#include <stdexcept>
#include <string>

namespace libresign::test {

std::vector<uint8_t> MockPkcs11Token::sign(std::span<const uint8_t> /*hash*/, const std::string& /*algorithm*/,
                                           std::span<const uint8_t> /*rawData*/)
{
    if (errorOnSign != 0)
        throw std::runtime_error("PKCS#11 error: 0x" + std::to_string(errorOnSign));
    return signValue;
}

std::vector<uint8_t> MockPkcs11Token::certificate() const
{
    return cert;
}

std::vector<std::vector<uint8_t>> MockPkcs11Token::certificateChain() const
{
    return chain;
}

} // namespace libresign::test
