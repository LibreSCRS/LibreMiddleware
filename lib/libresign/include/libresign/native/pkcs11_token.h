// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <vector>

namespace libresign {

class Pkcs11Token
{
public:
    // pin: byte view into caller-owned, caller-cleansed storage. The token
    // does not retain the view past construction; the bytes are passed
    // straight to C_Login which copies them into the PKCS#11 module.
    Pkcs11Token(const std::string& modulePath, std::span<const uint8_t> pin, const std::string& keyAlias,
                int slotIndex = -1);
    Pkcs11Token(const std::string& modulePath, std::span<const uint8_t> pin, const std::string& keyAlias,
                const std::string& tokenLabel);
    ~Pkcs11Token();

    Pkcs11Token(const Pkcs11Token&) = delete;
    Pkcs11Token& operator=(const Pkcs11Token&) = delete;

    std::vector<uint8_t> sign(std::span<const uint8_t> hash, const std::string& algorithm = "SHA256withRSA");
    std::vector<uint8_t> certificate() const;
    std::vector<std::vector<uint8_t>> certificateChain() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl;
};

} // namespace libresign
