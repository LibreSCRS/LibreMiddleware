// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

#include <pkcs15/pkcs15_types.h>

#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace smartcard {
class PCSCConnection;
}

namespace pkcs15 {

class PKCS15Card
{
public:
    explicit PKCS15Card(smartcard::PCSCConnection& conn);

    bool probe();
    bool selectApplet();
    PKCS15Profile readProfile();
    std::vector<uint8_t> readCertificate(const CertificateInfo& cert);
    PinResult verifyPIN(const PinInfo& pin, const std::string& pinValue);
    int getPINTriesLeft(const PinInfo& pin);

private:
    bool selectByPath(std::span<const uint8_t> path);
    std::vector<uint8_t> readSelectedFile();

    smartcard::PCSCConnection& conn;
};

} // namespace pkcs15
