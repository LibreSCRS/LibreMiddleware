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

    bool probe();        // Try AID SELECT, then EF.DIR fallback
    bool selectApplet(); // Re-select using the method that worked in probe()
    PKCS15Profile readProfile();
    std::vector<uint8_t> readCertificate(const CertificateInfo& cert);
    PinResult verifyPIN(const PinInfo& pin, const std::string& pinValue);
    PinResult changePIN(const PinInfo& pin, const std::string& oldPin, const std::string& newPin);
    int getPINTriesLeft(const PinInfo& pin);

private:
    bool selectByPath(std::span<const uint8_t> path, uint8_t selectP2 = 0x00);
    std::vector<uint8_t> readSelectedFile();
    bool probeViaEfDir(); // EF.DIR fallback: read MF/2F00, find PKCS#15 path

    smartcard::PCSCConnection& conn;
    std::vector<uint8_t> pkcs15Path; // Path discovered from EF.DIR (empty = use AID)
    uint8_t fileSelectP2 = 0x00;     // Discovered during probe/first selectByPath
};

} // namespace pkcs15
