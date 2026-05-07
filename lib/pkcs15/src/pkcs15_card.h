// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

#include "pkcs15_types.h"

#include <smartcard/secure_buffer.h>

#include <cstdint>
#include <span>
#include <string>
#include <string_view>
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
    TokenInfo readTokenInfo(); // Lightweight: reads only EF(TokenInfo), no certs/keys/PINs
    std::vector<uint8_t> readCertificate(const CertificateInfo& cert);
    PinResult verifyPIN(const PinInfo& pin, std::string_view pinValue);
    PinResult changePIN(const PinInfo& pin, std::string_view oldPin, std::string_view newPin);
    int getPINTriesLeft(const PinInfo& pin);
    std::vector<uint8_t> sign(const PrivateKeyInfo& key, std::string_view pin, const PinInfo& pinInfo,
                              const std::vector<uint8_t>& digestInfo, const std::vector<uint8_t>& rawData,
                              SignScheme scheme);

private:
    struct KeyRefInfo
    {
        uint8_t keyTag;
        std::vector<uint8_t> keyRefData;
    };
    static KeyRefInfo resolveKeyRef(const PrivateKeyInfo& key);
    std::vector<uint8_t> tryMsePso(uint8_t sigAlgo, const KeyRefInfo& keyRef, const std::vector<uint8_t>& psoData,
                                   uint16_t expectedSigLen, uint16_t& lastSW);
    static smartcard::SecureBuffer encodePIN(std::string_view pin, const PinInfo& pinInfo);
    // Returns: 1=success, 0=wrong PIN (0x63Cx), -1=other failure
    int verifyPinInline(const PinInfo& pinInfo, const smartcard::SecureBuffer& pinData);
    static std::vector<uint8_t> extractRawHash(const std::vector<uint8_t>& digestInfo);
    bool selectByPath(std::span<const uint8_t> path, uint8_t selectP2 = 0x00);
    std::vector<uint8_t> readSelectedFile();
    bool probeViaEfDir(); // EF.DIR fallback: read MF/2F00, find PKCS#15 path

    smartcard::PCSCConnection& conn;
    std::vector<uint8_t> pkcs15Path; // Path discovered from EF.DIR (empty = use AID)
    uint8_t fileSelectP2 = 0x00;     // Discovered during probe/first selectByPath
};

} // namespace pkcs15
