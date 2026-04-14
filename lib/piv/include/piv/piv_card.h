// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

#include <piv/piv_types.h>
#include <plugin/card_plugin.h>

#include <span>
#include <string>
#include <utility>
#include <vector>

namespace smartcard {
class PCSCConnection;
}

namespace piv {

class PIVCard
{
public:
    explicit PIVCard(smartcard::PCSCConnection& conn);

    bool probe();

    PIVData readAll();

    CCCInfo readCCC();
    CHUIDInfo readCHUID();
    DiscoveryInfo readDiscovery();
    std::optional<PrintedInfo> readPrintedInfo();
    std::optional<KeyHistoryInfo> readKeyHistory();

    std::vector<PIVCertificate> readCertificates();

    std::vector<PINInfo> discoverPINs();
    plugin::PINResult verifyPIN(uint8_t keyRef, const std::string& pin);
    int getPINTriesLeft(uint8_t keyRef);

    std::vector<std::pair<std::string, uint16_t>> discoverKeys();

    // Sign data using GENERAL AUTHENTICATE.
    // keyRef: 0x9A/0x9C/0x9D/0x9E, algId: PIV algorithm (0x07=RSA-2048, 0x05=3DES, etc.)
    // keySizeBytes: RSA modulus size in bytes (e.g. 256 for RSA-2048)
    // data: DER DigestInfo (will be PKCS#1 v1.5 padded to keySizeBytes)
    std::vector<uint8_t> signData(uint8_t keyRef, uint8_t algId, size_t keySizeBytes, const std::vector<uint8_t>& data);

private:
    smartcard::PCSCConnection& conn;

    // Send GET DATA for a PIV object. Returns response data, or empty on error.
    std::vector<uint8_t> getData(std::span<const uint8_t> objectTag);
};

} // namespace piv
