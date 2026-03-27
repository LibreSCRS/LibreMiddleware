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

private:
    smartcard::PCSCConnection& conn;

    // Send GET DATA for a PIV object. Returns response data, or empty on error.
    std::vector<uint8_t> getData(std::span<const uint8_t> objectTag);
};

} // namespace piv
