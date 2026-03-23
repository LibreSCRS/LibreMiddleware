// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright hirashix0@proton.me

#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace cardedge {

struct CertificateData
{
    std::string label;
    std::vector<uint8_t> derBytes;
    uint16_t keyFID = 0;      // private key FID on PKI applet (0 if not available)
    uint16_t keySizeBits = 0; // key size in bits from cmapfile (0 if unknown)
};

using CertificateList = std::vector<CertificateData>;

struct PINResult
{
    bool success = false;
    int retriesLeft = -1; // -1 = unknown
    bool blocked = false;
};

} // namespace cardedge
