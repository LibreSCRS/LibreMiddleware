// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright hirashix0@proton.me

#ifndef SMARTCARD_APDU_H
#define SMARTCARD_APDU_H

#include <cstdint>
#include <vector>

namespace smartcard {

struct APDUCommand {
    uint8_t cla, ins, p1, p2;
    std::vector<uint8_t> data;  // Lc data (empty = no data field)
    uint8_t le = 0;             // Expected response length (0 = 256)
    bool hasLe = true;

    std::vector<uint8_t> toBytes() const;
};

struct APDUResponse {
    std::vector<uint8_t> data;
    uint8_t sw1, sw2;

    bool isSuccess() const;
    uint16_t statusWord() const;
};

// Builders for common ISO 7816-4 commands
APDUCommand selectByAID(const std::vector<uint8_t>& aid);
APDUCommand selectByPath(uint8_t fileId1, uint8_t fileId2, uint8_t le = 4);
APDUCommand selectByFileId(uint8_t fileId1, uint8_t fileId2);
APDUCommand readBinary(uint16_t offset, uint8_t length);

} // namespace smartcard

#endif // SMARTCARD_APDU_H
