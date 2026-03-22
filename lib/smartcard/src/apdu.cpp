// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright hirashix0@proton.me

#include "smartcard/apdu.h"

namespace smartcard {

std::vector<uint8_t> APDUCommand::toBytes() const
{
    std::vector<uint8_t> bytes;
    bytes.push_back(cla);
    bytes.push_back(ins);
    bytes.push_back(p1);
    bytes.push_back(p2);

    // ISO 7816-4: short form supports Lc/Nc up to 255.
    // When data.size() > 255, use extended form: 0x00 followed by 2-byte length.
    const bool useExtended = (data.size() > 255);

    if (!data.empty()) {
        if (!useExtended) {
            bytes.push_back(static_cast<uint8_t>(data.size()));
        } else {
            bytes.push_back(0x00);
            bytes.push_back(static_cast<uint8_t>((data.size() >> 8) & 0xFF));
            bytes.push_back(static_cast<uint8_t>(data.size() & 0xFF));
        }
        bytes.insert(bytes.end(), data.begin(), data.end());
    }

    if (hasLe) {
        if (useExtended) {
            // Extended Le: le==0 (short form = "up to 256") → 0x01 0x00 (256 bytes).
            uint16_t extLe = (le == 0) ? 256u : static_cast<uint16_t>(le);
            bytes.push_back(static_cast<uint8_t>(extLe >> 8));
            bytes.push_back(static_cast<uint8_t>(extLe & 0xFF));
        } else {
            bytes.push_back(le);
        }
    }

    return bytes;
}

bool APDUResponse::isSuccess() const
{
    return sw1 == 0x90 && sw2 == 0x00;
}

uint16_t APDUResponse::statusWord() const
{
    return static_cast<uint16_t>((sw1 << 8) | sw2);
}

APDUCommand selectByAID(const std::vector<uint8_t>& aid, uint8_t p2)
{
    return APDUCommand{.cla = 0x00,
                       .ins = 0xA4, // SELECT
                       .p1 = 0x04,  // Select by DF name (AID)
                       .p2 = p2,
                       .data = aid,
                       .le = 0,
                       .hasLe = false};
}

APDUCommand selectByPath(uint8_t fileId1, uint8_t fileId2, uint8_t le)
{
    return APDUCommand{.cla = 0x00,
                       .ins = 0xA4, // SELECT
                       .p1 = 0x08,  // Select by path from current DF
                       .p2 = 0x00,
                       .data = {fileId1, fileId2},
                       .le = le,
                       .hasLe = true};
}

APDUCommand selectByFileId(uint8_t fileId1, uint8_t fileId2, uint8_t p2)
{
    return APDUCommand{.cla = 0x00,
                       .ins = 0xA4, // SELECT
                       .p1 = 0x00,  // Select by file identifier
                       .p2 = p2,
                       .data = {fileId1, fileId2},
                       .le = 0,
                       .hasLe = (p2 != 0x0C)};
}

APDUCommand readBinary(uint16_t offset, uint8_t length)
{
    return APDUCommand{.cla = 0x00,
                       .ins = 0xB0, // READ BINARY
                       .p1 = static_cast<uint8_t>((offset >> 8) & 0x7F),
                       .p2 = static_cast<uint8_t>(offset & 0xFF),
                       .data = {},
                       .le = length,
                       .hasLe = true};
}

APDUCommand verifyPIN(uint8_t pinRef, const std::vector<uint8_t>& pin)
{
    return APDUCommand{.cla = 0x00,
                       .ins = 0x20, // VERIFY
                       .p1 = 0x00,
                       .p2 = pinRef,
                       .data = pin,
                       .le = 0,
                       .hasLe = false};
}

APDUCommand verifyPINStatus(uint8_t pinRef)
{
    return APDUCommand{.cla = 0x00,
                       .ins = 0x20, // VERIFY (no data = status check)
                       .p1 = 0x00,
                       .p2 = pinRef,
                       .data = {},
                       .le = 0,
                       .hasLe = false};
}

APDUCommand changeReferenceData(uint8_t pinRef, const std::vector<uint8_t>& oldPin, const std::vector<uint8_t>& newPin)
{
    std::vector<uint8_t> data;
    data.reserve(oldPin.size() + newPin.size());
    data.insert(data.end(), oldPin.begin(), oldPin.end());
    data.insert(data.end(), newPin.begin(), newPin.end());

    return APDUCommand{.cla = 0x00,
                       .ins = 0x24, // CHANGE REFERENCE DATA
                       .p1 = 0x00,
                       .p2 = pinRef,
                       .data = std::move(data),
                       .le = 0,
                       .hasLe = false};
}

} // namespace smartcard
