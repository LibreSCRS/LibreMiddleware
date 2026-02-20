// SPDX-License-Identifier: GPL-3.0-or-later
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

    if (!data.empty()) {
        bytes.push_back(static_cast<uint8_t>(data.size()));
        bytes.insert(bytes.end(), data.begin(), data.end());
    }

    if (hasLe) {
        bytes.push_back(le);
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

APDUCommand selectByAID(const std::vector<uint8_t>& aid)
{
    return APDUCommand{
        .cla = 0x00,
        .ins = 0xA4,  // SELECT
        .p1 = 0x04,   // Select by DF name (AID)
        .p2 = 0x00,
        .data = aid,
        .le = 0,
        .hasLe = false
    };
}

APDUCommand selectByPath(uint8_t fileId1, uint8_t fileId2, uint8_t le)
{
    return APDUCommand{
        .cla = 0x00,
        .ins = 0xA4,  // SELECT
        .p1 = 0x08,   // Select by path from current DF
        .p2 = 0x00,
        .data = {fileId1, fileId2},
        .le = le,
        .hasLe = true
    };
}

APDUCommand selectByFileId(uint8_t fileId1, uint8_t fileId2)
{
    return APDUCommand{
        .cla = 0x00,
        .ins = 0xA4,  // SELECT
        .p1 = 0x00,   // Select by file identifier
        .p2 = 0x00,
        .data = {fileId1, fileId2},
        .le = 0,      // Le=0x00: expect up to 256 bytes of FCI data
        .hasLe = true
    };
}

APDUCommand readBinary(uint16_t offset, uint8_t length)
{
    return APDUCommand{
        .cla = 0x00,
        .ins = 0xB0,  // READ BINARY
        .p1 = static_cast<uint8_t>((offset >> 8) & 0x7F),
        .p2 = static_cast<uint8_t>(offset & 0xFF),
        .data = {},
        .le = length,
        .hasLe = true
    };
}

} // namespace smartcard
