// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "apdu.h"

namespace LibreSCRS::SmartCard::Internal {

std::vector<uint8_t> APDUCommand::toBytes() const
{
    std::vector<uint8_t> bytes;
    bytes.push_back(cla);
    bytes.push_back(ins);
    bytes.push_back(p1);
    bytes.push_back(p2);

    // ISO 7816-4: short form supports Lc/Nc up to 255 and Le/Ne up to 256.
    // When data or expected response exceeds short limits, use extended form.
    const bool useExtended = (data.size() > 255) || (hasLe && le > 256);

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
        if (useExtended || le > 0xFF) {
            // Extended Le: 2-byte encoding
            if (data.empty() && !useExtended) {
                // Case 2 extended: no data, need 0x00 marker before Le
                bytes.push_back(0x00);
            }
            uint16_t extLe = (le == 0) ? 256u : le;
            bytes.push_back(static_cast<uint8_t>(extLe >> 8));
            bytes.push_back(static_cast<uint8_t>(extLe & 0xFF));
        } else {
            bytes.push_back(static_cast<uint8_t>(le));
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

APDUCommand verifyPIN(uint8_t pinRef, std::span<const uint8_t> pin)
{
    return APDUCommand{.cla = 0x00,
                       .ins = 0x20, // VERIFY
                       .p1 = 0x00,
                       .p2 = pinRef,
                       .data = {pin.begin(), pin.end()},
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
                       .hasLe = true}; // Le required for SM — Case 1 (no Le) triggers 6988 on some cards
}

APDUCommand getDataDocp(uint8_t orf)
{
    // 00 CB 3F FF | 4D 08 70 06 BF 80 <orf> 02 62 80 | 00
    return APDUCommand{.cla = 0x00,
                       .ins = 0xCB, // GET DATA (ODD)
                       .p1 = 0x3F,
                       .p2 = 0xFF,
                       .data = {0x4D, 0x08, 0x70, 0x06, 0xBF, 0x80, orf, 0x02, 0x62, 0x80},
                       .le = 0,
                       .hasLe = true};
}

APDUCommand changeReferenceData(uint8_t pinRef, std::span<const uint8_t> oldPin, std::span<const uint8_t> newPin,
                                uint8_t p1)
{
    std::vector<uint8_t> data;
    data.reserve(oldPin.size() + newPin.size());
    data.insert(data.end(), oldPin.begin(), oldPin.end());
    data.insert(data.end(), newPin.begin(), newPin.end());

    return APDUCommand{.cla = 0x00,
                       .ins = 0x24, // CHANGE REFERENCE DATA
                       .p1 = p1,
                       .p2 = pinRef,
                       .data = std::move(data),
                       .le = 0,
                       .hasLe = false};
}

APDUCommand resetRetryCounter(uint8_t p1, uint8_t pinRef, std::span<const uint8_t> puk, std::span<const uint8_t> newPin)
{
    std::vector<uint8_t> data;
    data.reserve(puk.size() + newPin.size());
    data.insert(data.end(), puk.begin(), puk.end());
    data.insert(data.end(), newPin.begin(), newPin.end());

    return APDUCommand{.cla = 0x00,
                       .ins = 0x2C, // RESET RETRY COUNTER
                       .p1 = p1,
                       .p2 = pinRef,
                       .data = std::move(data),
                       .le = 0,
                       .hasLe = false};
}

APDUCommand activate(uint8_t p1, uint8_t p2, std::span<const uint8_t> objectRef)
{
    return APDUCommand{.cla = 0x00,
                       .ins = 0x44, // ACTIVATE (ISO 7816-9)
                       .p1 = p1,
                       .p2 = p2,
                       .data = {objectRef.begin(), objectRef.end()},
                       .le = 0,
                       .hasLe = false};
}

bool isSelectRetryable(uint16_t sw)
{
    return sw == 0x6700     // Wrong length (Le rejected)
           || sw == 0x6982  // Security status not satisfied (may need P2=0x0C)
           || sw == 0x6A86; // Incorrect parameters P1-P2
}

} // namespace LibreSCRS::SmartCard::Internal
