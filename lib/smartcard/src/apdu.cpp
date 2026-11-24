// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "apdu.h"

#include <algorithm>
#include <cstddef>
#include <stdexcept>
#include <string>

namespace LibreSCRS::SmartCard::Internal {

std::vector<uint8_t> APDUCommand::toBytes() const
{
    // Header, up to 3 Lc bytes, the data, up to 3 Le bytes: reserved up front
    // so no append moves the serialization and frees a copy of the data field,
    // which is a PIN on a PIN verb.
    std::vector<uint8_t> bytes;
    bytes.reserve(4 + 3 + data.size() + 3);
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
        if (useExtended) {
            // Extended Le: 2-byte encoding. With no data field it is case 2
            // extended, which starts with the 00 marker (ISO/IEC 7816-4,
            // 5.1).
            if (data.empty()) {
                bytes.push_back(0x00);
            }
            uint16_t extLe = (le == 0) ? 256u : le;
            bytes.push_back(static_cast<uint8_t>(extLe >> 8));
            bytes.push_back(static_cast<uint8_t>(extLe & 0xFF));
        } else {
            // Short Le: one byte, 00 meaning 256 (an Le of 256 is short).
            bytes.push_back(static_cast<uint8_t>(le == 256 ? 0 : le));
        }
    }

    return bytes;
}

std::optional<APDUCommand> decodeCommand(std::span<const uint8_t> bytes)
{
    const std::size_t n = bytes.size();
    if (n < 4) {
        return std::nullopt;
    }
    APDUCommand cmd{
        .cla = bytes[0], .ins = bytes[1], .p1 = bytes[2], .p2 = bytes[3], .data = {}, .le = 0, .hasLe = false};
    const auto twoBytes = [&bytes](std::size_t at) { return static_cast<uint16_t>((bytes[at] << 8) | bytes[at + 1]); };
    if (n == 4) {
        // Case 1: header only.
    } else if (n == 5) {
        // Case 2 short: one Le byte, 00 meaning 256.
        cmd.le = bytes[4];
        cmd.hasLe = true;
    } else if (bytes[4] != 0x00) {
        // Short Lc, the data, then nothing or one Le byte.
        const std::size_t lc = bytes[4];
        if (n < 5 + lc) {
            return std::nullopt;
        }
        const std::size_t rest = n - 5 - lc;
        cmd.data.assign(bytes.begin() + 5, bytes.begin() + 5 + static_cast<std::ptrdiff_t>(lc));
        if (rest == 1) {
            cmd.le = bytes[5 + lc];
            cmd.hasLe = true;
        } else if (rest != 0) {
            return std::nullopt;
        }
    } else if (n == 7) {
        // Case 2 extended: 00, then a two-byte Le.
        cmd.le = twoBytes(5);
        cmd.hasLe = true;
    } else {
        // Extended Lc (00 LcHi LcLo), the data, then nothing or a two-byte Le.
        if (n < 7) {
            return std::nullopt;
        }
        const std::size_t lc = twoBytes(5);
        if (lc == 0 || n < 7 + lc) {
            return std::nullopt;
        }
        const std::size_t rest = n - 7 - lc;
        cmd.data.assign(bytes.begin() + 7, bytes.begin() + 7 + static_cast<std::ptrdiff_t>(lc));
        if (rest == 2) {
            cmd.le = twoBytes(7 + lc);
            cmd.hasLe = true;
        } else if (rest != 0) {
            return std::nullopt;
        }
    }
    return cmd;
}

std::optional<APDUCommand> parseCommand(std::span<const uint8_t> bytes)
{
    auto cmd = decodeCommand(bytes);
    if (!cmd) {
        return std::nullopt;
    }
    // Accept only what encodes back to the very same bytes: the command goes
    // on as this structure, so anything else would reach the card altered.
    const std::size_t n = bytes.size();
    auto encoded = cmd->toBytes();
    const bool same = encoded.size() == n && std::equal(encoded.begin(), encoded.end(), bytes.begin());
    if (!encoded.empty()) {
        secureWipe(encoded.data(), encoded.size());
    }
    if (!same) {
        return std::nullopt;
    }
    return cmd;
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

APDUCommand readBinary(uint16_t offset, uint16_t length)
{
    // P1 bit 8 selects short-EF addressing: an offset past 15 bits cannot be
    // sent with this INS, and masking it would read from offset - 0x8000.
    if (offset > 0x7FFF)
        throw std::invalid_argument("READ BINARY offset " + std::to_string(offset) + " needs more than 15 bits");
    return APDUCommand{.cla = 0x00,
                       .ins = 0xB0, // READ BINARY
                       .p1 = static_cast<uint8_t>(offset >> 8),
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
