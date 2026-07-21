// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

#include <cstdint>
#include <span>
#include <vector>

namespace LibreSCRS::SmartCard::Internal {

struct APDUCommand
{
    uint8_t cla, ins, p1, p2;
    std::vector<uint8_t> data; // Lc data (empty = no data field)
    uint16_t le = 0;           // Expected response length (0 = max, >255 = extended)
    bool hasLe = true;

    std::vector<uint8_t> toBytes() const;
};

struct APDUResponse
{
    std::vector<uint8_t> data;
    uint8_t sw1, sw2;

    bool isSuccess() const;
    uint16_t statusWord() const;
};

// Builders for common ISO 7816-4 commands
APDUCommand selectByAID(const std::vector<uint8_t>& aid, uint8_t p2 = 0x00);
APDUCommand selectByPath(uint8_t fileId1, uint8_t fileId2, uint8_t le = 4);
APDUCommand selectByFileId(uint8_t fileId1, uint8_t fileId2, uint8_t p2 = 0x00);
APDUCommand readBinary(uint16_t offset, uint8_t length);

// PIN management commands (ISO 7816-4)
APDUCommand verifyPIN(uint8_t pinRef, std::span<const uint8_t> pin);
APDUCommand verifyPINStatus(uint8_t pinRef);
// GET DATA (ODD, INS CB) reading a credential SDO's DOCP counters.
APDUCommand getDataDocp(uint8_t orf);
APDUCommand changeReferenceData(uint8_t pinRef, std::span<const uint8_t> oldPin, std::span<const uint8_t> newPin);

// Returns true if the status word indicates a SELECT format mismatch
// (wrong P2/Le), meaning retrying with alternative P2/Le is appropriate.
bool isSelectRetryable(uint16_t sw);

} // namespace LibreSCRS::SmartCard::Internal
