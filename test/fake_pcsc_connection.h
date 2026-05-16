// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

/// @file
/// @brief Test double for LibreSCRS::SmartCard::IConnection used by the
///        SecureChannel unit tests. Records every transmitted command and
///        returns a caller-supplied APDUResponse (defaulting to SW 9000).

#include <smartcard/i_connection.h>

#include "apdu.h"

#include <functional>
#include <utility>
#include <vector>

namespace LibreSCRS::SecureChannel::TestSupport {

class FakePCSCConnection final : public LibreSCRS::SmartCard::IConnection
{
public:
    using ResponseFn =
        std::function<LibreSCRS::SmartCard::Internal::APDUResponse(const LibreSCRS::SmartCard::Internal::APDUCommand&)>;

    void setResponder(ResponseFn fn)
    {
        responder = std::move(fn);
    }

    LibreSCRS::SmartCard::Internal::APDUResponse
    transmit(const LibreSCRS::SmartCard::Internal::APDUCommand& cmd) override
    {
        transmitted.push_back(cmd);
        if (!responder) {
            LibreSCRS::SmartCard::Internal::APDUResponse ok;
            ok.sw1 = 0x90;
            ok.sw2 = 0x00;
            return ok;
        }
        return responder(cmd);
    }

    /// Record the raw bytes verbatim then dispatch the equivalent
    /// APDUCommand to @ref responder. Tests that care about the wire
    /// shape inspect @ref rawTransmitted instead of @ref transmitted.
    LibreSCRS::SmartCard::Internal::APDUResponse transmitRaw(std::span<const std::uint8_t> cmdBytes) override
    {
        rawTransmitted.emplace_back(cmdBytes.begin(), cmdBytes.end());
        // For test purposes, build a minimal APDUCommand record so existing
        // history-based assertions (CLA/INS/P1/P2) continue to work without
        // a full extended-length parser inside the fake. Data payload and
        // chained TLVs are not parsed; tests that need them check
        // rawTransmitted directly.
        LibreSCRS::SmartCard::Internal::APDUCommand cmd;
        if (cmdBytes.size() >= 4) {
            cmd.cla = cmdBytes[0];
            cmd.ins = cmdBytes[1];
            cmd.p1 = cmdBytes[2];
            cmd.p2 = cmdBytes[3];
        }
        transmitted.push_back(cmd);
        if (!responder) {
            LibreSCRS::SmartCard::Internal::APDUResponse ok;
            ok.sw1 = 0x90;
            ok.sw2 = 0x00;
            return ok;
        }
        return responder(cmd);
    }

    [[nodiscard]] const std::vector<std::vector<std::uint8_t>>& rawHistory() const noexcept
    {
        return rawTransmitted;
    }

    [[nodiscard]] const std::vector<LibreSCRS::SmartCard::Internal::APDUCommand>& history() const noexcept
    {
        return transmitted;
    }

    void clearHistory() noexcept
    {
        transmitted.clear();
    }

private:
    std::vector<LibreSCRS::SmartCard::Internal::APDUCommand> transmitted;
    std::vector<std::vector<std::uint8_t>> rawTransmitted;
    ResponseFn responder;
};

} // namespace LibreSCRS::SecureChannel::TestSupport
