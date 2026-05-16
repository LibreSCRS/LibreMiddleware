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
    using ResponseFn = std::function<LibreSCRS::SmartCard::Internal::APDUResponse(
        const LibreSCRS::SmartCard::Internal::APDUCommand&)>;

    void setResponder(ResponseFn fn) { responder = std::move(fn); }

    LibreSCRS::SmartCard::Internal::APDUResponse transmit(
        const LibreSCRS::SmartCard::Internal::APDUCommand& cmd) override
    {
        transmitted.push_back(cmd);
        if (!responder)
        {
            LibreSCRS::SmartCard::Internal::APDUResponse ok;
            ok.sw1 = 0x90;
            ok.sw2 = 0x00;
            return ok;
        }
        return responder(cmd);
    }

    [[nodiscard]] const std::vector<LibreSCRS::SmartCard::Internal::APDUCommand>& history() const noexcept
    {
        return transmitted;
    }

    void clearHistory() noexcept { transmitted.clear(); }

private:
    std::vector<LibreSCRS::SmartCard::Internal::APDUCommand> transmitted;
    ResponseFn responder;
};

} // namespace LibreSCRS::SecureChannel::TestSupport
