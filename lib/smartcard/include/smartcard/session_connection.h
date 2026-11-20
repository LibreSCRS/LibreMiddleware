// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "smartcard/session_connection.h is internal to LibreMiddleware"
#endif

#include <LibreSCRS/CancelToken.h>
#include <LibreSCRS/SmartCard/CardSession.h>

#include <smartcard/card_connection.h>
#include <smartcard/secure_buffer.h>
#include <smartcard/secure_wipe.h>

#include "apdu.h"

#include <cstdint>
#include <span>
#include <stdexcept>
#include <utility>
#include <vector>

namespace LibreSCRS::SmartCard {

/// The card, for a card library, through the public calls of a card session.
///
/// Header-only and used inside a card plugin: its vtable and typeinfo are the
/// plugin's own, and every call goes through an exported CardSession member.
/// transmit() is the session's: through the open channel when the session
/// holds one, refused when a secure-messaging channel it holds has failed,
/// plain otherwise. transmitRaw() sends the bytes as given, refused while a
/// secure-messaging channel is live. A reader failure throws, as the
/// connection itself does.
class SessionConnection final : public CardConnection
{
public:
    explicit SessionConnection(CardSession& session, LibreSCRS::CancelToken token = {}) noexcept
        : session(session), token(std::move(token))
    {}

    Internal::APDUResponse transmit(const Internal::APDUCommand& cmd) override
    {
        // The serialization can carry a PIN: the bytes are wiped once sent.
        const Internal::SecureBuffer bytes(cmd.toBytes());
        return toResponse(session.transmit(std::span<const std::uint8_t>(bytes.data(), bytes.size()), token));
    }

    Internal::APDUResponse transmitRaw(std::span<const std::uint8_t> cmdBytes) override
    {
        return toResponse(session.transmitRaw(cmdBytes));
    }

    void beginTransaction() override
    {
        session.beginTransaction();
    }

    void endTransaction() noexcept override
    {
        session.endTransaction();
    }

    [[nodiscard]] bool isTransactionHeld() const noexcept override
    {
        return session.isTransactionHeld();
    }

    /// The ATR the card gave when the session opened. A session without a
    /// card (a detached one) has none, and the call fails as the connection's
    /// own query of a card that is not there does.
    [[nodiscard]] std::vector<std::uint8_t> getATR() const override
    {
        const auto& atr = session.atr();
        if (atr.empty()) {
            throw std::runtime_error("no ATR: the card session has no card");
        }
        return atr;
    }

    void reconnect() override
    {
        session.reconnect();
    }

    /// An answer (data, SW1, SW2) as a response. The data can be a decrypted
    /// record: the byte string it came in is wiped.
    static Internal::APDUResponse toResponse(std::vector<std::uint8_t> answer)
    {
        Internal::APDUResponse response{{}, 0x6F, 0x00};
        if (answer.size() >= 2) {
            response.sw1 = answer[answer.size() - 2];
            response.sw2 = answer[answer.size() - 1];
            response.data.assign(answer.begin(), answer.end() - 2);
        }
        if (!answer.empty()) {
            Internal::secureWipe(answer.data(), answer.size());
        }
        return response;
    }

private:
    CardSession& session;
    LibreSCRS::CancelToken token;
};

} // namespace LibreSCRS::SmartCard
