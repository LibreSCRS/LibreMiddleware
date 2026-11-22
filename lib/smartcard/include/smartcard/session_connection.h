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
#include <expected>
#include <span>
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
/// secure-messaging channel is live. A failed exchange is the error, as the
/// session reports it.
class SessionConnection final : public CardConnection
{
public:
    explicit SessionConnection(CardSession& session, LibreSCRS::CancelToken token = {}) noexcept
        : session(session), token(std::move(token))
    {}

    std::expected<Internal::APDUResponse, TransportError> transmit(const Internal::APDUCommand& cmd) override
    {
        return transmitThrough(session, cmd, token);
    }

    /// @p cmd through CardSession::transmit, as a response or the error.
    static std::expected<Internal::APDUResponse, TransportError>
    transmitThrough(CardSession& session, const Internal::APDUCommand& cmd, LibreSCRS::CancelToken token)
    {
        // The serialization can carry a PIN: the bytes are wiped once sent.
        const Internal::SecureBuffer bytes(cmd.toBytes());
        return toResponse(
            session.transmit(std::span<const std::uint8_t>(bytes.data(), bytes.size()), std::move(token)));
    }

    std::expected<Internal::APDUResponse, TransportError> transmitRaw(std::span<const std::uint8_t> cmdBytes) override
    {
        return toResponse(session.transmitRaw(cmdBytes));
    }

    std::expected<void, TransportError> beginTransaction() override
    {
        return session.beginTransaction();
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
    /// card (a detached one) has none: NoCardPresent, as the connection's own
    /// query of a card that is not there.
    [[nodiscard]] std::expected<std::vector<std::uint8_t>, TransportError> getATR() const override
    {
        const auto& atr = session.atr();
        if (atr.empty()) {
            return std::unexpected(
                TransportError{TransportError::Kind::NoCardPresent, "no ATR: the card session has no card"});
        }
        return atr;
    }

    std::expected<void, TransportError> reconnect() override
    {
        return session.reconnect();
    }

    /// An answer (data, then the SW1 SW2 the session always appends) as a
    /// response, or the error. The data can be
    /// a decrypted record: the byte string it came in is wiped.
    static std::expected<Internal::APDUResponse, TransportError>
    toResponse(std::expected<std::vector<std::uint8_t>, TransportError> result)
    {
        if (!result) {
            return std::unexpected(std::move(result.error()));
        }
        auto& answer = *result;
        Internal::APDUResponse response{};
        response.sw1 = answer[answer.size() - 2];
        response.sw2 = answer[answer.size() - 1];
        response.data.assign(answer.begin(), answer.end() - 2);
        Internal::secureWipe(answer.data(), answer.size());
        return response;
    }

private:
    CardSession& session;
    LibreSCRS::CancelToken token;
};

} // namespace LibreSCRS::SmartCard
