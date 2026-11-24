// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0 and LibreSCRS contributors

#pragma once

#include <LibreSCRS/SmartCard/TransportError.h>

#include <cstdint>
#include <expected>
#include <span>

namespace LibreSCRS::SmartCard::Internal {

// Forward declarations: the `apdu.h` definitions live in lib/smartcard/src/
// (internal core-transport headers, LIBRESCRS_INTERNAL_BUILD-gated) and
// pulling them in here would transitively force every consumer of
// <smartcard/i_connection.h> through that internal header. The abstract
// method signatures below only need declarations — every caller that
// actually invokes transmit/transmitRaw has to include <apdu.h> in its
// own translation unit anyway.
struct APDUCommand;
struct APDUResponse;
class ReadLengthPolicy;

} // namespace LibreSCRS::SmartCard::Internal

namespace LibreSCRS::SmartCard {

/// Abstract transmit seam shared by the production PC/SC connection
/// and any test double. Channel implementations
/// (PlainChannel / PaceChannel / BacChannel) consume this interface
/// so they can be unit-tested without a real PC/SC stack.
///
/// Channels need two things from a connection: the byte-level transmit
/// primitive and what it has learned about the Le the card accepts
/// (readLengthPolicy()); transaction control, ATR retrieval and reconnect
/// are on CardConnection.
class IConnection
{
public:
    virtual ~IConnection() = default;

    /// Send a command APDU to the card and return the response.
    /// Implementations are synchronous. A failed exchange is the error, never
    /// an exception; an answer of the card, whatever its status word, is the
    /// value.
    virtual std::expected<Internal::APDUResponse, TransportError> transmit(const Internal::APDUCommand& cmd) = 0;

    /// Send a pre-encoded command APDU (already-wrapped bytes) to the
    /// card and return the response. Used by SM channel implementations
    /// to ship the wrapped output of SecureMessaging::protect directly
    /// to the wire without round-tripping through APDUCommand /
    /// toBytes — a round-trip that previously truncated extended-length
    /// SM payloads when the wrapped Lc/Le fell in the extended-encoding
    /// range. PC/SC filter chain is bypassed (mirrors the legacy
    /// PCSCConnection::transmitRaw contract).
    virtual std::expected<Internal::APDUResponse, TransportError>
    transmitRaw(std::span<const std::uint8_t> cmdBytes) = 0;

    /// What this connection has learned about the Le the card accepts, or
    /// nullptr when it learns nothing (test doubles): then the plain transport
    /// leaves the Le as given, and a secure-messaging channel asks for at most
    /// 256.
    [[nodiscard]] virtual Internal::ReadLengthPolicy* readLengthPolicy() noexcept
    {
        return nullptr;
    }
};

} // namespace LibreSCRS::SmartCard
