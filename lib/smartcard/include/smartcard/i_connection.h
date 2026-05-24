// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0 and LibreSCRS contributors

#pragma once

#include <cstdint>
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

} // namespace LibreSCRS::SmartCard::Internal

namespace LibreSCRS::SmartCard {

/// Abstract transmit seam shared by the production PC/SC connection
/// and any test double. Channel implementations
/// (PlainChannel / PaceChannel / BacChannel) consume this interface
/// so they can be unit-tested without a real PC/SC stack.
///
/// The full set of operations on a connection (transaction control,
/// ATR retrieval, reconnect, etc.) intentionally stays on the
/// concrete PCSCConnection; only the byte-level transmit primitive
/// is abstracted here because that is the only seam channels need.
class IConnection
{
public:
    virtual ~IConnection() = default;

    /// Send a command APDU to the card and return the response.
    /// Implementations are expected to be synchronous and to surface
    /// PC/SC errors as exceptions (matching PCSCConnection's
    /// long-standing contract).
    virtual Internal::APDUResponse transmit(const Internal::APDUCommand& cmd) = 0;

    /// Send a pre-encoded command APDU (already-wrapped bytes) to the
    /// card and return the response. Used by SM channel implementations
    /// to ship the wrapped output of SecureMessaging::protect directly
    /// to the wire without round-tripping through APDUCommand /
    /// toBytes — a round-trip that previously truncated extended-length
    /// SM payloads when the wrapped Lc/Le fell in the extended-encoding
    /// range. PC/SC filter chain is bypassed (mirrors the legacy
    /// PCSCConnection::transmitRaw contract).
    virtual Internal::APDUResponse transmitRaw(std::span<const std::uint8_t> cmdBytes) = 0;
};

} // namespace LibreSCRS::SmartCard
