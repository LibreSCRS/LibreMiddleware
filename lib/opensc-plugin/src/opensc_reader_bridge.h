// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware (opensc-plugin)."
#endif

#pragma once

#include <cstdint>
#include <span>
#include <string>

#include <LibreSCRS/CancelToken.h>

#include <libopensc/opensc.h> // sc_reader_t, sc_context_t, sc_reader_driver

namespace LibreSCRS::SmartCard::Internal {
class PCSCConnection;
}

namespace LibreSCRS::SecureChannel {
class ISecureChannel;
}

namespace LibreSCRS::OpenSc::Bridge {

/// Per-reader private data (the libopensc @c reader->drv_data). Mirrors the
/// role of @c struct pcsc_private_data in reader-pcsc.c, but holds only a
/// non-owning pointer to the LM connection plus the bridge's transaction
/// bookkeeping. @c ownsTransaction records whether THIS bridge began the
/// PC/SC transaction (vs. the agent's holder already owning it), so unlock
/// never ends a transaction it does not own.
struct BridgeData
{
    LibreSCRS::SmartCard::Internal::PCSCConnection* conn = nullptr;
    bool ownsTransaction = false;
    /// Borrowed live secure channel. While non-null, the transmit op routes
    /// every sc_apdu through @c channel->transmit (the tunnel branch) instead
    /// of the raw connection: the channel SM-wraps and unwraps, so libopensc
    /// above still runs its own GET RESPONSE / retry logic against the
    /// UNWRAPPED SW it gets back. The plugin installs the pointer (together
    /// with @c token) for the duration of ONE libopensc call under an active
    /// channel holder and clears it afterwards; the bridge never owns or
    /// tears down the channel.
    LibreSCRS::SecureChannel::ISecureChannel* channel = nullptr;
    /// Operation cancel token forwarded to @c channel->transmit on the
    /// tunnel branch. Default-constructed (never-cancellable) until the
    /// plugin installs the running operation's token alongside @c channel.
    LibreSCRS::CancelToken token;
};

/// Heap-allocated block that keeps the @c sc_reader, its private data, and
/// the reader-name storage at STABLE addresses. The owning @c OpenSCSession
/// is moved into the plugin's session map AFTER @c sc_connect_card has set
/// @c card->reader = &reader; a by-value member would change address on that
/// move and dangle @c card->reader. One @c std::unique_ptr<OpenScBridge>
/// moves the pointer, not the pointee — addresses stay put.
struct OpenScBridge
{
    BridgeData data;
    sc_reader reader{};
    std::string readerName; // backs reader.name (stable)
};

/// Initialise @c bridge.reader as a librescrs-bridge reader bound to the
/// connection in @c bridge.data. The reader is NOT appended to
/// @c ctx->readers (its @c ctx is set directly and the OpenScBridge owns its
/// lifetime). @c bridge.data.conn and @c bridge.readerName must already be
/// populated. After this returns, call @c sc_connect_card(&bridge.reader,
/// &card).
void initBridgeReader(sc_context_t* ctx, OpenScBridge& bridge, std::span<const std::uint8_t> atr);

} // namespace LibreSCRS::OpenSc::Bridge
