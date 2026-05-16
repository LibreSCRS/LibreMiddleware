// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <LibreSCRS/SecureChannel/PlainChannel.h>

#include <smartcard/i_connection.h>

#include "apdu.h"

#include <utility>

namespace LibreSCRS::SecureChannel {

namespace {

LibreSCRS::SmartCard::Internal::APDUResponse makeSentinel(std::uint8_t sw1, std::uint8_t sw2)
{
    LibreSCRS::SmartCard::Internal::APDUResponse response;
    response.sw1 = sw1;
    response.sw2 = sw2;
    return response;
}

} // namespace

PlainChannel::PlainChannel(LibreSCRS::SmartCard::IConnection& conn,
                           LibreSCRS::SmartCard::AppletAid aid)
    : connection(conn), appletAid(std::move(aid))
{
}

LibreSCRS::SmartCard::AppletAid PlainChannel::currentApplet() const noexcept
{
    return appletAid;
}

ChannelState PlainChannel::state() const noexcept
{
    return channelState;
}

LibreSCRS::SmartCard::Internal::APDUResponse
PlainChannel::transmit(const LibreSCRS::SmartCard::Internal::APDUCommand& cmd,
                       LibreSCRS::CancelToken token)
{
    if (channelState == ChannelState::Closed)
    {
        return makeSentinel(0x6F, 0x00); // channel closed
    }
    if (channelState == ChannelState::Failed)
    {
        return makeSentinel(0x6F, 0x02); // channel failed
    }
    if (token.isCancellable() && token.isCancelled())
    {
        return makeSentinel(0x6F, 0x01); // cancelled
    }

    return connection.transmit(cmd);
}

void PlainChannel::close()
{
    channelState = ChannelState::Closed;
}

} // namespace LibreSCRS::SecureChannel
