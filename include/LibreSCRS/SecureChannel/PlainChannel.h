// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

/// @file
/// @brief @ref LibreSCRS::SecureChannel::PlainChannel — the no-secure-
///        messaging implementation of @ref ISecureChannel. Default for
///        cards that do not require PACE/BAC (RS eID, GEO CB without
///        PACE, AET, Zdravstvena, classical PKCS#15 over contact).

#include <LibreSCRS/Export.h>
#include <LibreSCRS/SecureChannel/ISecureChannel.h>

namespace LibreSCRS::SmartCard {
class IConnection;
} // namespace LibreSCRS::SmartCard

namespace LibreSCRS::SecureChannel {

/// @brief Pass-through channel: forwards APDUs to the underlying
///        @ref LibreSCRS::SmartCard::IConnection without wrapping.
///
/// The current applet AID is recorded at construction time; subsequent
/// applet switches are out of scope — CardSession constructs a new
/// PlainChannel per selected applet.
///
/// @since 4.1
class LIBRESCRS_PUBLIC_API PlainChannel final : public ISecureChannel
{
public:
    PlainChannel(LibreSCRS::SmartCard::IConnection& connection, LibreSCRS::SmartCard::AppletAid currentAppletAid);

    ~PlainChannel() override = default;

    [[nodiscard]] LibreSCRS::SmartCard::AppletAid currentApplet() const noexcept override;
    [[nodiscard]] ChannelState state() const noexcept override;

    [[nodiscard]] LibreSCRS::SmartCard::Internal::APDUResponse
    transmit(const LibreSCRS::SmartCard::Internal::APDUCommand& cmd, LibreSCRS::CancelToken token) override;

    void close() override;

private:
    LibreSCRS::SmartCard::IConnection& connection;
    LibreSCRS::SmartCard::AppletAid appletAid;
    ChannelState channelState = ChannelState::Open;
};

} // namespace LibreSCRS::SecureChannel
