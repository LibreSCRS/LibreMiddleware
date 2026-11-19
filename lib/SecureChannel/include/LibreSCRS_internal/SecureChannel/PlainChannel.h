// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error                                                                                                                 \
    "LibreSCRS_internal/SecureChannel/PlainChannel.h is internal to LibreMiddleware. Public API: <LibreSCRS/SecureChannel/...>"
#endif

#pragma once

/// @file
/// @brief @ref LibreSCRS::SecureChannel::PlainChannel — the no-secure-
///        messaging implementation of @ref ISecureChannel. Default for
///        cards that do not require PACE/BAC (contact PKCS#15 and
///        equivalent).

#include <LibreSCRS/Export.h>
#include <LibreSCRS_internal/SecureChannel/ISecureChannel.h>

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
class PlainChannel final : public ISecureChannel
{
public:
    /// @note The constructor and the destructor are the only exported members:
    ///       card plugins build a PlainChannel on their stack, so they call
    ///       exactly these two. The destructor is out of line on purpose -- an
    ///       inline one writes the vtable pointer from the plugin, and whether
    ///       it does depends on the optimiser (-O2 did, -O3 did not), which
    ///       would make the vtable an export some builds need and others not.
    LIBRESCRS_PUBLIC_API PlainChannel(LibreSCRS::SmartCard::IConnection& connection,
                                      LibreSCRS::SmartCard::AppletAid currentAppletAid);

    LIBRESCRS_PUBLIC_API ~PlainChannel() override;

    [[nodiscard]] const LibreSCRS::SmartCard::AppletAid& currentApplet() const noexcept override;
    [[nodiscard]] ChannelState state() const noexcept override;

    [[nodiscard]] LibreSCRS::SmartCard::Internal::APDUResponse
    transmit(const LibreSCRS::SmartCard::Internal::APDUCommand& cmd, LibreSCRS::CancelToken token) override;

    void close() override;

protected:
    /// @brief No-op: @ref PlainChannel has no SM tunnel and no cross-
    ///        applet reuse. The activation path destroys and recreates a
    ///        @ref PlainChannel for each applet switch, so the bound AID
    ///        is constructor-fixed for the channel's lifetime.
    /// @since 4.1
    void setCurrentApplet(LibreSCRS::SmartCard::AppletAid /*aid*/) noexcept override
    {
        // intentionally empty — applet binding is constructor-fixed
    }

    /// @brief No-op: @ref PlainChannel has no SM session keys to rotate.
    /// @since 4.1
    void replaceKeys(SessionKeys /*keys*/) noexcept override
    {
        // intentionally empty — no SM key material exists on a plain channel
    }

private:
    LibreSCRS::SmartCard::IConnection& connection;
    LibreSCRS::SmartCard::AppletAid appletAid;
    ChannelState channelState = ChannelState::Open;
};

} // namespace LibreSCRS::SecureChannel
