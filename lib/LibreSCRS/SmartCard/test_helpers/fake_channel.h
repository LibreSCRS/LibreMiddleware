// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "LibreSCRS/SmartCard/test_helpers/fake_channel.h is internal to LibreMiddleware tests"
#endif

/// @file
/// @brief Shared @ref LibreSCRS::SecureChannel::ISecureChannel test double
///        used by SmartCard / SecureChannel / PKCS#15 regression suites.
///
/// Constructor-configurable @ref ChannelState, @c carriesSm flag, and
/// optional @c supportsCrossAppletReuse flag. @c transmit captures the
/// last wrapped command, increments a counter, and fires an optional
/// caller-supplied @c onTransmitCallback hook before returning SW=9000 so
/// a test can simulate a concurrent session mutation (e.g. another thread
/// resetting the active channel) mid-dispatch. @c close transitions the
/// channel to @ref ChannelState::Closed. The protected
/// @c setCurrentApplet override updates the cached AID for wrapped-SELECT
/// scenarios; @c replaceKeys is a no-op because the double carries no
/// session key material.

#include <LibreSCRS/CancelToken.h>
#include <LibreSCRS/SmartCard/AppletAid.h>
#include <LibreSCRS_internal/SecureChannel/ISecureChannel.h>
#include <LibreSCRS_internal/SecureChannel/SessionKeys.h>

#include "apdu.h"

#include <functional>
#include <utility>

namespace LibreSCRS::SecureChannel::TestSupport {

class FakeChannel final : public ISecureChannel
{
public:
    FakeChannel(LibreSCRS::SmartCard::AppletAid aid, ChannelState initialState, bool carriesSm,
                bool crossAppletReuse = false) noexcept
        : appletAid(std::move(aid)), channelState(initialState), carriesSmFlag(carriesSm),
          crossAppletReuseFlag(crossAppletReuse)
    {}

    [[nodiscard]] const LibreSCRS::SmartCard::AppletAid& currentApplet() const noexcept override
    {
        return appletAid;
    }

    [[nodiscard]] ChannelState state() const noexcept override
    {
        return channelState;
    }

    [[nodiscard]] LibreSCRS::SmartCard::Internal::APDUResponse
    transmit(const LibreSCRS::SmartCard::Internal::APDUCommand& cmd, LibreSCRS::CancelToken /*token*/) override
    {
        lastCommand = cmd;
        ++transmitCount;
        if (onTransmitCallback) {
            onTransmitCallback();
        }
        LibreSCRS::SmartCard::Internal::APDUResponse resp;
        resp.sw1 = 0x90;
        resp.sw2 = 0x00;
        return resp;
    }

    void close() override
    {
        channelState = ChannelState::Closed;
    }

    [[nodiscard]] bool carriesSm() const noexcept override
    {
        return carriesSmFlag;
    }

    [[nodiscard]] bool supportsCrossAppletReuse() const noexcept override
    {
        return crossAppletReuseFlag;
    }

    [[nodiscard]] const LibreSCRS::SmartCard::Internal::APDUCommand& lastWrappedCommand() const noexcept
    {
        return lastCommand;
    }

    [[nodiscard]] int transmits() const noexcept
    {
        return transmitCount;
    }

    std::function<void()> onTransmitCallback;

protected:
    void setCurrentApplet(LibreSCRS::SmartCard::AppletAid aid) noexcept override
    {
        appletAid = std::move(aid);
    }

    void replaceKeys(LibreSCRS::SecureChannel::SessionKeys /*keys*/) noexcept override
    {
        // no SM key material to rotate on the test double
    }

private:
    LibreSCRS::SmartCard::AppletAid appletAid;
    ChannelState channelState;
    bool carriesSmFlag;
    bool crossAppletReuseFlag;
    LibreSCRS::SmartCard::Internal::APDUCommand lastCommand{};
    int transmitCount{0};
};

} // namespace LibreSCRS::SecureChannel::TestSupport
