// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

/// @file
/// @brief Declared test support for card sessions
///        (<LibreSCRS/SmartCard/testing/CardSessionTesting.h>).
///
/// Compiled into the static archive @ref LibreSCRS_SmartCardTesting only, so
/// no shipped shared library exports these functions. The archive reaches
/// into @c CardSession::Impl, which is why it ships with — and is only valid
/// against — the libraries of the same release.

#include <LibreSCRS/SmartCard/CardSession.h>
#include <LibreSCRS/SmartCard/detail/ChannelInjection.h>
#include <LibreSCRS/SmartCard/testing/CardSessionTesting.h>
#include <LibreSCRS_internal/SecureChannel/ISecureChannel.h>
#include <LibreSCRS_internal/SecureChannel/SessionKeys.h>
#include <LibreSCRS_internal/SmartCard/CardSessionImpl.h>

#include "apdu.h"
#include <pcsc_connection.h>

#include <memory>
#include <string>
#include <utility>

namespace LibreSCRS::SmartCard::Testing {

struct SessionAccess
{
    static std::shared_ptr<CardSession> detached(std::string readerName)
    {
        auto session = std::shared_ptr<CardSession>(new CardSession());
        session->d->readerName = std::move(readerName);
        session->d->ownedConn = std::make_unique<LibreSCRS::SmartCard::Internal::PCSCConnection>(
            LibreSCRS::SmartCard::Internal::PCSCConnection::DetachedTag{}, session->d->readerName);
        // atr stays empty — there is no card
        return session;
    }
};

namespace {

using LibreSCRS::SecureChannel::ChannelState;

class StandIn final : public LibreSCRS::SecureChannel::ISecureChannel
{
public:
    StandIn(ChannelState state, bool carriesSm) noexcept : channelState(state), carriesSmFlag(carriesSm) {}

    [[nodiscard]] const LibreSCRS::SmartCard::AppletAid& currentApplet() const noexcept override
    {
        return applet;
    }

    [[nodiscard]] ChannelState state() const noexcept override
    {
        return channelState;
    }

    [[nodiscard]] LibreSCRS::SmartCard::Internal::APDUResponse
    transmit(const LibreSCRS::SmartCard::Internal::APDUCommand& /*cmd*/, LibreSCRS::CancelToken /*token*/) override
    {
        // 6F00: no card answered, the same word a detached session reports.
        LibreSCRS::SmartCard::Internal::APDUResponse resp;
        resp.sw1 = 0x6F;
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

protected:
    void setCurrentApplet(LibreSCRS::SmartCard::AppletAid aid) noexcept override
    {
        applet = std::move(aid);
    }

    void replaceKeys(LibreSCRS::SecureChannel::SessionKeys /*keys*/) noexcept override
    {
        // no key material on a stand-in
    }

private:
    LibreSCRS::SmartCard::AppletAid applet;
    ChannelState channelState;
    bool carriesSmFlag;
};

} // namespace

std::shared_ptr<CardSession> makeDetachedCardSession(std::string readerName)
{
    return SessionAccess::detached(std::move(readerName));
}

void installStandInChannel(CardSession& session, StandInChannel channel) noexcept
{
    std::unique_ptr<LibreSCRS::SecureChannel::ISecureChannel> standIn;
    try {
        switch (channel) {
        case StandInChannel::LiveSecureMessaging:
            standIn = std::make_unique<StandIn>(ChannelState::Open, true);
            break;
        case StandInChannel::FailedSecureMessaging:
            standIn = std::make_unique<StandIn>(ChannelState::Failed, true);
            break;
        case StandInChannel::Plain:
            standIn = std::make_unique<StandIn>(ChannelState::Open, false);
            break;
        }
    } catch (...) {
        return; // allocation failure: nothing installed
    }
    LibreSCRS::SmartCard::detail::ChannelInjector::installForTesting(session, std::move(standIn));
}

} // namespace LibreSCRS::SmartCard::Testing
