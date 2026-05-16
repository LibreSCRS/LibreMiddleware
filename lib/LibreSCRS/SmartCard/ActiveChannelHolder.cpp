// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <LibreSCRS/SmartCard/ActiveChannelHolder.h>
#include <LibreSCRS/SmartCard/CardSession.h>

#include "ActiveChannelHolderInternal.h"

#include "apdu.h"
#include "smartcard/pcsc_connection.h"

#include <memory>
#include <mutex>
#include <utility>

namespace LibreSCRS::SmartCard {

class ActiveChannelHolder::Impl
{
public:
    Impl(CardSession* sessionPtr, std::unique_lock<std::mutex> sessionLock,
         std::unique_ptr<LibreSCRS::SmartCard::Internal::CardTransaction> tx) noexcept
        : session(sessionPtr), lock(std::move(sessionLock)), transaction(std::move(tx)), active(true)
    {}

    LibreSCRS::SmartCard::Internal::APDUResponse transmit(const LibreSCRS::SmartCard::Internal::APDUCommand& cmd,
                                                          LibreSCRS::CancelToken token)
    {
        if (!active || !session) {
            LibreSCRS::SmartCard::Internal::APDUResponse closed;
            closed.sw1 = 0x6F;
            closed.sw2 = 0x00;
            return closed;
        }
        return Internal::transmitThroughActiveChannel(*session, cmd, std::move(token));
    }

    void release() noexcept
    {
        if (active) {
            active = false;
            transaction.reset(); // unique_ptr<CardTransaction>::reset ends PC/SC tx
            if (lock.owns_lock()) {
                lock.unlock();
            }
        }
    }

    [[nodiscard]] bool isActive() const noexcept
    {
        return active;
    }

    [[nodiscard]] LibreSCRS::SecureChannel::ISecureChannel* activeChannel() noexcept
    {
        if (!active || !session) {
            return nullptr;
        }
        return Internal::activeChannelOf(*session);
    }

private:
    CardSession* session = nullptr;
    std::unique_lock<std::mutex> lock;
    std::unique_ptr<LibreSCRS::SmartCard::Internal::CardTransaction> transaction;
    bool active = false;
};

ActiveChannelHolder::ActiveChannelHolder(std::unique_ptr<Impl> impl) noexcept : pImpl(std::move(impl)) {}

ActiveChannelHolder::ActiveChannelHolder(ActiveChannelHolder&&) noexcept = default;
ActiveChannelHolder& ActiveChannelHolder::operator=(ActiveChannelHolder&&) noexcept = default;
ActiveChannelHolder::~ActiveChannelHolder() = default;

LibreSCRS::SmartCard::Internal::APDUResponse
ActiveChannelHolder::transmit(const LibreSCRS::SmartCard::Internal::APDUCommand& cmd, LibreSCRS::CancelToken token)
{
    if (!pImpl) {
        LibreSCRS::SmartCard::Internal::APDUResponse closed;
        closed.sw1 = 0x6F;
        closed.sw2 = 0x00;
        return closed;
    }
    return pImpl->transmit(cmd, std::move(token));
}

void ActiveChannelHolder::release() noexcept
{
    if (pImpl) {
        pImpl->release();
    }
}

bool ActiveChannelHolder::isActive() const noexcept
{
    return pImpl && pImpl->isActive();
}

LibreSCRS::SecureChannel::ISecureChannel* ActiveChannelHolder::activeChannel() noexcept
{
    if (!pImpl || !pImpl->isActive()) {
        return nullptr;
    }
    return pImpl->activeChannel();
}

namespace Internal {

ActiveChannelHolder makeActiveChannelHolder(CardSession* session, std::unique_lock<std::mutex> lock,
                                            std::unique_ptr<LibreSCRS::SmartCard::Internal::CardTransaction> tx)
{
    auto impl = std::make_unique<ActiveChannelHolder::Impl>(session, std::move(lock), std::move(tx));
    return ActiveChannelHolder{std::move(impl)};
}

} // namespace Internal

} // namespace LibreSCRS::SmartCard
