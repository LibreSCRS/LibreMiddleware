// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <LibreSCRS/SmartCard/ActiveChannelHolder.h>
#include <LibreSCRS/SmartCard/CardSession.h>

#include <LibreSCRS_internal/SmartCard/ActiveChannelHolderInternal.h>

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

    // Explicit destructor enforces the release ordering documented in
    // ActiveChannelHolder.h: PC/SC transaction ends BEFORE the session
    // mutex is dropped. The compiler-generated dtor would destroy members
    // in reverse-declaration order, which happens to be correct today
    // (active → transaction → lock), but a future field reordering
    // could silently invert the order and leak a transaction across a
    // mutex release window. release() is idempotent, so calling it from
    // the destructor unconditionally is safe whether the holder is still
    // active or already released.
    ~Impl() noexcept
    {
        release();
    }

    Impl(const Impl&) = delete;
    Impl& operator=(const Impl&) = delete;
    Impl(Impl&&) = delete;
    Impl& operator=(Impl&&) = delete;

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
        return Internal::ActiveChannelAccessor::active(*session);
    }

private:
    CardSession* session = nullptr;
    std::unique_lock<std::mutex> lock;
    std::unique_ptr<LibreSCRS::SmartCard::Internal::CardTransaction> transaction;
    bool active = false;
};

ActiveChannelHolder::ActiveChannelHolder(std::unique_ptr<Impl> impl) noexcept : d(std::move(impl)) {}

ActiveChannelHolder::ActiveChannelHolder(ActiveChannelHolder&&) noexcept = default;
ActiveChannelHolder& ActiveChannelHolder::operator=(ActiveChannelHolder&&) noexcept = default;
ActiveChannelHolder::~ActiveChannelHolder() = default;

void ActiveChannelHolder::release() noexcept
{
    if (d) {
        d->release();
    }
}

bool ActiveChannelHolder::isActive() const noexcept
{
    return d && d->isActive();
}

namespace Internal {

ActiveChannelHolder makeActiveChannelHolder(CardSession* session, std::unique_lock<std::mutex> lock,
                                            std::unique_ptr<LibreSCRS::SmartCard::Internal::CardTransaction> tx)
{
    auto impl = std::make_unique<ActiveChannelHolder::Impl>(session, std::move(lock), std::move(tx));
    return ActiveChannelHolder{std::move(impl)};
}

LibreSCRS::SecureChannel::ISecureChannel* HolderChannelAccessor::channel(ActiveChannelHolder& holder) noexcept
{
    if (!holder.d || !holder.d->isActive()) {
        return nullptr;
    }
    return holder.d->activeChannel();
}

} // namespace Internal

} // namespace LibreSCRS::SmartCard
