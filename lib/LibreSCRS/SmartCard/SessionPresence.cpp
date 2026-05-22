// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <LibreSCRS/SmartCard/CardSession.h>
#include <LibreSCRS_internal/SmartCard/SessionPresence.h>

#include <utility>

namespace LibreSCRS::SmartCard::Internal {

SessionPresence::Registration::Registration(SessionPresence* o, std::string r) noexcept
    : owner(o), readerName(std::move(r))
{}

SessionPresence::Registration::Registration(Registration&& other) noexcept
    : owner(other.owner), readerName(std::move(other.readerName))
{
    other.owner = nullptr;
}

SessionPresence::Registration& SessionPresence::Registration::operator=(Registration&& other) noexcept
{
    if (this != &other) {
        if (owner)
            owner->remove(readerName);
        owner = other.owner;
        readerName = std::move(other.readerName);
        other.owner = nullptr;
    }
    return *this;
}

SessionPresence::Registration::~Registration()
{
    if (owner)
        owner->remove(readerName);
}

SessionPresence::Registration SessionPresence::insert(std::string readerName, std::weak_ptr<CardSession> session)
{
    std::lock_guard lock(mu);
    entries[readerName] = std::move(session);
    return Registration{this, std::move(readerName)};
}

std::shared_ptr<CardSession> SessionPresence::peek(const std::string& readerName) const noexcept
{
    std::lock_guard lock(mu);
    auto it = entries.find(readerName);
    if (it == entries.end())
        return nullptr;
    return it->second.lock();
}

bool SessionPresence::hasLiveSm(const std::string& readerName) const noexcept
{
    auto session = peek(readerName);
    if (!session)
        return false;
    // session->hasLiveSecureChannel() acquires the session's own mutex.
    // Lock order here is presence → session; presence has no callers that
    // re-enter the registry while holding the session mutex, so the order
    // is partially observable rather than mutual.
    return session->hasLiveSecureChannel();
}

void SessionPresence::clearAll() noexcept
{
    std::lock_guard lock(mu);
    entries.clear();
}

void SessionPresence::remove(const std::string& readerName) noexcept
{
    std::lock_guard lock(mu);
    entries.erase(readerName);
}

} // namespace LibreSCRS::SmartCard::Internal
