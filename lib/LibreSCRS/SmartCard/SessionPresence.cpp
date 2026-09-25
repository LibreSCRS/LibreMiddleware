// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <LibreSCRS/SmartCard/CardSession.h>
#include <LibreSCRS_internal/SmartCard/SessionPresence.h>

#include <utility>

namespace LibreSCRS::SmartCard::Internal {

namespace {

// Identity, not value: two weak references are the same entry when they share a
// control block, and this still answers after the session itself is gone --
// which is exactly when a registration is being destroyed.
[[nodiscard]] bool sameSession(const std::weak_ptr<CardSession>& a, const std::weak_ptr<CardSession>& b) noexcept
{
    return !a.owner_before(b) && !b.owner_before(a);
}

} // namespace

SessionPresence::Registration::Registration(SessionPresence* o, std::string r, std::weak_ptr<CardSession> s) noexcept
    : owner(o), readerName(std::move(r)), session(std::move(s))
{}

SessionPresence::Registration::Registration(Registration&& other) noexcept
    : owner(other.owner), readerName(std::move(other.readerName)), session(std::move(other.session))
{
    other.owner = nullptr;
}

SessionPresence::Registration& SessionPresence::Registration::operator=(Registration&& other) noexcept
{
    if (this != &other) {
        if (owner)
            owner->remove(readerName, session);
        owner = other.owner;
        readerName = std::move(other.readerName);
        session = std::move(other.session);
        other.owner = nullptr;
    }
    return *this;
}

SessionPresence::Registration::~Registration()
{
    if (owner)
        owner->remove(readerName, session);
}

SessionPresence::Registration SessionPresence::insert(std::string readerName, std::weak_ptr<CardSession> session)
{
    {
        std::lock_guard lock(mu);
        entries[readerName] = session;
    }
    return Registration{this, std::move(readerName), std::move(session)};
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

void SessionPresence::remove(const std::string& readerName, const std::weak_ptr<CardSession>& session) noexcept
{
    std::lock_guard lock(mu);
    const auto it = entries.find(readerName);
    // Only our own entry. A registration whose entry has already been replaced
    // by another session's must leave that one alone: erasing it would turn the
    // live-SM answer this registry exists to give into a false negative, and the
    // one consumer of that answer would then bind the card.
    if (it != entries.end() && sameSession(it->second, session))
        entries.erase(it);
}

} // namespace LibreSCRS::SmartCard::Internal
