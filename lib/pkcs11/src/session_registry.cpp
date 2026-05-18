// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <internal/SessionRegistry.h>

#include <utility>

namespace LibreSCRS::Pkcs11::Internal {

SessionRegistry::SessionRegistry() = default;
SessionRegistry::~SessionRegistry() = default;

void SessionRegistry::put(std::string readerName, std::shared_ptr<LibreSCRS::SmartCard::CardSession> session)
{
    std::scoped_lock lock(mu);
    entries[std::move(readerName)] = std::move(session);
}

std::shared_ptr<LibreSCRS::SmartCard::CardSession> SessionRegistry::peek(const std::string& readerName) const noexcept
{
    std::scoped_lock lock(mu);
    auto it = entries.find(readerName);
    if (it == entries.end())
        return nullptr;
    // Copy the shared_ptr under the lock so the caller's ref is
    // independent of any concurrent remove().
    return it->second;
}

bool SessionRegistry::contains(const std::string& readerName) const noexcept
{
    std::scoped_lock lock(mu);
    return entries.find(readerName) != entries.end();
}

void SessionRegistry::remove(const std::string& readerName) noexcept
{
    std::scoped_lock lock(mu);
    entries.erase(readerName);
}

void SessionRegistry::clearAll() noexcept
{
    std::scoped_lock lock(mu);
    entries.clear();
}

} // namespace LibreSCRS::Pkcs11::Internal
