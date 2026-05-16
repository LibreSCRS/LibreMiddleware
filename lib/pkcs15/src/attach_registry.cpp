// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "attach_registry.h"

#include <utility>

namespace LibreSCRS::Pkcs15::Pkcs11 {

AttachRegistry::AttachRegistry() = default;
AttachRegistry::~AttachRegistry() = default;

void AttachRegistry::put(std::string readerName, std::shared_ptr<LibreSCRS::SmartCard::CardSession> session)
{
    std::scoped_lock lock(mu);
    entries[std::move(readerName)] = std::move(session);
}

std::shared_ptr<LibreSCRS::SmartCard::CardSession> AttachRegistry::tryAdopt(const std::string& readerName) noexcept
{
    std::scoped_lock lock(mu);
    auto it = entries.find(readerName);
    if (it == entries.end())
        return nullptr;
    auto session = std::move(it->second);
    entries.erase(it);
    return session;
}

void AttachRegistry::remove(const std::string& readerName) noexcept
{
    std::scoped_lock lock(mu);
    entries.erase(readerName);
}

void AttachRegistry::clearAll() noexcept
{
    std::scoped_lock lock(mu);
    entries.clear();
}

} // namespace LibreSCRS::Pkcs15::Pkcs11
