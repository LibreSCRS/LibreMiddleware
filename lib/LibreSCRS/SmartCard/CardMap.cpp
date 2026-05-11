// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <LibreSCRS/SmartCard/CardMap.h>

#include <utility>

namespace LibreSCRS::SmartCard {

namespace {

// Flatten the (reader, atrHex, serial) tuple into a unique string key.
// '\x1F' (Unit Separator) cannot appear in any of the textual inputs
// (PC/SC reader names are printable ASCII; ATR hex and serial are
// hex / digits), so it makes a robust unambiguous joiner.
std::string flatten(const CardMap::Key& key)
{
    const auto& [reader, atrHex, serial] = key;
    std::string out;
    out.reserve(reader.size() + atrHex.size() + serial.size() + 2);
    out.append(reader);
    out.push_back('\x1F');
    out.append(atrHex);
    out.push_back('\x1F');
    out.append(serial);
    return out;
}

} // namespace

std::optional<CardMapEntry> CardMap::get(const Key& key) const
{
    try {
        std::lock_guard lock(mu);
        auto it = entries.find(flatten(key));
        if (it == entries.end())
            return std::nullopt;
        return it->second;
    } catch (...) {
        // Allocation failure during flatten() or unordered_map probe.
        // Cache lookup is a best-effort fast-path; returning nullopt
        // forces the caller to re-discover, which is correct.
        return std::nullopt;
    }
}

void CardMap::put(const Key& key, CardMapEntry entry)
{
    try {
        std::lock_guard lock(mu);
        entries.insert_or_assign(flatten(key), std::move(entry));
    } catch (...) {
        // Allocation failure caching an entry — drop on the floor. The
        // next lookup re-discovers; correctness is preserved at the
        // cost of one extra probe.
    }
}

void CardMap::invalidate(const Key& key)
{
    try {
        std::lock_guard lock(mu);
        entries.erase(flatten(key));
    } catch (...) {
        // Same rationale as put(): swallow allocation failures during
        // key flattening. invalidate is advisory; the worst outcome of
        // a missed erase is a stale entry that the caller will detect
        // and overwrite on the next probe.
    }
}

void CardMap::invalidateAll()
{
    std::lock_guard lock(mu);
    entries.clear();
}

} // namespace LibreSCRS::SmartCard
