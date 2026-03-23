// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace plugin {

enum class FieldType { Text, Date, Photo, Binary };

// Well-known group keys (convention, not enforced):
// "personal"     — demographic identity data (name, birth, nationality)
// "address"      — address/residence data
// "document"     — document metadata (serial, issuing, expiry)
// "photo"        — portrait/photo data
// "pki"          — PKI-related info (certificate count, key references)
// "vehicle"      — vehicle-specific data
// "insurance"    — health insurance data
// Cards with only PKI (e.g. PKS) may have only a "pki" group.

struct CardField
{
    std::string key;
    std::string label;
    FieldType type;
    std::vector<uint8_t> value;

    std::string asString() const
    {
        return {value.begin(), value.end()};
    }
};

struct CardFieldGroup
{
    std::string groupKey;
    std::string groupLabel;
    std::vector<CardField> fields;
};

struct CardData
{
    std::string cardType;
    std::vector<CardFieldGroup> groups;

    CardFieldGroup* findGroup(const std::string& key)
    {
        for (auto& g : groups) {
            if (g.groupKey == key)
                return &g;
        }
        return nullptr;
    }

    const CardFieldGroup* findGroup(const std::string& key) const
    {
        for (const auto& g : groups) {
            if (g.groupKey == key)
                return &g;
        }
        return nullptr;
    }

    CardField* findField(const std::string& key)
    {
        for (auto& g : groups) {
            for (auto& f : g.fields) {
                if (f.key == key)
                    return &f;
            }
        }
        return nullptr;
    }

    const CardField* findField(const std::string& key) const
    {
        for (const auto& g : groups) {
            for (const auto& f : g.fields) {
                if (f.key == key)
                    return &f;
            }
        }
        return nullptr;
    }
};

inline void addTextField(CardFieldGroup& group, const std::string& key, const std::string& label,
                         const std::string& val)
{
    if (!val.empty())
        group.fields.push_back({key, label, FieldType::Text, {val.begin(), val.end()}});
}

} // namespace plugin
