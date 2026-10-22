// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

// The test cards of the CryptoTokenKit hardware checks, chosen only by the
// prefix of the ATR the slot manager reports without a session, and the
// environment the checks read. Shared by every hardware binary that must not
// touch a card it does not recognise.

#include "ctk_hw_probe.h"

#include <cstdint>
#include <cstdlib>
#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace LibreSCRS::Tests::CtkHw {

// test LK, contact (SCE 8.0-C2V0)
inline constexpr const char* kLkContact = "3BDE97008031FE4553434520382E302D43325630";
// test LK, contactless (SRB-eID-V2.00)
inline constexpr const char* kLkContactless = "3B8D80015352422D6549442D56322E3030";
// GEO test card, contactless
inline constexpr const char* kGeoContactless = "3B8E800153434520382E302D43325630";
// GEO test card, contact
inline constexpr const char* kGeoContact = "3B9E968031FE4553434520382E302D43325630";

inline std::optional<std::string> envOpt(const char* name)
{
    const char* value = std::getenv(name);
    if (value == nullptr || value[0] == '\0')
        return std::nullopt;
    return std::string(value);
}

inline long envLong(const char* name, long fallback)
{
    const auto value = envOpt(name);
    if (!value)
        return fallback;
    char* end = nullptr;
    const long parsed = std::strtol(value->c_str(), &end, 0);
    return end != nullptr && *end == '\0' ? parsed : fallback;
}

inline std::string hex(std::span<const std::uint8_t> bytes)
{
    static constexpr char kDigits[] = "0123456789ABCDEF";
    std::string out;
    out.reserve(bytes.size() * 2);
    for (const auto b : bytes) {
        out.push_back(kDigits[(b >> 4) & 0x0F]);
        out.push_back(kDigits[b & 0x0F]);
    }
    return out;
}

inline std::string upper(std::string text)
{
    for (auto& c : text)
        if (c >= 'a' && c <= 'f')
            c = static_cast<char>(c - 'a' + 'A');
    return text;
}

inline bool atrHasPrefix(std::span<const std::uint8_t> atr, std::string_view hexPrefix)
{
    const auto atrHex = hex(atr);
    return !hexPrefix.empty() && atrHex.size() >= hexPrefix.size() &&
           atrHex.compare(0, hexPrefix.size(), hexPrefix) == 0;
}

/// The first slot holding a valid card whose ATR, read without a session,
/// starts with @p hexPrefix.
inline std::optional<std::string> slotWithAtrPrefix(std::string_view hexPrefix)
{
    const auto prefix = upper(std::string(hexPrefix));
    for (const auto& slot : passiveSlots())
        if (slot.state == SlotState::ValidCard && atrHasPrefix(slot.atr, prefix))
            return slot.name;
    return std::nullopt;
}

} // namespace LibreSCRS::Tests::CtkHw
