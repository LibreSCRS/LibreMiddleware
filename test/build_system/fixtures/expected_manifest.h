// Generated from manifest.json. Do not edit.
#pragma once
#include <LibreSCRS/Plugin/PluginTypes.h>
#include <array>
#include <cstdint>
#include <optional>
#include <string_view>
#include <vector>

namespace LibreSCRS::Plugin::generated::rs_eid {

inline constexpr std::string_view kPluginId    = "rs-eid";
inline constexpr std::string_view kDisplayName = "Serbian electronic ID";
inline constexpr CardCapabilities kCapabilities = CardCapabilities::PKI | CardCapabilities::PinManagement;

inline const std::array<Atr, 2> kAtrs{{
    Atr{ {0x3B, 0x9F, 0x96, 0x80, 0x0A, 0xB0, 0x8B}, std::nullopt },
    Atr{ {0x3B, 0x9F, 0x96, 0x80, 0x0A, 0xB0, 0x8B, 0x00, 0x00}, std::optional<std::vector<std::uint8_t>>{std::vector<std::uint8_t>{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00}} }
}};

} // namespace LibreSCRS::Plugin::generated::rs_eid
