// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

/// @file
/// @brief @ref LibreSCRS::SmartCard::AppletAid — typed wrapper around an
///        ISO 7816-5 application identifier (AID) byte sequence.
///
/// AppletAid is a thin value type. It exists so cross-`.so` APIs (e.g.
/// @ref LibreSCRS::SecureChannel::ISecureChannel) can name the currently
/// selected applet without exposing `std::vector<std::uint8_t>` as a
/// load-bearing public type. Conversion to/from raw bytes is explicit.

#include <LibreSCRS/Export.h>

#include <compare>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <span>
#include <string>
#include <vector>

namespace LibreSCRS::SmartCard {

/// @brief Typed AID (5..16 bytes per ISO 7816-5). Stored as bytes.
///
/// Equality and ordering are byte-wise. Construction is explicit from
/// either a `std::vector<std::uint8_t>` or a `std::span<const std::uint8_t>`
/// to discourage implicit conversions from arbitrary byte sequences.
///
/// @since 4.1
class LIBRESCRS_PUBLIC_API AppletAid
{
public:
    /// @brief Default: empty (no applet selected). Use only as a sentinel.
    AppletAid() = default;

    /// @brief Construct from a byte vector.
    explicit AppletAid(std::vector<std::uint8_t> bytes) : storage(std::move(bytes)) {}

    /// @brief Construct from an initializer list (literal AIDs in code).
    AppletAid(std::initializer_list<std::uint8_t> bytes) : storage(bytes) {}

    /// @brief Factory: copy from a contiguous byte range.
    static AppletAid fromBytes(std::span<const std::uint8_t> bytes)
    {
        return AppletAid(std::vector<std::uint8_t>(bytes.begin(), bytes.end()));
    }

    /// @brief Byte view of the AID.
    [[nodiscard]] std::span<const std::uint8_t> bytes() const noexcept
    {
        return {storage.data(), storage.size()};
    }

    /// @brief Underlying storage (for builders that need a vector).
    [[nodiscard]] const std::vector<std::uint8_t>& asVector() const noexcept
    {
        return storage;
    }

    /// @brief Length of the AID in bytes (0 when no applet is set).
    [[nodiscard]] std::size_t size() const noexcept
    {
        return storage.size();
    }
    /// @brief Whether the AID is empty (sentinel for "no applet selected").
    [[nodiscard]] bool empty() const noexcept
    {
        return storage.empty();
    }

    /// @brief Lower-case hex rendering (no separators). Diagnostic use.
    [[nodiscard]] std::string toHex() const
    {
        static constexpr char kHex[] = "0123456789abcdef";
        std::string out;
        out.reserve(storage.size() * 2);
        for (std::uint8_t b : storage) {
            out.push_back(kHex[(b >> 4) & 0x0F]);
            out.push_back(kHex[b & 0x0F]);
        }
        return out;
    }

    /// @brief Byte-wise equality.
    [[nodiscard]] bool operator==(const AppletAid&) const noexcept = default;
    /// @brief Byte-wise lexicographic ordering (generates `<`, `<=`, `>`, `>=`).
    [[nodiscard]] auto operator<=>(const AppletAid&) const noexcept = default;

private:
    std::vector<std::uint8_t> storage;
};

} // namespace LibreSCRS::SmartCard
