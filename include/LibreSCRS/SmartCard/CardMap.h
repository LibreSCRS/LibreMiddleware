// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

/// @file
/// @brief @ref LibreSCRS::SmartCard::CardMap — process-local cache of
///        per-card discovered state, populated by the first successful
///        probe and consumed by later operations on the same card.

#include <LibreSCRS/Export.h>

#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <tuple>
#include <unordered_map>
#include <vector>

namespace LibreSCRS::SmartCard {

/// @brief Per-card discovered state cached in a @ref CardMap.
///
/// Populated by the first successful probe of a PKCS#15 layout (plugin
/// path or PKCS#11 provider path) and re-used by subsequent operations
/// against the same physical card to avoid re-running EF.DIR fallback,
/// SELECT FILE P2 probing, and PIN-label discovery on every entry point.
///
/// @since 4.1
struct LIBRESCRS_PUBLIC_API CardMapEntry
{
    /// @brief Resolved path to the PKCS#15 DF. Empty when the card's
    ///        applet was reachable by AID-only SELECT (no EF.DIR
    ///        fallback was required).
    std::vector<std::uint8_t> pkcs15Path;

    /// @brief Probed P2 value for SELECT FILE on this card. Defaults to
    ///        0x0C (no FCI); some cards require 0x00 instead. Stored
    ///        once @ref pkcs15::PKCS15Card::probe() determines the
    ///        working value.
    std::uint8_t fileSelectP2 = 0x0C;

    /// @brief PIN labels discovered in the AODF. Optional informational
    ///        field for consumers that want to surface the same labels
    ///        without re-parsing.
    std::vector<std::string> pinLabels;
};

/// @brief Process-local cache of per-card discovered state.
///
/// Keyed by the tuple `(reader, atrHex, serial)` — `serial` may be empty
/// for cards whose serial is not yet known at first probe; in that case
/// the cache is effectively keyed by reader+ATR until the serial is
/// resolved.
///
/// @par Ownership
/// CardMap is intended for shared ownership across actors that touch the
/// same card from different angles (CardPlugin entries and PKCS#11
/// providers). It is NOT a global singleton; consumers receive a
/// `std::shared_ptr<CardMap>` via constructor injection per the
/// project-wide DI policy.
///
/// @par Lifetime
/// Entries are invalidated explicitly via @ref invalidate (typically
/// on `cardRemoved` events from
/// @ref LibreSCRS::SmartCard::MonitorService) or via @ref invalidateAll
/// during a context-wide reset.
///
/// @par Thread-safety
/// All public methods are internally synchronised by a single mutex.
/// Concurrent readers and writers are safe.
///
/// @since 4.1
class LIBRESCRS_PUBLIC_API CardMap
{
public:
    /// @brief Composite cache key: `(reader, atrHex, serial)`.
    using Key = std::tuple<std::string, std::string, std::string>;

    /// @brief Look up the cached entry for @p key.
    /// @return The entry if present; @c std::nullopt otherwise.
    [[nodiscard]] std::optional<CardMapEntry> get(const Key& key) const;

    /// @brief Install or overwrite the entry for @p key.
    void put(const Key& key, CardMapEntry entry);

    /// @brief Remove the entry for @p key (no-op if absent).
    void invalidate(const Key& key);

    /// @brief Drop every cached entry. Typically used at provider
    ///        teardown / `C_Finalize` time.
    void invalidateAll();

private:
    mutable std::mutex mu;
    std::unordered_map<std::string, CardMapEntry> entries;
};

} // namespace LibreSCRS::SmartCard
