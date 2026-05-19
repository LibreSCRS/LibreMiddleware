// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

/// @file
/// @brief @ref LibreSCRS::SmartCard::CardMap — process-local cache of
///        per-card discovered state, populated by the first successful
///        probe and consumed by later operations on the same card.

#include <LibreSCRS/Export.h>

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <tuple>
#include <vector>

namespace LibreSCRS::SmartCard {

/// @brief Per-card discovered state cached in a @ref CardMap.
///
/// Populated by the first successful probe of a PKCS#15 layout (plugin
/// path or PKCS#11 provider path) and re-used by subsequent operations
/// against the same physical card to avoid re-running EF.DIR fallback,
/// SELECT FILE P2 probing, and PIN-label discovery on every entry point.
///
/// @par ABI export
/// Plain aggregate; carries no LIBRESCRS_PUBLIC_API annotation on the
/// type itself per API-POLICY §6.
///
/// @since 4.1
struct CardMapEntry
{
    /// @brief Resolved path to the PKCS#15 DF. Empty when the card's
    ///        applet was reachable by AID-only SELECT (no EF.DIR
    ///        fallback was required).
    std::vector<std::uint8_t> pkcs15Path;

    /// @brief Probed P2 value for SELECT FILE on this card. Defaults to
    ///        0x0C (no FCI); some cards require 0x00 instead. Stored
    ///        once the PKCS#15 probe path determines the working value.
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
/// All public methods are internally synchronised by a single mutex
/// held inside the pimpl body.
///
/// @par Implementation hiding
/// Backing storage (mutex + hash table) lives behind a pimpl so the
/// public header does not transitively pull `<mutex>` /
/// `<unordered_map>` into downstream SDK consumers. The class is move-
/// only (the underlying mutex is non-copyable; copying a cache also has
/// no obvious correct semantics).
///
/// @since 4.1
class LIBRESCRS_PUBLIC_API CardMap
{
public:
    /// @brief Composite cache key: `(reader, atrHex, serial)`.
    using Key = std::tuple<std::string, std::string, std::string>;

    /// @brief Construct an empty cache.
    /// @since 4.1
    CardMap();
    /// @brief Destroy and release every cached entry. Cleansing is not
    ///        required — discovered state is not secret material.
    /// @since 4.1
    ~CardMap();

    CardMap(const CardMap&) = delete;
    CardMap& operator=(const CardMap&) = delete;
    CardMap(CardMap&&) noexcept;
    CardMap& operator=(CardMap&&) noexcept;

    /// @brief Look up the cached entry for @p key.
    /// @return The entry if present; @c std::nullopt otherwise.
    /// @par Thread-safety + noexcept contract
    /// @c noexcept: the implementation wraps allocations (in `flatten`
    /// / @c unordered_map probe) in a top-level catch and degrades to
    /// @c std::nullopt on failure rather than letting @c std::bad_alloc
    /// escape and call @c std::terminate. Mutex acquisition cannot throw
    /// on an uncontended @c std::mutex (libstdc++ / libc++ — see
    /// PKCS11Slot::isLoggedIn for the same reliance).
    [[nodiscard]] std::optional<CardMapEntry> get(const Key& key) const noexcept;

    /// @brief Install or overwrite the entry for @p key.
    /// @par noexcept contract
    /// Allocation failures during `flatten` / `insert_or_assign` are
    /// caught and the entry is dropped silently; subsequent lookups
    /// re-discover, preserving correctness at the cost of one extra
    /// probe. The bad_alloc never escapes this @c noexcept boundary.
    void put(const Key& key, CardMapEntry entry) noexcept;

    /// @brief Remove the entry for @p key (no-op if absent).
    /// @par noexcept contract
    /// Same as @ref put: any allocation failure during `flatten` /
    /// `erase` is caught; the worst outcome is a stale entry that the
    /// caller will overwrite on the next @ref put.
    void invalidate(const Key& key) noexcept;

    /// @brief Drop every cached entry. Typically used at provider
    ///        teardown / `C_Finalize` time.
    void invalidateAll() noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> d;
};

} // namespace LibreSCRS::SmartCard
