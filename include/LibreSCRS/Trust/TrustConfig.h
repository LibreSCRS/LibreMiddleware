// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

/// @file
/// @brief @ref LibreSCRS::Trust::TrustConfig — trust-material injection
///        point for @ref LibreSCRS::Signing::SigningService. Carries the
///        Trusted List sources and the directory their copies are cached in.

#include <LibreSCRS/Export.h>

#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace LibreSCRS::Trust {

/// @brief A single ETSI Trusted List that the signing engine fetches and caches at runtime.
///
/// Populate when you want runtime TL fetching (the common case for eIDAS-
/// qualified signing across multiple member states).
///
/// @par Thread-safety
/// Thread-compatible per API-POLICY §8: distinct instances are independent;
/// concurrent reads of the same instance are race-free.
struct LIBRESCRS_PUBLIC_API TrustedListSource
{
    /// @brief HTTPS URL of the Trusted List XML (or LOTL).
    std::string url;
    /// @brief True when this source is a List Of Trusted Lists (pointer to other TLs).
    bool lotl = false;
    /// @brief Fetch mode. When @c true, the engine fetches the TL eagerly at
    ///        TrustStoreService configure-time; when @c false (the 4.0
    ///        default), the engine fetches lazily at sign-time only when a
    ///        signature level actually requires the anchor.
    ///
    /// @note 4.0 defaults to @c false (lazy) so that an offline host or a
    ///       consumer that never requests a TL-dependent signature level
    ///       (B_B, for example) is not forced into a startup HTTPS round-trip.
    ///       Consumers that prefer "fail loudly at startup" for online-only
    ///       deployments can opt back into eager fetch by setting this
    ///       field to @c true per source.
    bool eager = false;

    /// @brief Defaulted byte-identity equality.
    [[nodiscard]] bool operator==(const TrustedListSource&) const noexcept = default;
};

/// @brief Declarative trust-anchor configuration passed to the
///        @ref LibreSCRS::Signing::SigningService constructor.
///
/// All fields are plain data: ETSI Trusted List sources fetched over HTTPS and
/// an optional cache directory. The bundled anchors and the system
/// certificate store always take part in chain validation.
///
/// @par Thread-safety
/// Thread-compatible per API-POLICY §8: distinct instances are independent;
/// concurrent reads of the same instance are race-free.
struct LIBRESCRS_PUBLIC_API TrustConfig
{
    /// @brief Zero or more URL-based ETSI Trusted List sources the engine fetches and caches.
    std::vector<TrustedListSource> trustedListSources;
    /// @brief Directory where the engine caches TLs fetched from @ref trustedListSources.
    /// @note When unset, the engine chooses a platform-appropriate default.
    std::optional<std::filesystem::path> cacheDirectory;

    /// @brief Defaulted byte-identity equality.
    [[nodiscard]] bool operator==(const TrustConfig&) const noexcept = default;
};

} // namespace LibreSCRS::Trust
