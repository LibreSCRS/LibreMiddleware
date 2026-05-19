// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

/// @file
/// @brief @ref LibreSCRS::Trust::TrustStore — opaque trust-anchor store
///        composed from bundled, Trusted-List-derived, and (optionally) OS
///        system anchors. Public surface is read-only; LM-internal code
///        constructs and grows it via friend access (see implementation).

#include <LibreSCRS/Export.h>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace LibreSCRS::Trust {

/// @brief Non-owning view over a single DER-encoded certificate.
/// @since 4.0
using CertificateView = std::span<const std::uint8_t>;

/// @brief Resolved trust anchor — DER-encoded certificate plus provenance label.
///
/// The label encodes where the anchor came from for diagnostics and audit;
/// callers must not parse it as a structured identifier.
///
/// @par Thread-safety
/// Thread-compatible per API-POLICY §8: distinct instances are independent;
/// concurrent reads of the same instance are race-free.
///
/// @since 4.0
struct LIBRESCRS_PUBLIC_API TrustAnchor
{
    /// @brief DER-encoded X.509 certificate bytes.
    std::vector<std::uint8_t> certificateDer;
    /// @brief Human-readable provenance tag (e.g. "bundled:root-CA-A",
    ///        "tl:rs-mit-2026-04"). Diagnostics only — do not parse.
    std::string sourceLabel;

    /// @brief Defaulted byte-identity equality.
    [[nodiscard]] bool operator==(const TrustAnchor&) const noexcept = default;
};

namespace detail {
/// @brief LM-internal access struct, forward-declared for friend mechanism.
/// @note Definition lives in an LM-internal header and is not reachable
///       through the public include path. External consumers cannot
///       construct or use it.
struct TrustStoreInternalAccess;
} // namespace detail

/// @brief Composed trust-anchor store used by LibreSCRS::Signing for chain
///        validation and hierarchy queries, and by plugin runtime for
///        card-data signature verification.
///
/// Public callers obtain instances via @ref LibreSCRS::Trust::TrustStoreService::trustStore
/// (the unified async trust surface in 4.0). The class is
/// move-only with a private constructor; LM-internal code constructs and
/// grows it via the LM-internal `detail::TrustStoreInternalAccess` shim
/// (defined in an internal header that is not part of the public include path).
///
/// @par Thread-safety
/// Thread-safe (see API-POLICY §8). Public read methods (@ref validateChain,
/// @ref findIssuerOf, @ref enumerableAnchors) are protected by an internal
/// shared mutex; they may be called concurrently from multiple threads.
/// LM-internal mutation paths take an exclusive lock.
///
/// @since 4.0
class LIBRESCRS_PUBLIC_API TrustStore
{
public:
    /// @brief Outcome of validating a certificate chain against this store.
    ///
    /// @note When the owning @ref TrustStoreService still has eager-fetch
    ///       work in flight, an anchor that is in the process of being
    ///       fetched and merged is not yet present in the store; a chain
    ///       whose root depends on that anchor will validate to
    ///       ChainStatus::UntrustedRoot until the merge completes. Consumers that
    ///       must distinguish "really untrusted" from "still loading"
    ///       query @ref LibreSCRS::Trust::TrustStoreService::status()
    ///       (or @ref LibreSCRS::Trust::TrustStoreService::sourceStatuses())
    ///       in addition to inspecting the @ref ChainStatus value. Doing
    ///       the disambiguation on the consumer side avoids a back-pointer
    ///       cycle from @ref TrustStore into @ref TrustStoreService and
    ///       keeps the validation surface free of an Unsettled value that
    ///       only makes sense for online sources.
    ///
    /// @note Append-only per API-POLICY §9 — new outcome values land at
    ///       the tail and consumers' switches MUST close over every value
    ///       or carry a default-branch.
    enum class ChainStatus {
        Trusted,
        UntrustedRoot,
        BrokenChain,
        InvalidCertificate,
        Expired,
    };

    ~TrustStore();
    TrustStore(const TrustStore&) = delete;
    TrustStore& operator=(const TrustStore&) = delete;
    /// @brief Move-construct, transferring the pimpl.
    TrustStore(TrustStore&&) noexcept;
    /// @brief Move-assign, transferring the pimpl.
    TrustStore& operator=(TrustStore&&) noexcept;

    /// @brief True when this object holds a valid (non-moved-from) pimpl.
    explicit operator bool() const noexcept;

    /// @brief Validate certificate chain (leaf first) against this store.
    /// @since 4.0
    [[nodiscard]] ChainStatus validateChain(std::span<const CertificateView> chain) const;

    /// @brief Find the issuer of @p certDer among trust anchors.
    /// @return The matching anchor when known; nullopt otherwise.
    /// @note Searches enumerable anchors only; OS system store entries
    ///       are opaque and not exposed via this API.
    /// @since 4.0
    [[nodiscard]] std::optional<TrustAnchor> findIssuerOf(CertificateView certDer) const;

    /// @brief Snapshot of enumerable trust anchors (bundled + TL-derived).
    /// @note OS system store entries are opaque and excluded from this list,
    ///       but they still participate in @ref validateChain.
    /// @since 4.0
    [[nodiscard]] std::vector<TrustAnchor> enumerableAnchors() const;

private:
    struct Impl;
    std::unique_ptr<Impl> d;

    explicit TrustStore(std::unique_ptr<Impl> impl);
    friend struct detail::TrustStoreInternalAccess;
};

} // namespace LibreSCRS::Trust
