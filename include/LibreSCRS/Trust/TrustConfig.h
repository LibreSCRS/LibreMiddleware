// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

/// @file
/// @brief @ref LibreSCRS::Trust::TrustConfig — trust-material injection
///        point for @ref LibreSCRS::Signing::SigningService. Carries the
///        offline TL cache location, bundled anchors, system-store toggle,
///        and TSA trust-root toggles.

#include <LibreSCRS/Export.h>

#include <filesystem>
#include <optional>
#include <string>
#include <type_traits>
#include <vector>

namespace LibreSCRS::Trust {

/// @brief A single ETSI Trusted List that the signing engine fetches and caches at runtime.
///
/// Populate when you want runtime TL fetching (the common case for eIDAS-
/// qualified signing across multiple member states). For pre-fetched TL files
/// on disk, use @ref TrustConfig::trustedListFile instead.
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
/// All fields are plain data. The shipped 4.0 surface matches what the underlying
/// libresign engine actually forwards: ETSI Trusted List sources (URL-fetched
/// and/or pre-fetched on disk) plus an optional cache directory. Directory /
/// file / system-store trust sources and per-source revocation timeouts are
/// tracked for 4.1+; they were removed from 4.0 because the engine silently
/// ignored them, which is a security risk for SDK consumers assuming their
/// trust policy applied.
///
/// @par Thread-safety
/// Thread-compatible per API-POLICY §8: distinct instances are independent;
/// concurrent reads of the same instance are race-free.
struct LIBRESCRS_PUBLIC_API TrustConfig
{
    /// @brief Optional pre-fetched ETSI Trusted List XML file on disk.
    std::optional<std::filesystem::path> trustedListFile;
    /// @brief Optional signing certificate (PEM or DER) used to verify the
    ///        XML-DSig on @ref trustedListFile. When unset, the engine falls
    ///        back to the pinned-cert table for production TLs; for
    ///        hermetic test fixtures (synthetic TLs signed with a test key)
    ///        this MUST point at the matching test cert. Ignored unless
    ///        @ref trustedListFile is also set.
    /// @since 4.0
    std::optional<std::filesystem::path> trustedListFileSigningCert;
    /// @brief Zero or more URL-based ETSI Trusted List sources the engine fetches and caches.
    /// @note When both @ref trustedListFile and @ref trustedListSources are set,
    ///       both are honoured — the union forms the trust anchor set.
    std::vector<TrustedListSource> trustedListSources;
    /// @brief Directory where the engine caches TLs fetched from @ref trustedListSources.
    /// @note When unset, the engine chooses a platform-appropriate default.
    std::optional<std::filesystem::path> cacheDirectory;

    /// @brief Include the OS system trust store in the resolved TrustStore.
    /// @note Default true. Air-gapped or strictly-controlled QES scenarios
    ///       can opt out by setting false. When false, only bundled anchors
    ///       and Trusted-List-derived anchors participate in chain validation.
    /// @since 4.0
    bool includeSystemTrustStore = true;

    /// @brief Defaulted byte-identity equality.
    [[nodiscard]] bool operator==(const TrustConfig&) const noexcept = default;

    class Builder;
};

/// @brief Fluent builder that validates and produces a @ref TrustConfig.
///
/// Setters return a reference to the builder; each setter performs
/// per-argument validation eagerly and throws @c std::invalid_argument on
/// the spot. @ref build is rvalue-qualified — use
/// @c std::move(builder).build() — and is @c noexcept once every setter
/// has succeeded.
///
/// @par Validation policy
/// Per API-POLICY §5.1, each setter validates its argument when called and
/// throws @c std::invalid_argument with a message identifying the offending
/// field. The @ref build call is then assembly-only: every invariant
/// enforceable at the per-setter level is enforced there. Contrast with
/// @ref LibreSCRS::Signing::SigningRequest::Builder, which validates
/// inside @c build because its invariants span multiple fields (e.g.
/// @c visualParams requires @c format==PAdES). @ref TrustConfig has no
/// cross-field invariants — every field is independent — so per-setter
/// validation alone covers the surface.
///
/// @par Direct aggregate construction still supported
/// The aggregate @ref TrustConfig remains a plain-data struct with public
/// fields; existing callers that prefer designated-initialiser syntax
/// (`TrustConfig{.includeSystemTrustStore = false}`) continue to compile.
/// The Builder is the recommended path for inputs that benefit from
/// validation (HTTPS URLs, on-disk paths) and for SDK consumers who want
/// the discoverability of fluent setters.
///
/// @par Thread-safety
/// Thread-compatible (see API-POLICY §8). A single Builder instance is not
/// internally synchronised and is intended for single-thread use during
/// configuration. Distinct Builder instances are independent.
///
/// @since 4.0
class LIBRESCRS_PUBLIC_API TrustConfig::Builder
{
public:
    /// @brief Default-construct an empty Builder.
    Builder();
    /// @brief Destroy the Builder; built #TrustConfig snapshots are unaffected.
    ~Builder();
    Builder(const Builder&) = delete;
    Builder& operator=(const Builder&) = delete;
    /// @brief Move-construct, transferring the in-progress configuration.
    Builder(Builder&&) noexcept;
    /// @brief Move-assign, transferring the in-progress configuration.
    Builder& operator=(Builder&&) noexcept;

    /// @brief Append a URL-based ETSI Trusted List source.
    /// @param url   HTTPS URL of the Trusted List XML (or LOTL).
    /// @param isLotl @c true when @p url points at a List-Of-Trusted-Lists.
    /// @param eager @c true to fetch eagerly at TrustStoreService
    ///              construction; @c false (default) defers fetch to first
    ///              sign-time use that requires the anchor.
    /// @throws std::invalid_argument if @p url is empty, does not begin with
    ///         @c "http://" or @c "https://", or duplicates an already-added
    ///         source. See API-POLICY §5.1.
    /// @return @c *this for chaining.
    Builder& addTrustedListSource(std::string url, bool isLotl = false, bool eager = false);

    /// @brief Set the directory where TLs fetched from URL sources are cached.
    /// @param path Directory to use for TL cache files. The directory is
    ///             created on first use; the parent must exist and be
    ///             writable. Pass an empty path to clear a previously-set
    ///             cache directory.
    /// @throws std::invalid_argument if @p path's parent directory is not
    ///         present (an existing path that is not writable triggers a
    ///         runtime error at fetch time, not here, since per-mount
    ///         permissions vary across platforms). See API-POLICY §5.1.
    /// @return @c *this for chaining.
    Builder& setCacheDirectory(std::filesystem::path path);

    /// @brief Toggle inclusion of the OS system trust store.
    /// @param include @c true to include the system store (default), @c false
    ///                to restrict the trust set to bundled + TL-derived
    ///                anchors only.
    /// @return @c *this for chaining.
    Builder& setIncludeSystemTrustStore(bool include) noexcept;

    /// @brief Set a pre-fetched ETSI Trusted List XML file on disk.
    /// @param path Path to the TL file. The file must exist and be readable
    ///             at the time of the setter call.
    /// @throws std::invalid_argument if @p path does not refer to an
    ///         existing regular file. See API-POLICY §5.1.
    /// @return @c *this for chaining.
    Builder& setTrustedListFile(std::filesystem::path path);

    /// @brief Set the optional signing certificate that verifies the
    ///        XML-DSig on @ref setTrustedListFile's file.
    /// @param path Path to a PEM- or DER-encoded X.509 certificate. The
    ///             file must exist and be readable.
    /// @throws std::invalid_argument if @p path does not refer to an
    ///         existing regular file. See API-POLICY §5.1.
    /// @return @c *this for chaining.
    Builder& setTrustedListFileSigningCert(std::filesystem::path path);

    /// @brief Consume the builder and return a configured @ref TrustConfig.
    /// @note Conditionally @c noexcept on @c TrustConfig's move constructor:
    ///       all input invariants are checked at setter-invocation time per
    ///       API-POLICY §5.1, so the assembly itself is logically
    ///       infallible. The qualifier propagates whatever allocation /
    ///       throw guarantees the underlying @ref TrustConfig type carries,
    ///       so future fields with non-noexcept moves degrade the contract
    ///       honestly instead of silently terminating via the previous
    ///       hard-coded @c noexcept.
    [[nodiscard]] TrustConfig build() && noexcept(std::is_nothrow_move_constructible_v<TrustConfig>);

private:
    TrustConfig cfg;
};

} // namespace LibreSCRS::Trust
