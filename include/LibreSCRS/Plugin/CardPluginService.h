// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

/// @file
/// @brief @ref LibreSCRS::Plugin::CardPluginService — loads card plugin
///        shared objects on construction and answers ATR / AID lookups —
///        together with the structured @ref LibreSCRS::Plugin::LoadOutcome
///        report produced per plugin file scanned.

#include <LibreSCRS/Export.h>
#include <LibreSCRS/Plugin/CardPlugin.h>

#include <cstdint>
#include <filesystem>
#include <memory>
#include <span>
#include <string>
#include <vector>

// Forward decl — registry takes shared_ptr<const TrustStore> at construction.
namespace LibreSCRS::Trust {
class TrustStore;
}

namespace LibreSCRS::Plugin {

/// @brief Structured report of the outcome of loading a single plugin `.so`
///        from disk.
///
/// A @ref CardPluginService records one entry per regular file scanned in
/// every directory passed to its constructor (including files whose extension
/// rules them out — those are simply not represented, only candidates are
/// reported). The registry's @ref CardPluginService::loadReport accessor
/// returns the full list; callers iterate it to surface plugin-loading
/// issues to users or logs instead of silently observing an empty registry.
///
struct LoadOutcome
{
    /// @brief Absolute path to the plugin `.so` / `.dylib` that was probed.
    std::filesystem::path soPath;

    /// @brief Plugin identifier reported by a successfully loaded plugin.
    /// Empty string on any failure status.
    std::string pluginId;

    /// @brief Enumeration of possible outcomes when loading a single plugin.
    enum class Status : std::uint8_t {
        /// Plugin loaded and registered successfully.
        Loaded,
        /// `dlopen()` failed (file not readable, unresolved symbols, etc.).
        DlopenFailed,
        /// The `.so` does not export `card_plugin_abi_version` or
        /// `create_card_plugin`.
        MissingFactory,
        /// `card_plugin_abi_version()` returned a value different from
        /// `kCardPluginAbiVersion`.
        AbiMismatch,
        /// `create_card_plugin()` threw or returned nullptr.
        FactoryThrew,
    };

    /// @brief Outcome of the load attempt for this shared object. Defaults
    ///        to @ref Status::Loaded on successful construction.
    Status status = Status::Loaded;

    /// @brief Human-readable failure detail. Empty on success.
    /// Example values: `dlerror()` text on `DlopenFailed`, "expected ABI N
    /// got M" on `AbiMismatch`.
    std::string diagnostic;

    /// @brief Defaulted member-wise equality.
    [[nodiscard]] bool operator==(const LoadOutcome&) const noexcept = default;
};

/// @brief Loads card-plugin `.so` files from one or more directories on
///        construction and dispatches card lookups against the loaded set.
///
/// Owns the `dlopen` handles and plugin instances.
///
/// @par Thread-safety
/// Thread-safe (see API-POLICY §8). All accessors (@ref findPluginForCard,
/// @ref findAllCandidates, @ref plugins, @ref size, @ref loadReport) may be
/// called concurrently from multiple consumer threads — internal state is
/// guarded by an internal mutex held only briefly during a snapshot.
/// Mutation is confined to construction and destruction; once a registry
/// is constructed its plugin set is immutable.
///
/// @par Construction
/// Construction is the only load point — the registry does not expose a
/// mutable setter. Pass a list of directories via the `std::span` ctor, or
/// a single directory via the convenience overload. Any plugin that fails
/// to load is captured in the @ref loadReport with a @ref LoadOutcome::Status
/// indicating the failure mode; the registry itself never throws on a bad
/// plugin file (the only way construction can throw is an internal
/// allocation failure).
///
/// @par Ownership
/// @ref plugins and the @ref findAllCandidates overloads return
/// `std::vector<std::shared_ptr<CardPlugin>>`. The shared_ptr's custom
/// deleter runs the plugin's virtual destructor and then calls `dlclose`
/// on the handle, so the underlying SO stays mapped at least until the
/// last external reference is dropped — shared ownership eliminates the
/// "registry owns, callers alias with a no-op-deleter" footgun at the
/// @ref LibreSCRS::Signing::SigningService::sign seam.
class LIBRESCRS_PUBLIC_API CardPluginService
{
public:
    /// @brief Construct registry and eagerly load plugins from each of the
    ///        supplied directories in order.
    /// @param dirs Span of directory paths. Each is scanned for
    ///             `.so` / `.dylib` files; every regular file with one of
    ///             those extensions generates a @ref LoadOutcome entry.
    ///             `dlopen` failures, ABI mismatches, missing factory
    ///             entry points, and factory exceptions are captured in
    ///             @ref loadReport rather than propagated. A directory
    ///             that does not exist is not fatal and simply contributes
    ///             no entries.
    ///
    /// @note Multi-directory support is the primary reason for the
    ///       `std::span` shape — LibreCelik composes middleware-plugins
    ///       with GUI plugin directories at startup; each directory may
    ///       live under an install root or a build tree.
    ///
    /// @note Callers that pass a single directory inline can use the
    ///       convenience single-path overload below.
    /// @param trustStore Optional unified trust store (typically obtained
    ///        from #LibreSCRS::Trust::TrustStoreService::trustStore).
    ///        When non-null, the registry calls @ref CardPlugin::setTrustStore
    ///        on every successfully-loaded plugin immediately after load
    ///        and before exposing it via @ref plugins or any candidate-lookup
    ///        method. When nullptr (the default), plugins fall back to
    ///        whatever bundled trust mechanism they shipped with.
    /// @since 4.0. Call sites that omit the trustStore argument retain that
    ///         fallback behaviour.
    explicit CardPluginService(std::span<const std::filesystem::path> dirs,
                               std::shared_ptr<const LibreSCRS::Trust::TrustStore> trustStore = nullptr);

    /// @brief Convenience single-directory constructor. Equivalent to the
    ///        `std::span` ctor with a single-element range.
    ///
    /// @note Overload-resolution guarantees: a bare path literal (e.g.
    ///       `CardPluginService reg{"./plugins"}`) or an inline
    ///       `std::filesystem::path` argument selects THIS single-path ctor.
    ///       Two or more paths must be passed through the
    ///       `std::span`-based overload — either via a braced initialiser list aliased through
    ///       an explicit `std::vector<std::filesystem::path>` / array, or via
    ///       a named `std::span` local. A naïve
    ///       `CardPluginService{ {"a", "b"} }` is ill-formed; prefer
    ///       `std::vector<std::filesystem::path> dirs{"a", "b"};
    ///       CardPluginService reg{dirs};` to make the intent explicit at
    ///       the call site.
    explicit CardPluginService(std::filesystem::path dir,
                               std::shared_ptr<const LibreSCRS::Trust::TrustStore> trustStore = nullptr);

    /// @brief Unloads all plugin shared objects. Individual plugins are
    ///        destroyed as their owning `shared_ptr`s drop — which may be
    ///        after this destructor runs if external `shared_ptr<CardPlugin>`
    ///        handles obtained via @ref plugins or @ref findAllCandidates
    ///        are still alive.
    ~CardPluginService();

    CardPluginService(const CardPluginService&) = delete;
    CardPluginService& operator=(const CardPluginService&) = delete;

    /// @brief Move-constructs from another registry. The source registry is
    ///        left in a valid but empty state (no plugins, empty load report).
    CardPluginService(CardPluginService&&) noexcept;

    /// @brief Move-assigns from another registry. Existing plugins are
    ///        released per the standard shared_ptr unwinding rules.
    CardPluginService& operator=(CardPluginService&&) noexcept;

    /// @brief Publish the directory of country-signing (CSCA) certificates
    ///        this host holds to every plugin the registry loaded.
    ///
    /// Forwards @p dir to @ref CardPlugin::setCscaAnchorDirectory on each
    /// loaded plugin; plugins with nothing to verify against country signing
    /// certificates simply never read it. Read that method before this one —
    /// it carries why the value has to arrive through an interface rather
    /// than be looked up, and what happens when nobody calls this at all.
    ///
    /// @par Why this is not a constructor argument
    /// The @ref TrustStore is one, because a host knows it before it loads
    /// plugins. This one it may not: the Linux agent builds its registry at
    /// the top of @c main and only assembles the configuration that names
    /// this directory later, once the bus object exists — so a constructor
    /// argument could only be filled from a path guessed ahead of the
    /// configuration, which is how the two halves of this feature came to
    /// disagree in the first place. Publication is therefore separate from
    /// loading, and this method loads nothing: the plugin set is still fixed
    /// at construction.
    ///
    /// @par Single-shot
    /// Enforced per plugin by @ref CardPlugin::setCscaAnchorDirectory, so
    /// calling this twice publishes the FIRST directory and silently ignores
    /// the second. Deliberate: see that method's "Lifecycle".
    ///
    /// @par Thread-safety
    /// Thread-safe. Takes the registry's read lock (the plugin set is not
    /// modified) and each plugin serialises its own publication.
    /// @since 4.3
    void setCscaAnchorDirectory(const std::filesystem::path& dir);

    /// @brief Fast lookup by ATR bytes (no card I/O).
    /// @return The matching plugin with the smallest @ref CardPlugin::probePriority
    ///         integer (lower numbers are probed first — "highest priority"
    ///         means the smallest numeric value), or nullptr if no plugin's
    ///         @ref CardPlugin::canHandle returns true for @p atr.
    /// @since 4.0 — `atr` is a @c std::span<const std::uint8_t> for
    ///        consistency with @ref CardPlugin::canHandle, @ref Atr::matches,
    ///        and @ref CardPlugin::supportedAtrs.
    [[nodiscard]] std::shared_ptr<CardPlugin> findPluginForCard(std::span<const std::uint8_t> atr) const;

    /// @brief ATR-only overload (fast, no card I/O).
    ///
    /// Returns all plugins where canHandle(atr) returns true, sorted by
    /// priority (ascending).
    /// @since 4.0 — `atr` parameter type @c std::span<const std::uint8_t>;
    ///        see @ref findPluginForCard.
    [[nodiscard]] std::vector<std::shared_ptr<CardPlugin>> findAllCandidates(std::span<const std::uint8_t> atr) const;

    /// @brief Two-phase candidate lookup: ATR match first, then AID probe
    ///        on the live @p session for any plugin that did not match by
    ///        ATR.
    /// @return De-duplicated list of candidates; ATR matches are ordered
    ///         before AID matches, each group sorted by priority.
    /// @since 4.0 — `atr` parameter type @c std::span<const std::uint8_t>;
    ///        see @ref findPluginForCard.
    [[nodiscard]] std::vector<std::shared_ptr<CardPlugin>>
    findAllCandidates(std::span<const std::uint8_t> atr, LibreSCRS::SmartCard::CardSession& session) const;

    /// @brief Snapshot of all loaded plugins, sorted by
    ///        @ref CardPlugin::probePriority (ascending).
    /// @return Owned vector of shared-ownership handles. Iterating the
    ///         returned vector is safe outside any registry lock — each
    ///         `shared_ptr` carries its own reference count.
    /// @note Returns by value: the lock is held only while snapshotting
    ///       (a handful of shared_ptr increments), and consumers can
    ///       freely iterate afterwards without blocking a concurrent
    ///       registry access.
    [[nodiscard]] std::vector<std::shared_ptr<CardPlugin>> plugins() const;

    /// @brief Number of successfully loaded plugins.
    [[nodiscard]] std::size_t size() const noexcept;

    /// @brief Reports whether the registry has at least one usable plugin.
    ///
    /// Returns `true` iff `size() > 0` AND every entry in @ref loadReport
    /// has @ref LoadOutcome::Status::Loaded. A `false` result means either
    /// the registry directory was empty, every plugin failed to load (ABI
    /// mismatch, dlopen failure, etc.), or some subset failed and the
    /// caller may wish to surface a diagnostic instead of treating
    /// "no matching plugin for this ATR" as the explanation.
    ///
    /// @par Thread-safety
    /// Thread-safe. Pure read of the immutable post-construction snapshot;
    /// no locking required.
    /// @since 4.0
    [[nodiscard]] bool isUsable() const noexcept;

    /// @brief Structured load report — one entry per `.so` / `.dylib`
    ///        candidate scanned across every directory passed to the
    ///        constructor.
    ///
    /// Iterate this to surface plugin-loading diagnostics (failed to
    /// load, ABI mismatch, etc.) to logs or a UI; the registry does not
    /// log anything by itself beyond the structured report.
    [[nodiscard]] const std::vector<LoadOutcome>& loadReport() const noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> d;
};

} // namespace LibreSCRS::Plugin
