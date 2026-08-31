// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "probe_order.h"

#include <LibreSCRS/Plugin/CardPluginService.h>

#include <LibreSCRS/Export.h>

#include "probe_trace.h"

#include <algorithm>
#include <array>
#include <dlfcn.h>
#include <exception>
#include <iostream>
#include <memory>
#include <mutex>
#include <set>
#include <shared_mutex>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>

namespace LibreSCRS::Plugin {

namespace {

using CreateFunc = CardPlugin* (*)();
using DestroyFunc = void (*)(CardPlugin*);
using AbiVersionFunc = uint32_t (*)();

// POSIX RAII for the dlopen handle. Defined TU-local on purpose so the
// project-wide `*LibreSCRS::*` visibility glob (cmake/librescrs-public-
// exports.map) does not promote the inline template instantiations into
// the libLibreSCRS_Plugin.so export surface. Keeps the SO handle alive
// across throwable allocations between dlopen and the shared_ptr handoff.
struct DlCloser
{
    void operator()(void* handle) const noexcept
    {
        if (handle) {
            ::dlclose(handle);
        }
    }
};
using DlHandle = std::unique_ptr<void, DlCloser>;

// Free function at file scope — the std::shared_ptr custom deleter does not
// capture, so no Impl-dependent closure type leaks. Both the SO handle and
// the plugin-side destroy function pointer are passed by value so the
// deleter remains valid even after all other references to the registry
// are gone. Order matters: destroy the plugin (runs its virtual destructor
// against code still mapped in the SO, using the plugin's own allocator)
// BEFORE dlclose.
//
// ABI v6 requirement: plugins export destroy_card_plugin so the deletion
// happens inside the plugin's own translation unit. Without this, when the
// host and plugin were compiled against different C++ standard-library
// copies, the raw `delete` here would reach into the host's allocator for
// storage produced by the plugin's allocator — a classic cross-stdlib
// free-list mismatch crash. The plugin-side destroy_card_plugin matches
// the create_card_plugin allocator by construction.
void destroyLoadedPlugin(CardPlugin* plugin, DestroyFunc destroy, void* handle) noexcept
{
    if (plugin) {
        // destroy MUST be non-null here: loadDirectory rejects plugins that
        // don't export the symbol (LoadOutcome::Status::MissingFactory),
        // so the registry never constructs a LoadedPlugin with a null
        // deleter. The defensive check below covers the catch-path in
        // loadDirectory where a shared_ptr construction threw *after*
        // createFunc succeeded — we still need to release the instance
        // via the plugin's allocator.
        if (destroy) {
            destroy(plugin);
        }
    }
    if (handle) {
        ::dlclose(handle);
    }
}

} // namespace

// -----------------------------------------------------------------------------
// CardPluginService::Impl — hidden-visibility pimpl body.
//
// All state and thread-safety live here. The public header carries only the
// forward declaration + unique_ptr<Impl>, matching SigningService/MonitorService/
// CardSession and satisfying ci/scripts/check-impl-visibility.sh.
// -----------------------------------------------------------------------------
struct LIBRESCRS_INTERNAL CardPluginService::Impl
{
    struct LoadedPlugin
    {
        // Shared ownership of the plugin instance; the shared_ptr's custom
        // deleter also closes the SO handle, so callers who hold a
        // shared_ptr<CardPlugin> keep the underlying library mapped for as
        // long as they need it — even past the registry's own destruction.
        std::shared_ptr<CardPlugin> plugin;
    };

    mutable std::shared_mutex pluginsMtx;
    std::vector<LoadedPlugin> loadedPlugins;
    std::vector<std::shared_ptr<CardPlugin>> sortedPlugins;
    std::vector<LoadOutcome> report;

    void loadDirectory(const std::filesystem::path& dir);
    void sortPlugins();
};

void CardPluginService::Impl::loadDirectory(const std::filesystem::path& dir)
{
    // A nonexistent / non-directory path is not fatal — the absence is
    // recorded implicitly (no LoadOutcome entries) and construction returns
    // cleanly. Matches the v5 setter contract: missing plugin directories
    // on a dev box should never crash the app.
    std::error_code ec;
    if (!std::filesystem::exists(dir, ec) || !std::filesystem::is_directory(dir, ec)) {
        return;
    }

    // Refuse a plugin directory that is not owned by us or root, or that is
    // group/other-writable: a writable plugin dir lets any local user drop a
    // malicious .so we would dlopen into the host process. This defends the
    // real threat (write access to the dir); the per-entry symlink reject
    // below closes the narrower symlink-swap vector.
    struct ::stat dirStat{};
    if (::stat(dir.c_str(), &dirStat) != 0) {
        return;
    }
    if (dirStat.st_uid != ::geteuid() && dirStat.st_uid != 0) {
        std::clog << "[librescrs.plugin] refusing plugin directory not owned by "
                     "the current user or root: "
                  << dir.string() << '\n';
        return;
    }
    // Reject a directory writable by anyone other than its owner. Other-writable
    // is always rejected. Group-writable is rejected only when the directory is
    // NOT owned by us: a dir we own that is group-writable is our own
    // configuration and is safe on the common user-private-group + umask 002
    // setup where CMake emits 0775 build/test dirs — rejecting it there would
    // break plugin loading with no security gain.
    const bool ownedByUs = dirStat.st_uid == ::geteuid();
    if ((dirStat.st_mode & S_IWOTH) != 0 || ((dirStat.st_mode & S_IWGRP) != 0 && !ownedByUs)) {
        std::clog << "[librescrs.plugin] refusing world-writable or non-owner-writable plugin directory: "
                  << dir.string() << '\n';
        return;
    }

    for (const auto& entry : std::filesystem::directory_iterator(dir, ec)) {
        if (entry.is_symlink(ec)) {
            std::clog << "[librescrs.plugin] skipping symlinked plugin entry: " << entry.path().string() << '\n';
            continue;
        }

        if (!entry.is_regular_file())
            continue;

        auto ext = entry.path().extension().string();
        if (ext != ".so" && ext != ".dylib")
            continue;

        LoadOutcome outcome;
        outcome.soPath = entry.path();

        // RTLD_LOCAL prevents plugin symbols from leaking into the global
        // namespace. Constraint: plugins must not carry vendored static
        // copies of shared system libraries (e.g., OpenSSL), as each plugin
        // would get its own copy.
        //
        // DlHandle owns the dlopen handle across every throwable line in
        // this scope (report.push_back, std::to_string, std::string
        // construction). Ownership transfers via .release() to the
        // shared_ptr custom deleter once both factory + destroyer
        // symbols have resolved and the plugin instance is alive.
        DlHandle handle(::dlopen(entry.path().c_str(), RTLD_NOW | RTLD_LOCAL));
        if (!handle) {
            const char* err = ::dlerror();
            outcome.status = LoadOutcome::Status::DlopenFailed;
            outcome.diagnostic = err ? err : "dlopen failed (no error string)";
            report.push_back(std::move(outcome));
            continue;
        }

        auto abiFunc = reinterpret_cast<AbiVersionFunc>(::dlsym(handle.get(), "card_plugin_abi_version"));
        if (!abiFunc) {
            outcome.status = LoadOutcome::Status::MissingFactory;
            outcome.diagnostic = "missing card_plugin_abi_version()";
            report.push_back(std::move(outcome));
            continue;
        }

        const uint32_t version = abiFunc();
        if (version != kCardPluginAbiVersion) {
            outcome.status = LoadOutcome::Status::AbiMismatch;
            outcome.diagnostic = "ABI version mismatch (got " + std::to_string(version) + ", expected " +
                                 std::to_string(kCardPluginAbiVersion) + ")";
            report.push_back(std::move(outcome));
            continue;
        }

        auto createFunc = reinterpret_cast<CreateFunc>(::dlsym(handle.get(), "create_card_plugin"));
        if (!createFunc) {
            outcome.status = LoadOutcome::Status::MissingFactory;
            outcome.diagnostic = "missing create_card_plugin()";
            report.push_back(std::move(outcome));
            continue;
        }

        // ABI v6: plugins MUST also export destroy_card_plugin so the
        // deletion happens inside the plugin's own translation unit. A
        // plugin that is missing this symbol is rejected with the same
        // MissingFactory status so the deployment issue is surfaced to the
        // host operator.
        auto destroyFunc = reinterpret_cast<DestroyFunc>(::dlsym(handle.get(), "destroy_card_plugin"));
        if (!destroyFunc) {
            outcome.status = LoadOutcome::Status::MissingFactory;
            outcome.diagnostic = "missing destroy_card_plugin()";
            report.push_back(std::move(outcome));
            continue;
        }

        // Plugin factory returns a raw pointer to keep the C-linkage entry
        // point free of non-C types. Ownership transfers to us via the
        // shared_ptr deleter wrapping destroy_card_plugin + dlclose.
        CardPlugin* raw = nullptr;
        try {
            raw = createFunc();
        } catch (const std::exception& ex) {
            outcome.status = LoadOutcome::Status::FactoryThrew;
            outcome.diagnostic = std::string{"create_card_plugin() threw: "} + ex.what();
            report.push_back(std::move(outcome));
            continue;
        } catch (...) {
            outcome.status = LoadOutcome::Status::FactoryThrew;
            outcome.diagnostic = "create_card_plugin() threw non-std::exception";
            report.push_back(std::move(outcome));
            continue;
        }

        if (!raw) {
            outcome.status = LoadOutcome::Status::FactoryThrew;
            outcome.diagnostic = "create_card_plugin() returned nullptr";
            report.push_back(std::move(outcome));
            continue;
        }

        // Build the shared_ptr with a deleter that destroys the plugin
        // (via the plugin-side destroy_card_plugin symbol, so the plugin's
        // own allocator runs) before closing the SO. shared_ptr allocates
        // its control block once; if that allocation throws, the catch
        // runs destroyLoadedPlugin directly to match the success-path
        // cleanup exactly (same destroy function, same dlclose order).
        //
        // handle.release() must run only on the success path: if the
        // shared_ptr construction throws, the catch destroys the plugin
        // and DlHandle's dtor closes the SO during stack unwind.
        std::shared_ptr<CardPlugin> plugin;
        try {
            void* rawHandle = handle.get();
            plugin = std::shared_ptr<CardPlugin>(
                raw, [destroyFunc, rawHandle](CardPlugin* p) { destroyLoadedPlugin(p, destroyFunc, rawHandle); });
            // Success — transfer SO ownership into the shared_ptr deleter.
            (void)handle.release();
        } catch (...) {
            destroyLoadedPlugin(raw, destroyFunc, nullptr); // dtor of handle closes SO.
            outcome.status = LoadOutcome::Status::FactoryThrew;
            outcome.diagnostic = "failed to construct shared_ptr for plugin";
            report.push_back(std::move(outcome));
            continue;
        }

        outcome.status = LoadOutcome::Status::Loaded;
        outcome.pluginId = plugin->pluginId();
        report.push_back(std::move(outcome));

        loadedPlugins.push_back({std::move(plugin)});
    }
}

void CardPluginService::Impl::sortPlugins()
{
    sortedPlugins.clear();
    sortedPlugins.reserve(loadedPlugins.size());
    for (auto& lp : loadedPlugins) {
        sortedPlugins.push_back(lp.plugin);
    }
    std::sort(sortedPlugins.begin(), sortedPlugins.end(), Internal::probeOrderBefore);
}

// -----------------------------------------------------------------------------
// CardPluginService — public API defined out of line to keep Impl internal.
// -----------------------------------------------------------------------------

CardPluginService::CardPluginService(std::span<const std::filesystem::path> dirs,
                                     std::shared_ptr<const LibreSCRS::Trust::TrustStore> trustStore)
    : d(std::make_unique<Impl>())
{
    std::unique_lock lock(d->pluginsMtx);
    for (const auto& dir : dirs) {
        d->loadDirectory(dir);
    }
    // Trust subsystem: propagate the unified TrustStore to every loaded plugin BEFORE
    // they are exposed via plugins() / findPluginForCard(). Plugins that
    // override setTrustStore (e.g. rs-eid for card-data verification)
    // cache the pointer; plugins that don't need it ignore via the
    // CardPlugin default no-op.
    if (trustStore) {
        for (auto& lp : d->loadedPlugins) {
            if (lp.plugin) {
                lp.plugin->setTrustStore(trustStore);
            }
        }
    }
    d->sortPlugins();
}

CardPluginService::CardPluginService(std::filesystem::path dir,
                                     std::shared_ptr<const LibreSCRS::Trust::TrustStore> trustStore)
    : d(std::make_unique<Impl>())
{
    std::unique_lock lock(d->pluginsMtx);
    d->loadDirectory(dir);
    if (trustStore) {
        for (auto& lp : d->loadedPlugins) {
            if (lp.plugin) {
                lp.plugin->setTrustStore(trustStore);
            }
        }
    }
    d->sortPlugins();
}

CardPluginService::~CardPluginService() = default;

CardPluginService::CardPluginService(CardPluginService&&) noexcept = default;
CardPluginService& CardPluginService::operator=(CardPluginService&&) noexcept = default;

void CardPluginService::setCscaAnchorDirectory(const std::filesystem::path& dir)
{
    // A SHARED lock: the plugin set itself is not touched here, only walked.
    // Each plugin serialises its own publication behind its own lock, so two
    // hosts publishing at once cannot tear a path -- one of them wins whole.
    std::shared_lock lock(d->pluginsMtx);
    for (const auto& plugin : d->sortedPlugins) {
        if (plugin) {
            plugin->setCscaAnchorDirectory(dir);
        }
    }
}

std::shared_ptr<CardPlugin> CardPluginService::findPluginForCard(std::span<const std::uint8_t> atr) const
{
    std::shared_lock lock(d->pluginsMtx);
    for (const auto& plugin : d->sortedPlugins) {
        if (plugin->canHandle(atr)) {
            return plugin;
        }
    }
    return nullptr;
}

std::vector<std::shared_ptr<CardPlugin>> CardPluginService::findAllCandidates(std::span<const std::uint8_t> atr) const
{
    std::shared_lock lock(d->pluginsMtx);
    std::vector<std::shared_ptr<CardPlugin>> result;
    for (const auto& plugin : d->sortedPlugins) {
        if (plugin->canHandle(atr)) {
            result.push_back(plugin);
        }
    }
    return result;
}

std::vector<std::shared_ptr<CardPlugin>>
CardPluginService::findAllCandidates(std::span<const std::uint8_t> atr,
                                     LibreSCRS::SmartCard::CardSession& session) const
{
    std::shared_lock lock(d->pluginsMtx);
    std::set<CardPlugin*> seen;
    std::vector<std::shared_ptr<CardPlugin>> result;

    LibreSCRS::Internal::probeTrace(std::string{"PROBE-ENTRY atr="} + LibreSCRS::Internal::atrToHex(atr) +
                                    " plugins=" + std::to_string(d->sortedPlugins.size()));

    // Pass 1 — ATR-based matches.
    for (const auto& plugin : d->sortedPlugins) {
        if (plugin->canHandle(atr)) {
            LibreSCRS::Internal::probeTrace(std::string{"PROBE-ATR-HIT plugin="} + plugin->pluginId() +
                                            " atr=" + LibreSCRS::Internal::atrToHex(atr));
            result.push_back(plugin);
            seen.insert(plugin.get());
        }
    }

    // Pass 2 — AID probe on the remaining plugins. ATR is already known from
    // the session we just opened, so pass it through — plugins that want to
    // combine an AID probe with a secondary ATR check avoid re-reading it.
    const auto atrMatchCount = result.size();
    const auto& sessionAtr = session.atr();
    for (const auto& plugin : d->sortedPlugins) {
        if (seen.count(plugin.get()) > 0) {
            continue;
        }
        LibreSCRS::Internal::probeTrace(std::string{"PROBE-PLUGIN plugin="} + plugin->pluginId() +
                                        " priority=" + std::to_string(plugin->probePriority()));
        bool matched = false;
        bool threw = false;
        try {
            matched = plugin->canHandleConnection(sessionAtr, session);
            if (matched) {
                result.push_back(plugin);
            }
        } catch (...) {
            threw = true;
            // AID probe failed — skip this plugin. The 4.0 ABI v6 contract asks
            // plugins to return false rather than throw, but the registry
            // retains the safety net so a buggy plugin loaded across a
            // mismatched stdlib cannot abort the host process.
        }
        LibreSCRS::Internal::probeTrace(std::string{"PROBE-RESULT plugin="} + plugin->pluginId() + " matched=" +
                                        (matched ? "true" : "false") + " threw=" + (threw ? "true" : "false"));
    }

    // Sort within each pass independently — ATR matches stay ahead of AID probes.
    auto aidProbeStart = result.begin() + static_cast<ptrdiff_t>(atrMatchCount);
    std::sort(result.begin(), aidProbeStart, Internal::probeOrderBefore);
    std::sort(aidProbeStart, result.end(), Internal::probeOrderBefore);
    return result;
}

std::vector<std::shared_ptr<CardPlugin>> CardPluginService::plugins() const
{
    std::shared_lock lock(d->pluginsMtx);
    return d->sortedPlugins; // copy of shared_ptr vector — cheap (refcounted)
}

std::size_t CardPluginService::size() const noexcept
{
    std::shared_lock lock(d->pluginsMtx);
    return d->sortedPlugins.size();
}

const std::vector<LoadOutcome>& CardPluginService::loadReport() const noexcept
{
    // Report is populated once during construction and never mutated
    // afterwards, so no locking is needed for read access. Marked noexcept
    // to match the accessor contract on SigningService/MonitorService peers.
    return d->report;
}

bool CardPluginService::isUsable() const noexcept
{
    // Pure read of the post-construction snapshot. The report vector is set
    // up during ctor and never mutated afterwards, so the comparison below
    // does not need to take pluginsMtx.
    if (d->sortedPlugins.empty())
        return false;
    for (const auto& entry : d->report) {
        if (entry.status != LoadOutcome::Status::Loaded)
            return false;
    }
    return true;
}

} // namespace LibreSCRS::Plugin
