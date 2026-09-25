// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

/// @file
/// @brief Process-local cache of @c dlopen-ed PKCS#11 modules with a
///        single @c C_Initialize per module, shared across every
///        @ref libresign::Pkcs11Token built against the same path.
///
/// Lifts the @c dlopen + @c C_Initialize cost out of the per-Token
/// critical path. Each per-sign Token acquires a handle from the
/// manager; the handle's refcount keeps the underlying @c LoadedModule
/// alive while the Token uses it. The module stays mapped until the
/// last in-process holder of a handle to it is gone — which may be a
/// different manager than the one that loaded it.
///
/// @par Why per-Token @c dlclose is a regression vector
/// Per-Token @c C_Finalize + @c dlclose unmaps the module and forces
/// the next sign to reload a fresh copy with empty in-module state.
/// PACE-gated contactless cards observe this as latency spikes and as
/// vtable churn for any per-module service. The host's
/// @c SessionPresence is process-local (not module-local) so the
/// cross-reader SM guard survives a module reload, but the dlopen
/// round-trip itself is wasteful; this manager eliminates it.

#include "native/pkcs11_module_handle.h"

#include <chrono>
#include <cstddef>
#include <filesystem>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>

namespace libresign {

// Defined in this manager's own translation unit, which is the only one that
// finalises and unloads a module. Forward declared here so the header does not
// pull in pkcs11.h.
struct LoadedModule;

/// @brief Process-local cache of loaded PKCS#11 modules keyed by
///        canonical filesystem path.
///
/// @par Lifecycle
/// The manager owns a strong reference to every loaded module. The
/// first @ref acquire for a given path anywhere in the process performs
/// @c dlopen and @c C_Initialize; every later acquire of the same
/// canonical path — through this manager or any other one alive in the
/// process — returns a handle to that same @ref LoadedModule. A module
/// is unloaded (@c C_Finalize then @c dlclose) when the last manager and
/// the last handle referring to it are gone, which means a Token
/// outliving every holder would have a dangling function pointer. The
/// architectural invariant is therefore "manager is held by a longer-
/// lived owner than any Token built from it". @ref NativeSigningService
/// owns the manager as a member; Tokens are constructed within sign
/// calls and destroyed before the service.
///
/// @par Why the sharing is process-wide
/// Two concurrent sign calls own one manager each. While each kept its
/// own @c LoadedModule, the first to finish called @c C_Finalize under
/// the second, whose every subsequent PKCS#11 call then returned
/// @c CKR_CRYPTOKI_NOT_INITIALIZED. The module's initialised state is
/// process-scoped by specification (PKCS#11 v2.40 §6.6) and its mapping
/// is refcounted process-wide by @c dlopen, so a process-wide registry
/// of weak references mirrors a lifetime that already exists rather
/// than inventing one.
///
/// @par CKR_CRYPTOKI_ALREADY_INITIALIZED tolerance
/// Some loader configurations (in-process p11-kit, third-party tooling
/// pre-initialising the same module) leave the module already
/// initialised when our @ref acquire opens it. The implementation
/// treats this return code as success — we do not attempt a competing
/// @c C_Finalize on shutdown in that case either; @c dlclose alone is
/// safe because the original initialiser still holds its own copy of
/// the module mapping (via its own @c dlopen retain).
///
/// @par Thread-safety
/// All public methods are internally synchronised against a single
/// mutex. Concurrent @ref acquire calls for distinct paths are
/// effectively serialised — acceptable for the LC use case where the
/// manager is consulted once per sign and the dominant cost is the
/// card I/O after the handle has been returned. The @c CK_FUNCTION_LIST
/// itself is safe to call concurrently from distinct sessions per
/// PKCS#11 v2.40 §6.6.2; this manager does not impose extra
/// serialisation on PKCS#11 calls.
class Pkcs11ModuleManager
{
public:
    Pkcs11ModuleManager() noexcept = default;
    ~Pkcs11ModuleManager();

    Pkcs11ModuleManager(const Pkcs11ModuleManager&) = delete;
    Pkcs11ModuleManager& operator=(const Pkcs11ModuleManager&) = delete;
    Pkcs11ModuleManager(Pkcs11ModuleManager&&) = delete;
    Pkcs11ModuleManager& operator=(Pkcs11ModuleManager&&) = delete;

    /// @brief Return a handle to the loaded module at @p modulePath.
    ///
    /// The first call for a given canonical path performs @c dlopen
    /// and @c C_Initialize. Subsequent calls return a handle to the
    /// already-loaded module. The returned handle is lightweight; the
    /// caller may copy / store / discard it freely.
    ///
    /// @param modulePath Path to a PKCS#11 module shared object.
    ///                   Canonicalised via
    ///                   @c std::filesystem::weakly_canonical so two
    ///                   syntactically distinct paths that resolve to
    ///                   the same file share a cache entry.
    /// @throws std::runtime_error on @c dlopen failure, missing
    ///                            @c C_GetFunctionList, or a
    ///                            @c C_Initialize return code other
    ///                            than @c CKR_OK or
    ///                            @c CKR_CRYPTOKI_ALREADY_INITIALIZED.
    Pkcs11ModuleHandle acquire(const std::filesystem::path& modulePath);

private:
    mutable std::mutex mu;
    std::unordered_map<std::string, std::shared_ptr<LoadedModule>> modules;
};

/// @brief Test-only: the points inside the process-wide registry a test can
///        stop the thread that reached them at.
///
/// Both windows are a few instructions wide and cannot be hit by racing, so a
/// test that means to measure what happens inside one has to be let in.
enum class ModuleRegistryEvent {
    BeforeLoad,     ///< About to @c dlopen and @c C_Initialize a module.
    BeforeTeardown, ///< The last holder let go; nothing has been finalised yet.
    AfterTeardown,  ///< The module is finalised and unloaded; its entry is not yet erased.
};

/// @brief Test-only: run @p rendezvous whenever one of those points is reached.
///
/// Pass an empty function to remove it. The callback runs on whichever thread got
/// there, and what that thread holds differs per event:
///  - @c BeforeTeardown and @c AfterTeardown: the registry lock is NOT held. A
///    callback may do as it likes, including calling back into the registry.
///  - @c BeforeLoad: the registry lock IS held, because loading under it is the
///    property that event exists to test. A callback that calls @ref
///    Pkcs11ModuleManager::acquire, @ref resetSharedModuleRegistryForTest or
///    @ref liveSharedModuleCountForTest from there deadlocks against itself on a
///    non-recursive mutex. Block, signal and return; do not re-enter.
void setModuleRegistryRendezvousForTest(std::function<void(ModuleRegistryEvent)> rendezvous);

/// @brief Test-only: shorten the budget an acquire waits for a teardown in
///        flight before refusing (default 30 s).
///
/// The only honest test of a budget is one that shortens it; nothing else can
/// distinguish "waited and got a module" from "waited forever".
void setModuleTeardownBudgetForTest(std::chrono::milliseconds budget);

/// @brief Test-only: how many times a module has been loaded (@c dlopen plus
///        @c C_Initialize) since the last reset.
///
/// One load per module, however many managers ask for it, is the property the
/// registry exists for; nothing else observable distinguishes one load from two
/// of the same shared object.
[[nodiscard]] std::size_t sharedModuleLoadCountForTest();

/// @brief Test-only: drop every entry from the process-wide module registry.
///
/// The obligation that comes with process-global state. Entries are weak
/// references, so this neither finalises nor unloads anything — it only stops
/// a module loaded by an earlier test from being shared with a later one.
void resetSharedModuleRegistryForTest();

/// @brief Test-only: how many registry entries still refer to a live module.
/// @return Count of entries whose weak reference can still be locked.
[[nodiscard]] std::size_t liveSharedModuleCountForTest();

/// @brief Test-only: how many entries the registry lists at all, live or spent.
///
/// A spent entry is not a leak, it is the marker a caller waits on, so the two
/// counts answer different questions and a test that means the second must not
/// ask the first.
[[nodiscard]] std::size_t sharedModuleEntryCountForTest();

} // namespace libresign
