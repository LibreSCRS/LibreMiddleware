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
/// owning manager is destroyed (typically at host-process exit).
///
/// @par Why per-Token @c dlclose is a regression vector
/// Per-Token @c C_Finalize + @c dlclose unmaps the module and forces
/// the next sign to reload a fresh copy with empty in-module state.
/// PACE-gated contactless cards observe this as latency spikes and as
/// vtable churn for any per-module service. The host's
/// @c SessionPresence is process-local (not module-local) so the
/// cross-reader SM guard survives a module reload, but the dlopen
/// round-trip itself is wasteful; this manager eliminates it.

#include <filesystem>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>

namespace libresign {

// Forward declared so the header does not pull in pkcs11.h. The
// implementation TU resolves the concrete CK_FUNCTION_LIST shape.
struct LoadedModule;

/// @brief Lightweight handle to a process-shared loaded PKCS#11 module.
///
/// Held by @ref Pkcs11Token instances and other consumers; copying is
/// a refcount bump on the underlying @ref LoadedModule. The handle
/// exposes the module's path, the C @c CK_FUNCTION_LIST pointer and
/// the raw @c dlopen handle without enabling the holder to unload the
/// module — unload happens through @ref Pkcs11ModuleManager destruction.
///
/// @par Thread-safety
/// Distinct handles are independent. A single handle is not internally
/// synchronised — copy and move are not safe to race against. The
/// underlying @ref LoadedModule's PKCS#11 session state is owned by
/// the Token, not the manager.
class Pkcs11ModuleHandle
{
public:
    Pkcs11ModuleHandle() noexcept = default;

    /// @brief Reach the underlying C @c CK_FUNCTION_LIST.
    /// @return Pointer to the PKCS#11 function table, never null on a
    ///         live handle. @c valid() returns @c false on a default-
    ///         constructed handle and the function pointer is null.
    [[nodiscard]] void* functionList() const noexcept;

    /// @brief Raw @c dlopen handle for diagnostic / @c dlsym callers
    ///        that need to reach non-PKCS#11 symbols (the inject hook,
    ///        for example).
    /// @return Opaque @c dlopen handle or @c nullptr.
    [[nodiscard]] void* dlHandle() const noexcept;

    /// @brief Path the module was loaded from, after canonicalisation
    ///        by @ref Pkcs11ModuleManager::acquire.
    [[nodiscard]] const std::filesystem::path& path() const noexcept;

    /// @brief Whether the handle refers to a live module.
    /// @return @c true iff the underlying @ref LoadedModule is live;
    ///         @c false for a default-constructed handle.
    [[nodiscard]] bool valid() const noexcept
    {
        return static_cast<bool>(loaded);
    }

private:
    friend class Pkcs11ModuleManager;
    explicit Pkcs11ModuleHandle(std::shared_ptr<LoadedModule> module) noexcept;

    std::shared_ptr<LoadedModule> loaded;
};

/// @brief Process-local cache of loaded PKCS#11 modules keyed by
///        canonical filesystem path.
///
/// @par Lifecycle
/// The manager owns a strong reference to every loaded module. The
/// first @ref acquire for a given path performs @c dlopen and
/// @c C_Initialize; subsequent acquires return a handle to the cached
/// @ref LoadedModule. Modules are unloaded (@c C_Finalize then
/// @c dlclose) when the manager is destroyed — which means a Token
/// outliving the manager would have a dangling function pointer. The
/// architectural invariant is therefore "manager is held by a longer-
/// lived owner than any Token built from it". @ref NativeSigningService
/// owns the manager as a member; Tokens are constructed within sign
/// calls and destroyed before the service.
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

} // namespace libresign
