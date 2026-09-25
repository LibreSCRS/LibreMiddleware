// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "native/pkcs11_module_manager.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <dlfcn.h>
#include <sstream>
#include <stdexcept>
#include <system_error>
#include <utility>

#define CK_PTR *
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType(*name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType(*name)
#ifndef NULL_PTR
#define NULL_PTR 0
#endif

#include "pkcs11/pkcs11.h"

namespace libresign {

namespace {

// Test-only rendezvous and load counter.
//
// Deliberately leaked, and read through an atomic first. A module can be
// destroyed during static destruction -- a signing service that outlives main,
// or a leaked token -- and the deleter is the first thing that would reach these:
// locking a destroyed mutex and reading a destroyed std::function is what the
// obvious function-local statics would buy. Leaking the state removes the
// destruction order from the question entirely, and the flag means production,
// which never installs a hook, does not so much as take the lock.
struct RendezvousState
{
    std::mutex mu;
    std::function<void(ModuleRegistryEvent)> hook;
    std::atomic<bool> installed{false};
};

[[nodiscard]] RendezvousState& rendezvousState()
{
    static RendezvousState* const state = new RendezvousState();
    return *state;
}

std::atomic<std::size_t>& moduleLoadCount()
{
    // Trivially destructible, so it is safe after static destruction as it is.
    static std::atomic<std::size_t> count{0};
    return count;
}

void reachRendezvous(ModuleRegistryEvent event)
{
    auto& state = rendezvousState();
    if (!state.installed.load(std::memory_order_acquire))
        return;

    std::function<void(ModuleRegistryEvent)> hook;
    {
        std::scoped_lock lock(state.mu);
        hook = state.hook;
    }
    if (hook)
        hook(event);
}

} // namespace

/// @brief Internal state for one loaded PKCS#11 module. Lives in a
///        @c shared_ptr held by the manager (cache) and by every live
///        @ref Pkcs11ModuleHandle returned from @ref acquire.
///
/// The destructor releases the module symmetrically with @ref load:
/// @c C_Finalize is called only when @ref load itself drove the
/// initialiser (i.e. the @c C_Initialize call returned @c CKR_OK).
/// If the module reported @c CKR_CRYPTOKI_ALREADY_INITIALIZED — meaning
/// some other in-process consumer had already initialised it — we never
/// call @c C_Finalize, because doing so would race the original
/// initialiser. @c dlclose is always called on a non-null handle to
/// drop our reference on the dynamic-loader side; the OS keeps the
/// mapping alive as long as any other consumer's @c dlopen retains it.
struct LoadedModule
{
    /// Everything a @ref Pkcs11ModuleHandle is allowed to see, held by value so
    /// a handle can alias it while sharing ownership of this object.
    Pkcs11ModuleView view;
    bool weInitialized = false;

    LoadedModule() = default;
    ~LoadedModule()
    {
        if (view.functions && weInitialized) {
            // C_Finalize takes a reserved argument that must be NULL_PTR
            // per PKCS#11 v2.40 §6.6.2. Failures here are not actionable
            // from a destructor; the module is going away regardless.
            (void)static_cast<CK_FUNCTION_LIST*>(view.functions)->C_Finalize(nullptr);
        }
        if (view.dlopenHandle) {
            (void)::dlclose(view.dlopenHandle);
        }
    }

    LoadedModule(const LoadedModule&) = delete;
    LoadedModule& operator=(const LoadedModule&) = delete;
    LoadedModule(LoadedModule&&) = delete;
    LoadedModule& operator=(LoadedModule&&) = delete;
};

Pkcs11ModuleManager::~Pkcs11ModuleManager()
{
    // Drop the cache map under the lock. Each entry's shared_ptr is
    // destroyed as the entry leaves the map; if a Token, a handle or
    // another manager in this process still refers to the LoadedModule it
    // survives until the last of them drops it. In practice Tokens are
    // stack-scoped within sign calls and are gone by the time the
    // service-owning manager destroys.
    std::scoped_lock lock(mu);
    modules.clear();
}

namespace {

std::string canonicalKey(const std::filesystem::path& modulePath)
{
    // weakly_canonical does not require the path to exist on disk —
    // helpful for tests that pass synthetic paths through the manager.
    // Failures fall back to the lexically normalised string so the key
    // is at least deterministic; the subsequent dlopen will surface
    // any "file not found" condition with the usual diagnostic.
    std::error_code ec;
    auto canonical = std::filesystem::weakly_canonical(modulePath, ec);
    if (ec)
        return modulePath.lexically_normal().string();
    return canonical.string();
}

// Process-wide registry of loaded modules, keyed by the same canonical path
// the per-manager cache uses.
//
// Sanctioned process-global state, and the only one in this library: dlopen
// already refcounts the mapping process-wide and PKCS#11 v2.40 §6.6 scopes
// C_Initialize to the process, so a module's initialised lifetime is
// process-wide whether or not anything here models it. While each manager kept
// its own LoadedModule, two concurrent sign calls each loaded the module, the
// first to finish called C_Finalize, and the second one's every remaining
// PKCS#11 call returned CKR_CRYPTOKI_NOT_INITIALIZED. The entries are weak
// references, so the registry mirrors that lifetime instead of extending it,
// and resetSharedModuleRegistryForTest() is the obligation that comes with it.
//
// The alternative -- one mutex serialising every signature that shares a
// module -- is equally global and would remove the cross-reader parallelism
// the service's own tests guarantee. This registry's own mutex is global too,
// and the honest statement of the difference is: it is held while a path is
// first loaded and while its entry is erased, not for the duration of a
// signature, and not across a module's teardown.
struct SharedModuleRegistry
{
    std::mutex mu;
    // Signalled when a module has been finalised, unloaded and removed. A
    // caller that finds an expired entry waits on this rather than loading the
    // module under a teardown that has not run yet.
    std::condition_variable teardownComplete;
    std::unordered_map<std::string, std::weak_ptr<LoadedModule>> modules;
};

[[nodiscard]] SharedModuleRegistry& sharedModuleRegistry()
{
    // Leaked on purpose, for the same reason as the rendezvous state above: a
    // module released during static destruction must not lock a destroyed mutex,
    // and a thread still parked on the condition variable when main returns must
    // not be waiting on a destroyed one. Leak-on-exit is the cheap half of that;
    // the bounded wait below is the other half.
    static SharedModuleRegistry* const registry = new SharedModuleRegistry();
    return *registry;
}

// How long an acquire waits for a teardown in flight before refusing. Test-only
// settable, because the only honest test of the budget is one that shortens it.
std::atomic<std::chrono::milliseconds::rep>& teardownBudgetMs()
{
    static std::atomic<std::chrono::milliseconds::rep> budget{30'000};
    return budget;
}

[[nodiscard]] std::chrono::milliseconds teardownBudget()
{
    return std::chrono::milliseconds{teardownBudgetMs().load(std::memory_order_relaxed)};
}

// True while THIS thread is inside the registry lock. The module deleter can be
// reached from that thread -- a control-block allocation failure destroys the
// module the thread was in the middle of publishing -- and a second lock on a
// non-recursive mutex would deadlock it against itself.
thread_local bool registryHeldByThisThread = false;

class RegistryLock
{
public:
    explicit RegistryLock(SharedModuleRegistry& registry) : lock(registry.mu)
    {
        registryHeldByThisThread = true;
    }
    ~RegistryLock()
    {
        registryHeldByThisThread = false;
    }
    RegistryLock(const RegistryLock&) = delete;
    RegistryLock& operator=(const RegistryLock&) = delete;

    std::unique_lock<std::mutex> lock;
};

// Remove our own entry, and only ours: if a later load already replaced it, the
// replacement is live and belongs to somebody else.
void forgetExpiredEntry(SharedModuleRegistry& registry, const std::string& key)
{
    if (const auto it = registry.modules.find(key); it != registry.modules.end() && it->second.expired())
        registry.modules.erase(it);
}

// The deleter every registered module is destroyed through.
//
// What closes the window the weak reference leaves open is the ENTRY, not the
// lock: a weak_ptr expires the instant the last owner lets go, which is strictly
// before C_Finalize runs, so the entry is left in place -- present and expired --
// for the whole teardown, and that is precisely the state acquireShared waits on.
// The entry is erased, under the lock, only once the module is gone.
//
// The lock is therefore NOT held across the teardown, and deliberately so. What
// runs inside `delete module` is not cheap: for this project's own module,
// C_Finalize takes a write lock on the library and waits out every PKCS#11 call
// in flight (a C_Sign is card I/O), logs out each logged-in slot with real APDUs,
// and then tears down the PC/SC transport -- SCardDisconnect and
// SCardReleaseContext, blocking IPC to pcscd. Holding a process-global lock
// across that would stall every acquire of every OTHER module path too, which is
// exactly the granularity the registry's own comment claims not to have.
void releaseModule(LoadedModule* module) noexcept
{
    if (module == nullptr)
        return;
    reachRendezvous(ModuleRegistryEvent::BeforeTeardown);

    auto& registry = sharedModuleRegistry();
    const std::string key = module->view.canonicalPath.string();

    if (registryHeldByThisThread) {
        // Already serialised by this thread's own lock; see the note above it.
        forgetExpiredEntry(registry, key);
        delete module;
        // Unconditionally correct even though no waiter on this key can exist
        // here: it would itself be parked in wait().
        registry.teardownComplete.notify_all();
        return;
    }

    delete module; // C_Finalize + dlclose, with the registry NOT held
    // The entry is still listed here, and that is the whole ordering: it is what
    // a caller arriving mid-teardown waits on, so it outlives the finalise and is
    // erased only now. Erasing it earlier would let such a caller load a second
    // copy while this one was still finalising.
    reachRendezvous(ModuleRegistryEvent::AfterTeardown);
    {
        std::scoped_lock lock(registry.mu);
        forgetExpiredEntry(registry, key);
    }
    registry.teardownComplete.notify_all();
}

// Returns an OWNING pointer, not a shared one: every failure below destroys the
// module through the plain destructor, which wants no registry lock. The module
// becomes a shared_ptr with the registry's deleter only once it is going in.
[[nodiscard]] std::unique_ptr<LoadedModule> loadModule(const std::filesystem::path& canonical)
{
    reachRendezvous(ModuleRegistryEvent::BeforeLoad);

    auto loaded = std::make_unique<LoadedModule>();
    loaded->view.canonicalPath = canonical;

    loaded->view.dlopenHandle = ::dlopen(canonical.c_str(), RTLD_NOW);
    if (!loaded->view.dlopenHandle)
        throw std::runtime_error(std::string("Cannot load PKCS#11 module: ") + ::dlerror());

    auto getList = reinterpret_cast<CK_C_GetFunctionList>(::dlsym(loaded->view.dlopenHandle, "C_GetFunctionList"));
    if (!getList)
        throw std::runtime_error("C_GetFunctionList not found in module");

    CK_FUNCTION_LIST* functions = nullptr;
    if (CK_RV rv = getList(&functions); rv != CKR_OK) {
        char buf[32];
        std::snprintf(buf, sizeof(buf), "0x%08lX", static_cast<unsigned long>(rv));
        throw std::runtime_error(std::string("C_GetFunctionList failed: CKR ") + buf);
    }

    // Tolerate CKR_CRYPTOKI_ALREADY_INITIALIZED: some hosts (in-process
    // p11-kit clients, libsofthsm2 inside the same address space) drive
    // C_Initialize earlier in the process lifetime. Treating it as
    // success keeps our own teardown clean — see ~LoadedModule on why
    // weInitialized must remain false in that branch.
    loaded->view.functions = functions;

    CK_RV initRv = functions->C_Initialize(nullptr);
    if (initRv == CKR_OK) {
        loaded->weInitialized = true;
    } else if (initRv == CKR_CRYPTOKI_ALREADY_INITIALIZED) {
        loaded->weInitialized = false;
    } else {
        char buf[32];
        std::snprintf(buf, sizeof(buf), "0x%08lX", static_cast<unsigned long>(initRv));
        throw std::runtime_error(std::string("C_Initialize failed: CKR ") + buf);
    }

    moduleLoadCount().fetch_add(1, std::memory_order_relaxed);
    return loaded;
}

// Share the module with whoever else in this process holds it, or load it.
//
// loadModule runs while the registry is locked, on purpose: two threads that
// reach the same path at the same time must produce one dlopen and one
// C_Initialize, not a race whose loser's C_Finalize tears the winner down.
// Lock order is always manager mutex first, registry mutex second; nothing
// takes them the other way round.
[[nodiscard]] std::shared_ptr<LoadedModule> acquireShared(const std::string& key)
{
    auto& registry = sharedModuleRegistry();
    RegistryLock held(registry);

    // An entry that is present but expired does NOT mean the module is gone: a
    // weak reference expires when the last owner lets go, and the teardown that
    // finalises and unloads it runs after that, through releaseModule, which
    // erases the entry as part of it. So an expired entry means exactly "a
    // teardown is on its way", and the only safe thing to do is wait for it.
    //
    // Bounded, because what is being waited for is a card: the teardown logs out
    // slots and tears down the PC/SC transport, so an unresponsive card, a 6C
    // retry storm or a wedged pcscd all land here. Before this registry existed
    // the second signature got a fast wrong answer; it must not now get a correct
    // one after an unbounded wait. On expiry the acquire is refused and says so,
    // which the facade turns into an engine error for that one signature.
    const bool ready = registry.teardownComplete.wait_for(held.lock, teardownBudget(), [&] {
        const auto it = registry.modules.find(key);
        return it == registry.modules.end() || !it->second.expired();
    });
    if (!ready) {
        std::ostringstream what;
        what << "PKCS#11 module " << key << " is still being finalized after " << teardownBudget().count()
             << " ms; refusing to wait longer";
        throw std::runtime_error(what.str());
    }

    if (const auto it = registry.modules.find(key); it != registry.modules.end()) {
        if (auto live = it->second.lock())
            return live;
    }

    auto owned = loadModule(std::filesystem::path{key});
    // Make the node exist before anything owns the module: assigning into a node
    // that is already there cannot throw, so the module can never be orphaned
    // into a deleter that would be asking for this very lock.
    registry.modules[key] = std::weak_ptr<LoadedModule>{};
    std::shared_ptr<LoadedModule> loaded(owned.release(), &releaseModule);
    registry.modules[key] = loaded;
    return loaded;
}

} // namespace

void setModuleRegistryRendezvousForTest(std::function<void(ModuleRegistryEvent)> rendezvous)
{
    auto& state = rendezvousState();
    const bool installed = static_cast<bool>(rendezvous);
    {
        std::scoped_lock lock(state.mu);
        state.hook = std::move(rendezvous);
    }
    state.installed.store(installed, std::memory_order_release);
}

std::size_t sharedModuleLoadCountForTest()
{
    return moduleLoadCount().load(std::memory_order_relaxed);
}

std::size_t sharedModuleEntryCountForTest()
{
    auto& registry = sharedModuleRegistry();
    std::scoped_lock lock(registry.mu);
    return registry.modules.size();
}

void setModuleTeardownBudgetForTest(std::chrono::milliseconds budget)
{
    teardownBudgetMs().store(budget.count(), std::memory_order_relaxed);
}

void resetSharedModuleRegistryForTest()
{
    auto& registry = sharedModuleRegistry();
    {
        std::scoped_lock lock(registry.mu);
        registry.modules.clear();
        moduleLoadCount().store(0, std::memory_order_relaxed);
    }
    // Clearing entries can satisfy a waiter's predicate, and a waiter that is
    // not told about it sleeps until somebody else's teardown notifies.
    registry.teardownComplete.notify_all();
}

std::size_t liveSharedModuleCountForTest()
{
    auto& registry = sharedModuleRegistry();
    std::scoped_lock lock(registry.mu);
    std::size_t live = 0;
    for (const auto& [path, module] : registry.modules) {
        if (!module.expired())
            ++live;
    }
    return live;
}

Pkcs11ModuleHandle Pkcs11ModuleManager::acquire(const std::filesystem::path& modulePath)
{
    const std::string key = canonicalKey(modulePath);

    std::scoped_lock lock(mu);

    auto it = modules.find(key);
    if (it == modules.end()) {
        it = modules.try_emplace(key, acquireShared(key)).first;
    }

    // The only place a LoadedModule becomes a handle. The handle gets an
    // ALIASING shared_ptr: it shares ownership of the module and points at the
    // module's own view of itself, so pkcs11_module_handle.cpp compiles against
    // a forward declaration alone -- which keeps this object file, with its
    // dlopen and its C_Finalize, out of the link closure of the exported
    // Pkcs11Token constructors -- while a handle stays one shared_ptr wide.
    return Pkcs11ModuleHandle(std::shared_ptr<const Pkcs11ModuleView>(it->second, &it->second->view));
}

} // namespace libresign
