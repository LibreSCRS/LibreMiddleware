// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "native/pkcs11_module_manager.h"

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
    std::filesystem::path canonicalPath;
    void* dl = nullptr;
    CK_FUNCTION_LIST* funcs = nullptr;
    bool weInitialized = false;

    LoadedModule() = default;
    ~LoadedModule()
    {
        if (funcs && weInitialized) {
            // C_Finalize takes a reserved argument that must be NULL_PTR
            // per PKCS#11 v2.40 §6.6.2. Failures here are not actionable
            // from a destructor; the module is going away regardless.
            (void)funcs->C_Finalize(nullptr);
        }
        if (dl) {
            (void)::dlclose(dl);
        }
    }

    LoadedModule(const LoadedModule&) = delete;
    LoadedModule& operator=(const LoadedModule&) = delete;
    LoadedModule(LoadedModule&&) = delete;
    LoadedModule& operator=(LoadedModule&&) = delete;
};

Pkcs11ModuleHandle::Pkcs11ModuleHandle(std::shared_ptr<LoadedModule> module) noexcept : loaded(std::move(module)) {}

void* Pkcs11ModuleHandle::functionList() const noexcept
{
    return loaded ? static_cast<void*>(loaded->funcs) : nullptr;
}

void* Pkcs11ModuleHandle::dlHandle() const noexcept
{
    return loaded ? loaded->dl : nullptr;
}

const std::filesystem::path& Pkcs11ModuleHandle::path() const noexcept
{
    static const std::filesystem::path empty;
    return loaded ? loaded->canonicalPath : empty;
}

Pkcs11ModuleManager::~Pkcs11ModuleManager()
{
    // Drop the cache map under the lock. Each entry's shared_ptr is
    // destroyed as the entry leaves the map; if a Token still holds a
    // handle the LoadedModule survives until that handle drops. In
    // practice Tokens are stack-scoped within sign calls and are gone
    // by the time the service-owning manager destroys.
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

[[nodiscard]] std::shared_ptr<LoadedModule> loadModule(const std::filesystem::path& canonical)
{
    auto loaded = std::make_shared<LoadedModule>();
    loaded->canonicalPath = canonical;

    loaded->dl = ::dlopen(canonical.c_str(), RTLD_NOW);
    if (!loaded->dl)
        throw std::runtime_error(std::string("Cannot load PKCS#11 module: ") + ::dlerror());

    auto getList = reinterpret_cast<CK_C_GetFunctionList>(::dlsym(loaded->dl, "C_GetFunctionList"));
    if (!getList)
        throw std::runtime_error("C_GetFunctionList not found in module");

    if (CK_RV rv = getList(&loaded->funcs); rv != CKR_OK) {
        char buf[32];
        std::snprintf(buf, sizeof(buf), "0x%08lX", static_cast<unsigned long>(rv));
        throw std::runtime_error(std::string("C_GetFunctionList failed: CKR ") + buf);
    }

    // Tolerate CKR_CRYPTOKI_ALREADY_INITIALIZED: some hosts (in-process
    // p11-kit clients, libsofthsm2 inside the same address space) drive
    // C_Initialize earlier in the process lifetime. Treating it as
    // success keeps our own teardown clean — see ~LoadedModule on why
    // weInitialized must remain false in that branch.
    CK_RV initRv = loaded->funcs->C_Initialize(nullptr);
    if (initRv == CKR_OK) {
        loaded->weInitialized = true;
    } else if (initRv == CKR_CRYPTOKI_ALREADY_INITIALIZED) {
        loaded->weInitialized = false;
    } else {
        char buf[32];
        std::snprintf(buf, sizeof(buf), "0x%08lX", static_cast<unsigned long>(initRv));
        throw std::runtime_error(std::string("C_Initialize failed: CKR ") + buf);
    }

    return loaded;
}

} // namespace

Pkcs11ModuleHandle Pkcs11ModuleManager::acquire(const std::filesystem::path& modulePath)
{
    const std::string key = canonicalKey(modulePath);

    std::scoped_lock lock(mu);

    if (auto it = modules.find(key); it != modules.end())
        return Pkcs11ModuleHandle(it->second);

    auto loaded = loadModule(std::filesystem::path{key});
    auto [it, inserted] = modules.try_emplace(key, std::move(loaded));
    return Pkcs11ModuleHandle(it->second);
}

} // namespace libresign
