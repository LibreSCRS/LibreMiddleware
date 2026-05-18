// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

/// @file
/// @brief extern "C" hooks for in-process CardSession injection. The
///        matching public header is installed as
///        <LibreSCRS/Pkcs11/AttachHook.h> alongside the SDK headers.
///
/// Both function bodies use a function-try-block to satisfy the C-linkage
/// contract (no exception ever crosses the boundary). std::bad_alloc is
/// the only realistic escape — SessionRegistry::put may rehash an
/// std::unordered_map — so the catch translates to OUT_OF_MEMORY; any
/// other escape (defensive `catch (...)`) maps to the same numeric code
/// because the caller has no way to distinguish further.

#include <LibreSCRS/Pkcs11/AttachHook.h>

#include "pkcs15_pkcs11_module_context.h"

#include <internal/SessionRegistry.h>

#include <LibreSCRS/SmartCard/CardSession.h>

#include <memory>
#include <mutex>
#include <new>
#include <shared_mutex>
#include <string>

extern "C" int librescrs_pkcs11_attach_session(const char* reader_name, const LibrescrsPkcs11AttachTokenV1* token)
try {
    using namespace LibreSCRS::Pkcs15::Pkcs11;

    // Take libraryMutex shared for the entire span in which the
    // ModuleContext pointer is dereferenced. C_Finalize takes the same
    // mutex exclusively before resetting g_module; without this lock the
    // moduleContext() pointer could be freed under our feet between the
    // accessor call and the put() that uses it.
    std::shared_lock libraryLock(libraryMutex);

    auto* ctx = moduleContext();
    if (!ctx || !ctx->sessionRegistry)
        return LIBRESCRS_PKCS11_ATTACH_NOT_INITIALIZED;

    if (!reader_name || !token)
        return LIBRESCRS_PKCS11_ATTACH_NULL_PTR;
    if (token->magic != LIBRESCRS_PKCS11_ATTACH_MAGIC_V1)
        return LIBRESCRS_PKCS11_ATTACH_BAD_MAGIC;
    if (token->flags != 0UL)
        return LIBRESCRS_PKCS11_ATTACH_BAD_FLAGS;
    if (!token->session_ptr)
        return LIBRESCRS_PKCS11_ATTACH_NULL_PTR;

    auto* sptr = static_cast<std::shared_ptr<LibreSCRS::SmartCard::CardSession>*>(token->session_ptr);
    if (!*sptr)
        return LIBRESCRS_PKCS11_ATTACH_NULL_PTR;

    ctx->sessionRegistry->put(std::string{reader_name}, *sptr);
    return LIBRESCRS_PKCS11_ATTACH_OK;
} catch (const std::bad_alloc&) {
    return LIBRESCRS_PKCS11_ATTACH_OUT_OF_MEMORY;
} catch (...) {
    return LIBRESCRS_PKCS11_ATTACH_OUT_OF_MEMORY;
}

extern "C" int librescrs_pkcs11_detach_session(const char* reader_name)
try {
    using namespace LibreSCRS::Pkcs15::Pkcs11;

    // Same locking discipline as librescrs_pkcs11_attach_session above:
    // shared on libraryMutex for the duration of the ModuleContext deref.
    std::shared_lock libraryLock(libraryMutex);

    auto* ctx = moduleContext();
    if (!ctx || !ctx->sessionRegistry)
        return LIBRESCRS_PKCS11_ATTACH_NOT_INITIALIZED;
    if (!reader_name)
        return LIBRESCRS_PKCS11_ATTACH_NULL_PTR;

    ctx->sessionRegistry->remove(std::string{reader_name});
    return LIBRESCRS_PKCS11_ATTACH_OK;
} catch (const std::bad_alloc&) {
    return LIBRESCRS_PKCS11_ATTACH_OUT_OF_MEMORY;
} catch (...) {
    return LIBRESCRS_PKCS11_ATTACH_OUT_OF_MEMORY;
}
