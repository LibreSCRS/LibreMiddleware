// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

/// @file
/// @brief @ref libresign::Pkcs11ModuleHandle — a refcounted view of one
///        @c dlopen-ed PKCS#11 module, in a translation unit of its own.
///
/// @par Why this lives apart from the module manager
/// The exported @ref libresign::Pkcs11Token constructors take a handle by
/// value, so whichever object file defines the handle's members is pulled into
/// every library that links a Token. While that object file was also the
/// manager's, it carried @c dlopen, @c C_Initialize and the module-path
/// resolver with it, and the signing library linked the loader whether or not
/// it ever called it. Split out, the handle's OBJECT FILE references neither the
/// manager nor the dynamic loader, so the loader's presence becomes a statement
/// about which objects a library actually pulls in. The library itself is a
/// separate question and today still answers yes: the signing library imports
/// @c dlopen because the facade calls the manager.
///
/// That is also why a handle does not point at @ref libresign::LoadedModule but
/// at the read-only projection of it defined below: the module definition, and
/// with it @c C_Finalize and @c dlclose, stays in the manager's translation
/// unit, and this one needs nothing from it.
///
/// @par Why an aliasing @c shared_ptr and not three cached values
/// A handle is passed BY VALUE through two exported, versioned constructors
/// (@ref libresign::Pkcs11Token). Caching the projection's fields inside the
/// handle would grow it from one pointer pair to five, and neither ABI gate can
/// see that: the symbol snapshot compares mangled names, which do not change
/// with a parameter type's layout, and the layout snapshot records only types
/// whose name carries @c LibreSCRS::. A partial rebuild would then read the new
/// size out of an object built to the old one, with no link error to say so.
/// Sharing ownership with the module while pointing at its projection keeps the
/// handle exactly one @c shared_ptr wide, which is what the exported signature
/// was compiled against; the @c static_assert below is what keeps it that way.

#include <filesystem>
#include <memory>

namespace libresign {

// Forward declared so this header does not pull in pkcs11.h. The manager's
// translation unit defines the concrete shape.
struct LoadedModule;

/// @brief Everything a handle is allowed to know about a loaded module.
///
/// Held by value inside the @ref LoadedModule the manager owns, so a handle can
/// share ownership of the module while pointing here. Nothing in it needs
/// pkcs11.h or dlfcn.h, which is the point: this is the whole of the module that
/// crosses into the handle's translation unit.
struct Pkcs11ModuleView
{
    void* functions = nullptr;           ///< The module's @c CK_FUNCTION_LIST, type-erased.
    void* dlopenHandle = nullptr;        ///< The module's @c dlopen handle.
    std::filesystem::path canonicalPath; ///< Path the module was loaded from.
};

/// @brief Lightweight handle to a process-shared loaded PKCS#11 module.
///
/// Held by @ref Pkcs11Token instances and other consumers; copying is
/// a refcount bump on the underlying @ref LoadedModule. The handle
/// exposes the module's path, the C @c CK_FUNCTION_LIST pointer and
/// the raw @c dlopen handle without enabling the holder to unload the
/// module — unload happens when the last handle to it goes away.
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
        return static_cast<bool>(view);
    }

private:
    friend class Pkcs11ModuleManager;
    /// @param moduleView An aliasing pointer: it shares ownership of the
    ///                   @ref LoadedModule that contains the view, so the view
    ///                   cannot outlive the module it describes.
    explicit Pkcs11ModuleHandle(std::shared_ptr<const Pkcs11ModuleView> moduleView) noexcept;

    std::shared_ptr<const Pkcs11ModuleView> view;
};

// The exported Pkcs11Token constructors take a handle BY VALUE. Growing it is
// an ABI change that both gates are blind to (see the note above), so its width
// is asserted here rather than left to a reviewer to notice.
static_assert(sizeof(Pkcs11ModuleHandle) == sizeof(std::shared_ptr<void>),
              "Pkcs11ModuleHandle crosses an exported signature by value: keep it one shared_ptr wide");

} // namespace libresign
