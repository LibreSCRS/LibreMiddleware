// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

/// @file
/// @brief Plugin ABI entry-point convenience macros.
///
/// Every card plugin `.so` / `.dylib` MUST export three C-linkage symbols:
///
///  - `LibreSCRS::Plugin::CardPlugin* create_card_plugin()` — heap-allocates
///    and returns a plugin instance. Ownership transfers to the caller.
///  - `void destroy_card_plugin(LibreSCRS::Plugin::CardPlugin*)` — destroys
///    an instance previously returned by `create_card_plugin`. MUST perform
///    the deletion inside the plugin's own translation unit so the
///    plugin's allocator handles the release, avoiding stdlib-mismatch
///    crashes when the host application and the plugin were compiled
///    against different `libstdc++` / `libc++` copies.
///  - `uint32_t card_plugin_abi_version()` — returns
///    @c LibreSCRS::Plugin::kCardPluginAbiVersion so the registry can
///    reject plugins built against a stale header.
///
/// Declaring these by hand in every plugin is error-prone; the
/// @ref LIBRESCRS_DECLARE_CARD_PLUGIN macro emits all three entry points
/// plus a compile-time ABI check in one line.
///
/// Hosts that load plugins (`LibreSCRS::Plugin::CardPluginService`) rely
/// on both the `create` and `destroy` symbols; see `card_plugin_registry.cpp`
/// for the loader's ABI check + symbol lookup sequence.
/// @since 4.0

#include <LibreSCRS/Plugin/CardPlugin.h>
#include <LibreSCRS/Plugin/PluginTypes.h>

#include <cstdint>

namespace LibreSCRS::Plugin::detail {

/// @brief Instantiate a @p PluginType with exception translation.
///
/// Helper used by @ref LIBRESCRS_DECLARE_CARD_PLUGIN. Wrapping the
/// `new PluginType()` call in a function (instead of inlining it inside
/// the macro expansion) keeps stack traces readable: debuggers and
/// crash-report symbolisers can name this frame rather than reporting an
/// unnamed lambda-like site in the macro-expanded factory. The translation
/// unit that carries the macro still pays only one template instantiation.
///
/// @return A heap-allocated @p PluginType on success; @c nullptr when the
///         constructor threw. Exceptions MUST NOT cross the plugin ABI
///         boundary — host and plugin may be compiled against different
///         standard libraries. Callers translate @c nullptr into
///         @ref LibreSCRS::Plugin::LoadOutcome::Status::FactoryThrew.
template <typename PluginType>
CardPlugin* createPluginInstance() noexcept
{
    try {
        return new PluginType();
    } catch (...) {
        return nullptr;
    }
}

} // namespace LibreSCRS::Plugin::detail

/// @brief Declare the ABI entry points for a card plugin.
///
/// Use in exactly ONE source file per plugin `.so` / `.dylib`. Pins the ABI
/// version at compile time via `static_assert` and exports
/// `create_card_plugin`, `destroy_card_plugin`, and
/// `card_plugin_abi_version` with C linkage.
///
/// Usage:
/// @code
/// // In e.g. my_plugin.cpp:
/// class MyPlugin : public LibreSCRS::Plugin::CardPlugin { ... };
/// LIBRESCRS_DECLARE_CARD_PLUGIN(MyPlugin, 7)
/// @endcode
///
/// Where @c PluginType is the derived class name and @c AbiVersion is the
/// ABI revision the plugin was authored against. If
/// @c LibreSCRS::Plugin::kCardPluginAbiVersion changes without a plugin
/// rebuild, the `static_assert` fires at compile time rather than at load
/// time.
///
/// @note Each plugin SO gets its own pair of factory symbols, so naming
///       collisions are impossible across `.so` boundaries when
///       `RTLD_LOCAL` is used (see `CardPluginService`).
///
/// @note `create_card_plugin` is declared @c noexcept: the `new PluginType()`
///       call is wrapped in a try/catch that returns @c nullptr on any
///       exception. Combined with the existing symmetry — `destroy_card_plugin`
///       is already @c noexcept — this keeps exceptions from crossing the
///       plugin ABI boundary in either direction. An exception thrown by
///       the derived plugin's constructor surfaces to the registry as
///       `LoadOutcome::Status::FactoryThrew` with an empty @c diagnostic.
///       The registry's own try/catch (see `card_plugin_registry.cpp`)
///       remains in place as a defence-in-depth belt for plugins compiled
///       against older copies of this macro.
#define LIBRESCRS_DECLARE_CARD_PLUGIN(PluginType, AbiVersion)                                                          \
    static_assert(::LibreSCRS::Plugin::kCardPluginAbiVersion == static_cast<std::uint32_t>(AbiVersion),                \
                  "Plugin ABI version mismatch — rebuild against current LibreSCRS headers");                          \
    extern "C" LIBRESCRS_PUBLIC_API ::LibreSCRS::Plugin::CardPlugin* create_card_plugin() noexcept                     \
    {                                                                                                                  \
        /* Delegates to a named template helper so debuggers and crash                                                 \
         * reports can resolve the frame — macro-expanded try/catch sites                                            \
         * symbolise as the plugin's own TU with no function name. */                                                  \
        return ::LibreSCRS::Plugin::detail::createPluginInstance<PluginType>();                                        \
    }                                                                                                                  \
    extern "C" LIBRESCRS_PUBLIC_API void destroy_card_plugin(::LibreSCRS::Plugin::CardPlugin* plugin) noexcept         \
    {                                                                                                                  \
        delete plugin;                                                                                                 \
    }                                                                                                                  \
    extern "C" LIBRESCRS_PUBLIC_API std::uint32_t card_plugin_abi_version() noexcept                                   \
    {                                                                                                                  \
        return ::LibreSCRS::Plugin::kCardPluginAbiVersion;                                                             \
    }
