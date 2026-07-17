// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

/// @file
/// @brief Export and visibility macros for the LibreSCRS public API.
/// @since 4.0
///
/// Defines two complementary macros:
///
///   - @ref LIBRESCRS_PUBLIC_API — applied to every public class/function
///     declaration in the LibreSCRS::{Auth,SmartCard,Secure,Plugin,Signing}
///     namespaces, exporting the symbol across the shared-library boundary.
///   - @ref LIBRESCRS_INTERNAL — applied to implementation types inside
///     public compilation units (notably pimpl `struct Impl` definitions) to
///     force hidden visibility and prevent their symbols from leaking across
///     the shared-library boundary.
///
/// @par API Policy
/// The full LibreSCRS API policy (versioning, deprecation rules, validation
/// vs. runtime error handling, plugin ABI) is published at:
///   https://librescrs.github.io/dev/api-policy/
/// Doxygen comments throughout the public headers reference that document by
/// section number (e.g. "per API-POLICY §5.1" for the validation-throws rule).
/// Consumers reading these headers should follow the URL above for the
/// normative text.
///
/// @par Ownership convention
/// All public LibreSCRS services that depend on another service (rather than
/// on a plain-data aggregate) take those dependencies by `std::shared_ptr`.
/// This is a deliberate footgun-elimination rule: it removes the "must
/// outlive" destruction-order class of UAF bugs that only surface at
/// process shutdown. Services that apply this rule include
/// @ref LibreSCRS::Signing::SigningService::sign (`cardPlugin`, `session`)
/// and @ref LibreSCRS::Plugin::AutoReaderService (`monitor`, `registry`). Internal
/// workers that outlive the caller's stack frame capture `std::weak_ptr`
/// and promote at use.

/// @def LIBRESCRS_PUBLIC_API
/// @brief Export attribute applied to public declarations whose symbols
///        cross the library boundary.
///
/// Expands to:
///   - `__attribute__((visibility("default")))` on GCC/Clang (Linux/macOS) to
///     preserve exported symbols when the library is compiled with
///     `-fvisibility=hidden` (which public LibreSCRS targets are — see
///     `lib/LibreSCRS/CMakeLists.txt`);
///   - nothing on unknown toolchains.
///
/// Currently supported toolchains: GCC >= 13, Clang >= 16, AppleClang >= 16.
/// The corresponding MSVC `__declspec(dllexport)`/`dllimport` branch will be
/// added when Windows support lands (5.x consideration).
///
/// @par When to apply LIBRESCRS_PUBLIC_API
///
/// Applied to **pimpl-backed classes with defined ABI**: types whose member
/// functions are defined in a `.cpp` file and whose state is held through an
/// opaque `struct Impl` pointer. Examples: @ref LibreSCRS::Signing::SigningService,
/// @ref LibreSCRS::SmartCard::CardSession, @ref LibreSCRS::SmartCard::MonitorService,
/// @ref LibreSCRS::Plugin::AutoReaderService, @ref LibreSCRS::Plugin::CardPluginService,
/// @ref LibreSCRS::Secure::Buffer, @ref LibreSCRS::Secure::String. Also applied
/// to the @ref LibreSCRS::Plugin::CardPlugin abstract base (vtable + typeinfo
/// must be exported so `dynamic_cast` across the plugin `.so` boundary works).
/// Free functions with cross-TU definitions (e.g.
/// `LibreSCRS::Signing::staticTsa`) and selected out-of-line members on
/// otherwise aggregate types
/// (@ref LibreSCRS::Auth::AuthRequirement factory functions,
/// @ref LibreSCRS::Plugin::SecurityStatus::computeOverall) carry the macro on
/// the individual symbol rather than the enclosing type.
///
/// **Not** applied to plain-data aggregate structs (e.g. @ref
/// LibreSCRS::Signing::SigningResult, @ref LibreSCRS::Auth::CredentialResult,
/// @ref LibreSCRS::Plugin::CardData, @ref LibreSCRS::Signing::TsaCredentials).
/// These types are header-only: their members (`std::string`, `std::vector`,
/// `std::map`, `std::optional`, etc.) have layouts dependent on the consumer's
/// C++ standard library ABI, so exporting them via `__declspec(dllexport)`
/// is meaningless on ELF and an MSVC footgun (it drags the STL specialisations
/// into the export set). Instead, LibreSCRS relies on the **static-link
/// consistent-toolchain contract**: consumers link against the static archive
/// and compile against the same C++ standard library (libstdc++ or libc++)
/// version as the LibreSCRS build. Mixed-stdlib and mixed-`_GLIBCXX_USE_CXX11_ABI`
/// linking is unsupported.
#if defined(__GNUC__) || defined(__clang__)
#define LIBRESCRS_PUBLIC_API __attribute__((visibility("default")))
#else
#define LIBRESCRS_PUBLIC_API
#endif

/// @def LIBRESCRS_INTERNAL
/// @brief Hidden-visibility attribute for implementation types.
///
/// Apply to pimpl `struct Impl` definitions in .cpp files, and to any other
/// internal class in a public compilation unit whose symbols must stay local
/// to the translation unit. Expands to
/// `__attribute__((visibility("hidden")))` on GCC/Clang, and to nothing on
/// other compilers.
#if defined(__GNUC__) || defined(__clang__)
#define LIBRESCRS_INTERNAL __attribute__((visibility("hidden")))
#else
#define LIBRESCRS_INTERNAL
#endif
