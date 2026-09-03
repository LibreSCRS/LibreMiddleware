// SPDX-License-Identifier: LGPL-2.1-or-later
#pragma once

#include <filesystem>
#include <string>
#include <string_view>

namespace LibreSCRS::Signing::detail {

/// @brief Resolve the path to the PKCS#11 module for one install layout.
///
/// Split out of SigningService so the layouts can be asserted. The lookup used
/// to have internal linkage inside a service that opens /proc/self/exe, so no
/// test could reach it and seven install layouts had no coverage between them.
///
/// Pure by construction: every input the decision depends on is a parameter.
/// Reading /proc/self/exe (or _NSGetExecutablePath) and the
/// LIBRESCRS_PKCS11_MODULE environment override both stay in SigningService.cpp.
///
/// @param exeDir            directory of the running executable
/// @param moduleName        e.g. "librescrs-pkcs11.so" ("…dylib" on Apple)
/// @param relLibDir         CMAKE_INSTALL_LIBDIR of the build that installed the
///                          module: "lib", "lib64", "lib/x86_64-linux-gnu"
/// @param configuredAbsolute CMAKE_INSTALL_FULL_LIBDIR/pkcs11/<moduleName> of
///                          that same build; empty is allowed
/// @return the resolved absolute path, or @p moduleName when nothing matched —
///         in which case the dynamic loader takes the decision.
[[nodiscard]] std::string resolvePkcs11ModulePath(const std::filesystem::path& exeDir, std::string_view moduleName,
                                                  std::string_view relLibDir, std::string_view configuredAbsolute);

} // namespace LibreSCRS::Signing::detail
