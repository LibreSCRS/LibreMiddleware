// SPDX-License-Identifier: LGPL-2.1-or-later
#include "Pkcs11ModulePath.h"

#include <array>
#include <system_error>

namespace LibreSCRS::Signing::detail {

std::string resolvePkcs11ModulePath(const std::filesystem::path& exeDir, std::string_view moduleName,
                                    std::string_view relLibDir, std::string_view configuredAbsolute)
{
    const std::filesystem::path name{moduleName};
    // relLibDir is the install layout's library directory — "lib", "lib64", or
    // a multiarch triplet. It belongs ONLY in the two candidates that describe
    // an installed prefix. Candidates 2, 6, 7 and 8 keep "lib" spelled out
    // because there it is the literal name of a directory a build tree makes,
    // not a distribution's libdir; parameterising them would break the dev,
    // FetchContent and bundle layouts they exist for.
    const std::filesystem::path libDir{relLibDir.empty() ? std::string_view{"lib"} : relLibDir};
    const std::array<std::filesystem::path, 8> candidates{
        exeDir / name,
        exeDir / ".." / "lib" / name,
        exeDir / ".." / "Frameworks" / name,
        exeDir / ".." / libDir / "pkcs11" / name,
        exeDir / libDir / "pkcs11" / name,
        exeDir / ".." / "_deps" / "libremiddleware-build" / "lib" / "pkcs11" / name,
        exeDir / ".." / ".." / "LibreMiddleware" / "build" / "lib" / "pkcs11" / name,
        exeDir / ".." / ".." / ".." / ".." / "lib" / "pkcs11" / name,
    };
    // canonical() with an error_code, never the throwing overload: an exception
    // would unwind across a plugin's dlopen boundary.
    for (const auto& p : candidates) {
        std::error_code cec;
        auto c = std::filesystem::canonical(p, cec);
        if (!cec && std::filesystem::exists(c)) {
            return c.string();
        }
    }
    // LAST, and deliberately so: the absolute this build was configured with is
    // right for an installed prefix that is not exe-relative, but a bundled
    // module — AppImage, .app, FetchContent, dev tree — must win over a system
    // one of a different version, and every candidate above describes a bundle.
    if (!configuredAbsolute.empty()) {
        std::error_code cec;
        auto c = std::filesystem::canonical(std::filesystem::path{configuredAbsolute}, cec);
        if (!cec && std::filesystem::exists(c)) {
            return c.string();
        }
    }
    return std::string{moduleName};
}

} // namespace LibreSCRS::Signing::detail
