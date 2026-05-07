// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "dss/dss_path_resolver.h"

#include <cstdlib>
#include <filesystem>

#ifdef __APPLE__
#include <mach-o/dyld.h>
#endif

namespace fs = std::filesystem;

namespace libresign {

std::string DSSPathResolver::executableDir()
{
#ifdef __APPLE__
    uint32_t size = 0;
    _NSGetExecutablePath(nullptr, &size);
    std::string buf(size, '\0');
    if (_NSGetExecutablePath(buf.data(), &size) == 0)
        return fs::path(buf).parent_path().string();
    return {};
#else
    std::error_code ec;
    auto exePath = fs::read_symlink("/proc/self/exe", ec);
    if (!ec)
        return exePath.parent_path().string();
    return {};
#endif
}

DSSServiceManager::Config DSSPathResolver::resolve()
{
    DSSServiceManager::Config config;
    config.startupTimeout = std::chrono::seconds{30};

    // 1. Environment override
    if (const char* envJar = std::getenv("LIBRESCRS_DSS_JAR")) {
        fs::path jarPath(envJar);
        if (fs::exists(jarPath)) {
            config.jarPath = jarPath.string();
            auto dir = jarPath.parent_path();
            auto jreBin = dir / "jre" / "bin" / "java";
            config.javaPath = fs::exists(jreBin) ? jreBin.string() : "java";
            auto cdsArchive = dir / "cds" / "application.jsa";
            if (fs::exists(cdsArchive))
                config.bundledCdsPath = (dir / "cds").string();
            return config;
        }
    }

    // 2. Installed / bundled locations relative to executable
    auto exeDir = executableDir();
    if (!exeDir.empty()) {
        std::vector<fs::path> candidates = {
            fs::path(exeDir) / ".." / "share" / "librescrs" / "signing",
#ifdef __APPLE__
            fs::path(exeDir) / ".." / "Frameworks" / "signing",
#endif
        };

        for (const auto& dir : candidates) {
            std::error_code ec;
            if (!fs::is_directory(dir, ec))
                continue;

            // Scan for first *.jar
            for (const auto& entry : fs::directory_iterator(dir, ec)) {
                if (entry.path().extension() == ".jar") {
                    config.jarPath = entry.path().string();
                    break;
                }
            }
            if (config.jarPath.empty())
                continue;

            auto jreBin = dir / "jre" / "bin" / "java";
            config.javaPath = fs::exists(jreBin) ? jreBin.string() : "java";

            auto cdsArchive = dir / "cds" / "application.jsa";
            if (fs::exists(cdsArchive))
                config.bundledCdsPath = (dir / "cds").string();

            break;
        }
    }

    // 3. Dev fallback
    if (config.jarPath.empty()) {
        if (const char* srcDir = std::getenv("LIBREMIDDLEWARE_SOURCE_DIR")) {
            auto devJar = fs::path(srcDir) / "tools" / "dss-service" / "target" / "dss-service-1.0.0-SNAPSHOT.jar";
            if (fs::exists(devJar))
                config.jarPath = devJar.string();
        }
    }

    return config;
}

} // namespace libresign
