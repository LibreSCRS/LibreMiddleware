// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "libresign/dss/dss_service_manager.h"
#include "libresign/http_client.h"

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <mutex>
#include <thread>
#include <vector>

#include <fcntl.h>
#include <signal.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

namespace fs = std::filesystem;

namespace libresign {

namespace {

bool isJavaAvailable(const std::string& javaPath)
{
    // Absolute or relative path with directory separator
    if (javaPath.find('/') != std::string::npos)
        return access(javaPath.c_str(), X_OK) == 0;

    // Bare command name — search PATH
    const char* pathEnv = std::getenv("PATH");
    if (!pathEnv)
        return false;

    std::string_view path(pathEnv);
    size_t start = 0;
    while (start <= path.size()) {
        auto end = path.find(':', start);
        if (end == std::string_view::npos)
            end = path.size();
        auto dir = path.substr(start, end - start);
        auto candidate = (fs::path(dir) / javaPath).string();
        if (!dir.empty() && access(candidate.c_str(), X_OK) == 0)
            return true;
        start = end + 1;
    }
    return false;
}

fs::path platformCacheDir()
{
#ifdef __APPLE__
    const char* home = std::getenv("HOME");
    if (home)
        return fs::path(home) / "Library" / "Caches" / "LibreSCRS" / "dss";
#else
    const char* xdgCache = std::getenv("XDG_CACHE_HOME");
    if (xdgCache)
        return fs::path(xdgCache) / "librescrs" / "dss";
    const char* home = std::getenv("HOME");
    if (home)
        return fs::path(home) / ".cache" / "librescrs" / "dss";
#endif
    std::cerr << "libresign: HOME not set, CDS cache disabled" << std::endl;
    return {};
}

/// Close inherited file descriptors and redirect stdout/stderr to a log file.
/// Must be called immediately after fork() in the child process.
static void prepareChildProcess(const std::string& logPath, int openFlags = O_TRUNC)
{
    // Restrict file creation mode so that the Unix socket created by the
    // Java service (and any other files it creates) is owner-only (0600).
    // This matters on Linux when we fall back to /tmp/libresc-dss-<uid>.sock
    // where /tmp is world-writable and default permissions would let other
    // local users connect.
    umask(0077);

    // Close inherited file descriptors (X11, dbus, PC/SC, etc.)
    long maxFd = sysconf(_SC_OPEN_MAX);
    if (maxFd < 0 || maxFd > 4096)
        maxFd = 4096;
    for (int fd = 3; fd < maxFd; ++fd)
        close(fd);

    // Redirect stdout/stderr to log file.
    // Mode 0600: log contains Java stack traces and DSS verbose output
    // which may leak path/cert info — restrict to owner.
    int logFd = open(logPath.c_str(), O_WRONLY | O_CREAT | openFlags, 0600);
    if (logFd < 0)
        logFd = open("/dev/null", O_WRONLY);
    if (logFd >= 0) {
        dup2(logFd, STDOUT_FILENO);
        dup2(logFd, STDERR_FILENO);
        close(logFd);
    }
}

} // namespace

DSSServiceManager::DSSServiceManager(Config config)
    : config(std::move(config)), httpClient(std::make_unique<HttpClient>())
{}

DSSServiceManager::~DSSServiceManager()
{
    stop();
}

DSSServiceManager::StartResult DSSServiceManager::ensureRunning()
{
    std::lock_guard lock(mutex);

    if (socketPath.empty()) {
#ifdef __APPLE__
        // macOS: $TMPDIR is already per-user (/var/folders/.../T/), no uid needed.
        // Keep path short for 104-byte sun_path limit.
        socketPath = (fs::temp_directory_path() / "libresc-dss.sock").string();
#else
        // Linux: prefer $XDG_RUNTIME_DIR, fall back to /tmp with uid suffix.
        const char* xdgRuntime = std::getenv("XDG_RUNTIME_DIR");
        if (xdgRuntime && fs::exists(xdgRuntime))
            socketPath = (fs::path(xdgRuntime) / "libresc-dss.sock").string();
        else
            socketPath = (fs::temp_directory_path() / ("libresc-dss-" + std::to_string(getuid()) + ".sock")).string();
#endif
    }

    // Check if an existing service (started by another app) is already running
    if (isHealthy())
        return {baseUrl(), {}};

    if (!isJavaAvailable(config.javaPath))
        return {{}, "Java runtime not found. Please install Java 17 or later."};

    if (!fs::exists(config.jarPath))
        return {{}, "DSS service JAR not found: " + config.jarPath};

    // Remove stale socket file if it exists
    fs::remove(socketPath);

    std::string socketArg = "--server.socket-path=" + socketPath;

    // Resolve log file path next to the socket
    if (logPath.empty()) {
        auto socketDir = fs::path(socketPath).parent_path();
        logPath = (socketDir / "libresc-dss.log").string();
    }

    // Try CDS-accelerated startup, fall back to plain JAR
    auto cds = prepareCds();

    pid = fork();
    if (pid == 0) {
        prepareChildProcess(logPath);

        if (!cds.archiveFile.empty()) {
            std::string archiveArg = "-XX:SharedArchiveFile=" + cds.archiveFile;
            execlp(config.javaPath.c_str(), "java", "--enable-native-access=ALL-UNNAMED", archiveArg.c_str(), "-jar",
                   cds.appJar.c_str(), socketArg.c_str(), nullptr);
        }
        // Fallback: plain JAR (also reached if execlp above fails)
        execlp(config.javaPath.c_str(), "java", "--enable-native-access=ALL-UNNAMED", "-jar", config.jarPath.c_str(),
               socketArg.c_str(), nullptr);
        _exit(1);
    }

    if (pid < 0)
        return {{}, "Failed to start DSS service process"};

    if (!waitForHealth(config.startupTimeout)) {
        stop();
        return {{}, "DSS service failed to start within " + std::to_string(config.startupTimeout.count()) + " seconds"};
    }

    return {baseUrl(), {}};
}

bool DSSServiceManager::isHealthy() const
{
    std::lock_guard lock(mutex);

    if (socketPath.empty())
        return false;

    auto resp = httpClient->get(baseUrl() + "/health", 3, socketPath);
    return resp.statusCode == 200;
}

void DSSServiceManager::stop()
{
    // Snapshot BOTH pid and socketPath under the lock, then clear them
    // atomically. Earlier revision cleared pid first, dropped the lock, and
    // re-acquired it at the end to remove socketPath — a concurrent
    // ensureRunning() inside the 5s waitpid window could then spawn a new
    // service and set a new socketPath, which we would then delete.
    pid_t localPid;
    fs::path localSocketPath;
    {
        std::lock_guard lock(mutex);
        localPid = pid;
        pid = -1;
        localSocketPath = std::move(socketPath);
        socketPath.clear();
    }

    // Wait for process outside the lock — waitpid can block for seconds
    if (localPid > 0) {
        kill(localPid, SIGTERM);

        // Wait up to 5 seconds for graceful shutdown
        auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        bool exited = false;
        while (std::chrono::steady_clock::now() < deadline) {
            int status;
            pid_t ret = waitpid(localPid, &status, WNOHANG);
            if (ret == localPid || ret < 0) {
                exited = true;
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        if (!exited) {
            kill(localPid, SIGKILL);
            int status;
            waitpid(localPid, &status, 0);
        }
    }

    if (!localSocketPath.empty()) {
        std::error_code ec;
        fs::remove(localSocketPath, ec); // ignore errors — best-effort cleanup
    }
}

std::string DSSServiceManager::baseUrl() const
{
    std::lock_guard lock(mutex);

    if (socketPath.empty())
        return {};
    return "http://localhost";
}

// Must be called with mutex held (called from ensureRunning which holds the lock).
bool DSSServiceManager::waitForHealth(std::chrono::seconds timeout)
{
    auto deadline = std::chrono::steady_clock::now() + timeout;

    while (std::chrono::steady_clock::now() < deadline) {
        // Check if child died
        int status;
        if (waitpid(pid, &status, WNOHANG) != 0) {
            pid = -1;
            return false;
        }

        if (isHealthy())
            return true;

        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
    return false;
}

bool DSSServiceManager::runProcess(const std::vector<std::string>& args, const std::string& logDir, int timeoutSeconds)
{
    pid_t child = fork();
    if (child == 0) {
        prepareChildProcess((fs::path(logDir) / "cds-setup.log").string(), O_APPEND);

        std::vector<const char*> argv;
        for (const auto& a : args)
            argv.push_back(a.c_str());
        argv.push_back(nullptr);
        execvp(argv[0], const_cast<char* const*>(argv.data()));
        _exit(1);
    }
    if (child < 0)
        return false;

    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(timeoutSeconds);
    while (std::chrono::steady_clock::now() < deadline) {
        int status;
        pid_t ret = waitpid(child, &status, WNOHANG);
        if (ret == child)
            return WIFEXITED(status) && WEXITSTATUS(status) == 0;
        if (ret < 0)
            return false;
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    // Timeout — kill the child
    kill(child, SIGKILL);
    int status;
    waitpid(child, &status, 0);
    return false;
}

DSSServiceManager::CdsPaths DSSServiceManager::prepareCds()
{
    auto jarDir = fs::path(config.jarPath).parent_path();
    auto jarFilename = fs::path(config.jarPath).filename();

    // Determine CDS directory: prefer next to JAR (dev mode), fall back to cache
    fs::path cdsDir;
    if (access(jarDir.c_str(), W_OK) == 0) {
        cdsDir = jarDir / "cds";
    } else {
        cdsDir = platformCacheDir();
        if (cdsDir.empty())
            return {};
    }

    auto extractedJar = cdsDir / jarFilename; // extract preserves original name
    auto archiveFile = cdsDir / "application.jsa";
    auto stampFile = cdsDir / ".jar-mtime";
    // Log next to cds/ dir: in dev mode this is the JAR directory,
    // on read-only mounts this is the cache parent (e.g. ~/.cache/librescrs/).
    auto logDir = cdsDir.parent_path().string();

    // Acquire an advisory lock to serialize concurrent CDS preparation
    // from multiple LibreCelik instances. The lock file lives in
    // cdsDir.parent_path() so it survives the fs::remove_all(cdsDir) below.
    // Released when the file descriptor closes (RAII via close-on-scope-exit).
    std::error_code ec;
    fs::create_directories(cdsDir.parent_path(), ec);
    ec.clear();
    auto lockPath = cdsDir.parent_path() / "cds.lock";
    int lockFd = open(lockPath.c_str(), O_CREAT | O_RDWR, 0600);
    if (lockFd < 0)
        return {}; // can't lock — give up
    struct LockGuard {
        int fd;
        ~LockGuard() {
            if (fd >= 0) {
                flock(fd, LOCK_UN);
                close(fd);
            }
        }
    } lockGuard{lockFd};
    if (flock(lockFd, LOCK_EX) != 0)
        return {};

    // Check if existing CDS is up-to-date by comparing source JAR mtime.
    // Done after acquiring the lock — another process may have prepared
    // CDS while we were waiting.
    auto jarMtime = fs::last_write_time(config.jarPath, ec);
    if (ec)
        return {};

    bool upToDate = false;
    if (fs::exists(stampFile) && fs::exists(archiveFile) && fs::exists(extractedJar)) {
        std::ifstream stamp(stampFile);
        long long storedMtime = 0;
        stamp >> storedMtime;
        upToDate = (storedMtime == static_cast<long long>(jarMtime.time_since_epoch().count()));
    }

    if (upToDate)
        return {extractedJar.string(), archiveFile.string()};

    // Try copying pre-built CDS from bundle (instant first launch)
    //
    // TODO(security): verify bundled CDS integrity. Currently we trust that
    // the bundled archive shipped with the application binary is intact.
    // Future: ship a SHA-256 of the bundled CDS in a separate manifest file
    // at build time and verify here before copying.
    if (!config.bundledCdsPath.empty()) {
        auto bundledArchive = fs::path(config.bundledCdsPath) / "application.jsa";
        // Basic sanity check: refuse to consume a suspiciously small archive.
        // A real JSA is many megabytes; anything below 1 KiB is almost
        // certainly truncated, empty, or a placeholder.
        std::error_code szEc;
        auto bundledSize = fs::exists(bundledArchive) ? fs::file_size(bundledArchive, szEc) : 0;
        if (szEc) bundledSize = 0;
        if (fs::exists(bundledArchive) && bundledSize >= 1024) {
            fs::remove_all(cdsDir, ec);
            ec.clear();
            fs::create_directories(cdsDir, ec);
            if (!ec) {
                // Extract the JAR into the cache directory
                bool extracted = runProcess({config.javaPath, "-Djarmode=tools", "-jar", config.jarPath, "extract",
                                             "--destination", cdsDir.string()},
                                            logDir, 30);
                if (extracted && fs::exists(extractedJar)) {
                    // Copy the pre-built CDS archive
                    fs::copy(bundledArchive, archiveFile, fs::copy_options::overwrite_existing, ec);
                    if (!ec) {
                        // Write stamp
                        std::ofstream stamp(stampFile);
                        stamp << static_cast<long long>(jarMtime.time_since_epoch().count());
                        return {extractedJar.string(), archiveFile.string()};
                    }
                }
            }
            // Copy failed — fall through to full CDS generation
            ec.clear();
        }
    }

    // Clean and recreate CDS directory
    fs::remove_all(cdsDir, ec);
    ec.clear();
    fs::create_directories(cdsDir, ec);
    if (ec)
        return {};

    // Step 1: Extract the Spring Boot fat JAR
    if (!runProcess(
            {config.javaPath, "-Djarmode=tools", "-jar", config.jarPath, "extract", "--destination", cdsDir.string()},
            logDir, 30))
        return {};

    if (!fs::exists(extractedJar))
        return {};

    // Step 2: Training run — load all classes, dump CDS archive, then exit.
    auto trainingArgs = std::vector<std::string>{config.javaPath,
                                                 "-XX:ArchiveClassesAtExit=" + archiveFile.string(),
                                                 "-Dspring.context.exit=onRefresh",
                                                 "--enable-native-access=ALL-UNNAMED",
                                                 "-jar",
                                                 extractedJar.string()};

    bool trained = runProcess(trainingArgs, logDir, 60);
    if (!trained) {
        // jlink JREs may lack a base CDS archive — generate one and retry
        runProcess({config.javaPath, "-Xshare:dump"}, logDir, 30);
        trained = runProcess(trainingArgs, logDir, 60);
    }
    if (!trained)
        return {};

    if (!fs::exists(archiveFile))
        return {};

    // Write stamp file with source JAR mtime for staleness detection
    std::ofstream stamp(stampFile);
    stamp << static_cast<long long>(jarMtime.time_since_epoch().count());

    return {extractedJar.string(), archiveFile.string()};
}

} // namespace libresign
