// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

#include <chrono>
#include <memory>
#include <mutex>
#include <string>

namespace libresign {

class HttpClient;

// Manages the lifecycle of the Java DSS signing service process.
// POSIX-only: uses fork/exec/waitpid/kill for process management.
class DSSServiceManager
{
public:
    struct Config
    {
        std::string jarPath;           // path to dss-service.jar
        std::string javaPath = "java"; // path to java binary
        std::string bundledCdsPath;    // path to pre-built cds/ in bundle (optional)
        std::chrono::seconds startupTimeout{30};
    };

    struct StartResult
    {
        std::string baseUrl; // empty on failure
        std::string error;   // empty on success
        explicit operator bool() const noexcept
        {
            return error.empty();
        }
    };

    explicit DSSServiceManager(Config config);
    ~DSSServiceManager();

    DSSServiceManager(const DSSServiceManager&) = delete;
    DSSServiceManager& operator=(const DSSServiceManager&) = delete;

    // Start the DSS service if not already running.
    // Blocks until health check passes or timeout.
    StartResult ensureRunning();

    // Check if the service is currently running and healthy.
    bool isHealthy() const;

    // Stop the service.
    void stop();

    // The base URL of the running service, empty if not running.
    std::string baseUrl() const;

    // The Unix socket path used for communication.
    // Returns empty string if the service is not running (after stop() or before ensureRunning()).
    std::string unixSocketPath() const
    {
        std::lock_guard lock(mutex);
        return socketPath;
    }

    // The log file path where DSS service stdout/stderr is captured.
    const std::string& logFilePath() const
    {
        return logPath;
    }

private:
    bool waitForHealth(std::chrono::seconds timeout);

    // CDS (Class Data Sharing) support for faster JVM startup.
    // Returns the directory containing the extracted app + CDS archive,
    // or empty string if CDS preparation is unavailable/failed (fallback to plain JAR).
    struct CdsPaths
    {
        std::string appJar;      // extracted application.jar
        std::string archiveFile; // .jsa CDS archive
    };
    CdsPaths prepareCds();
    bool runProcess(const std::vector<std::string>& args, const std::string& logDir, int timeoutSeconds = 60);

    mutable std::recursive_mutex mutex;
    Config config;
    pid_t pid = -1;
    std::string socketPath;
    std::string logPath;
    mutable std::unique_ptr<HttpClient> httpClient; // Thread safety: all access serialized by this->mutex
};

} // namespace libresign
