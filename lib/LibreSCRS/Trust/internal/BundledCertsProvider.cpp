// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

// dladdr is a glibc extension; it needs _GNU_SOURCE before the first libc
// header, which the includes below pull in. g++ already defines it, hence
// the guard.
#if defined(__linux__) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif

#include "BundledCertsProvider.h"

#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <climits>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>

#ifdef __linux__
#include <dlfcn.h>
#include <unistd.h>
#elif defined(__APPLE__)
#include <dlfcn.h>
#include <mach-o/dyld.h>
#endif

namespace LibreSCRS::Trust::detail {

namespace fs = std::filesystem;

namespace {

bool hasCertExtension(const fs::path& p)
{
    auto ext = p.extension().string();
    return ext == ".cer" || ext == ".crt" || ext == ".pem";
}

std::vector<std::uint8_t> readFile(const fs::path& p)
{
    std::ifstream f(p, std::ios::binary);
    if (!f)
        return {};
    return {std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>()};
}

// Convert PEM-encoded bytes to DER. Returns empty vector if parse fails.
std::vector<std::uint8_t> pemToDer(const std::vector<std::uint8_t>& bytes)
{
    BIO* bio = BIO_new_mem_buf(bytes.data(), static_cast<int>(bytes.size()));
    if (!bio)
        return {};
    X509* cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!cert)
        return {};
    int len = i2d_X509(cert, nullptr);
    if (len <= 0) {
        X509_free(cert);
        return {};
    }
    std::vector<std::uint8_t> der(static_cast<std::size_t>(len));
    std::uint8_t* p = der.data();
    i2d_X509(cert, &p);
    X509_free(cert);
    return der;
}

bool isValidDer(const std::vector<std::uint8_t>& bytes)
{
    const std::uint8_t* p = bytes.data();
    X509* cert = d2i_X509(nullptr, &p, static_cast<long>(bytes.size()));
    if (cert) {
        X509_free(cert);
        return true;
    }
    return false;
}

void loadDirectoryInto(std::vector<TrustAnchor>& out, const fs::path& dir, const std::string& bundleRoot)
{
    std::error_code ec;
    if (!fs::exists(dir, ec) || !fs::is_directory(dir, ec))
        return;
    for (const auto& entry : fs::directory_iterator(dir, ec)) {
        if (!entry.is_regular_file() || !hasCertExtension(entry.path()))
            continue;
        auto raw = readFile(entry.path());
        if (raw.empty())
            continue;
        std::vector<std::uint8_t> der = isValidDer(raw) ? raw : pemToDer(raw);
        if (der.empty())
            continue;

        TrustAnchor a;
        a.certificateDer = std::move(der);
        a.sourceLabel = "bundled:" + fs::relative(entry.path(), bundleRoot, ec).string();
        out.push_back(std::move(a));
    }
}

} // namespace

BundledCertsProvider::BundledCertsProvider(std::string dir) : bundledCertDir(std::move(dir))
{
    std::error_code ec;
    fs::path root(bundledCertDir);
    if (!fs::exists(root, ec) || !fs::is_directory(root, ec)) {
        return; // empty cache; anchors() will return empty vector
    }

    // Recurse one level into subdirectories (rs-mup, rs-mup-format, rs-pks, ...)
    for (const auto& sub : fs::directory_iterator(root, ec)) {
        if (sub.is_directory()) {
            loadDirectoryInto(cached, sub.path(), bundledCertDir);
        }
    }
    // Also load flat .cer/.crt/.pem files directly in the root.
    loadDirectoryInto(cached, root, bundledCertDir);
}

std::vector<TrustAnchor> BundledCertsProvider::anchors() const
{
    return cached; // copy — caller owns; cache itself is immutable post-ctor
}

namespace {

/// @brief Absolute path to the running executable, or @c nullopt if the
///        platform-specific lookup fails. Used only by @ref resolveBundledCertsDir
///        to derive @c \<exe\>/../share or @c \<exe\>/../Resources candidate
///        directories at runtime.
[[nodiscard]] std::optional<fs::path> exePath() noexcept
{
#ifdef __linux__
    char buf[PATH_MAX];
    auto n = ::readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (n <= 0)
        return std::nullopt;
    buf[n] = '\0';
    try {
        return fs::path(buf);
    } catch (...) {
        return std::nullopt;
    }
#elif defined(__APPLE__)
    char buf[PATH_MAX];
    std::uint32_t sz = sizeof(buf);
    if (_NSGetExecutablePath(buf, &sz) != 0)
        return std::nullopt;
    try {
        return fs::path(buf);
    } catch (...) {
        return std::nullopt;
    }
#else
    return std::nullopt;
#endif
}

/// @brief Anchor object for @ref libraryPath. Its address is somewhere inside
///        whichever shared object ends up carrying this translation unit,
///        which is all @c dladdr needs. A data symbol rather than the address
///        of a function because casting a function pointer to @c void* is what
///        @c -Wpedantic rejects.
const char libraryAnchor = 0;

/// @brief Absolute path of the shared object that contains this translation
///        unit, or @c nullopt where the platform offers no lookup or the
///        lookup fails. In a static build the loader reports the executable
///        itself, which collapses the library-relative candidates into the
///        exe-relative ones — a harmless duplicate probe.
[[nodiscard]] std::optional<fs::path> libraryPath() noexcept
{
#if defined(__linux__) || defined(__APPLE__)
    Dl_info info{};
    if (::dladdr(&libraryAnchor, &info) == 0)
        return std::nullopt;
    if (info.dli_fname == nullptr || info.dli_fname[0] == '\0')
        return std::nullopt;
    try {
        return fs::path(info.dli_fname);
    } catch (...) {
        return std::nullopt;
    }
#else
    return std::nullopt;
#endif
}

/// @brief True when at least one regular file in @p dir has a cert-like
///        extension (.crt / .pem / .cer / .der). Non-recursive — caller drives
///        the one-level descent if needed.
[[nodiscard]] bool dirContainsCertFile(const fs::path& dir) noexcept
{
    std::error_code ec;
    fs::directory_iterator it(dir, ec);
    if (ec)
        return false;
    const fs::directory_iterator end;
    for (; it != end; it.increment(ec)) {
        if (ec)
            return false;
        if (!it->is_regular_file(ec) || ec)
            continue;
        const auto ext = it->path().extension();
        if (ext == ".crt" || ext == ".pem" || ext == ".cer" || ext == ".der")
            return true;
    }
    return false;
}

/// @brief True when @p p exists as a directory and either it (or any of its
///        immediate subdirectories — matching the constructor's one-level
///        descent in @ref BundledCertsProvider) contains a file with a
///        cert-like extension. Empty or missing directories return false so
///        the walker rolls through to the next candidate.
[[nodiscard]] bool isUsableCertsDir(const fs::path& p) noexcept
{
    std::error_code ec;
    if (!fs::is_directory(p, ec))
        return false;
    if (dirContainsCertFile(p))
        return true;
    fs::directory_iterator it(p, ec);
    if (ec)
        return false;
    const fs::directory_iterator end;
    for (; it != end; it.increment(ec)) {
        if (ec)
            return false;
        if (!it->is_directory(ec) || ec)
            continue;
        if (dirContainsCertFile(it->path()))
            return true;
    }
    return false;
}

} // namespace

std::vector<fs::path> certsDirCandidatesForLibrary(const fs::path& libraryPath)
{
    const auto libDir = libraryPath.parent_path();
    if (libDir.empty())
        return {};

    std::vector<fs::path> candidates;
#ifdef __APPLE__
    candidates.push_back(libDir / ".." / "Resources" / "certificates");
#endif
    candidates.push_back(libDir / ".." / "share" / "librescrs" / "certificates");
    return candidates;
}

std::optional<fs::path> resolveBundledCertsDir() noexcept
{
    // Whole-body try/catch: the @c noexcept contract here promises the caller
    // a degraded-but-valid result on any allocation, filesystem, or path
    // construction failure. The bare std::nullopt return is the
    // "no bundled certs, fall back to system trust store" sentinel.
    try {
        // 1. env override — dev/test path; highest priority.
        if (const char* env = std::getenv("LIBRESCRS_CERTIFICATES_DIR")) {
            if (env[0] != '\0') {
                fs::path p(env);
                if (isUsableCertsDir(p))
                    return p;
            }
        }

        // 2. compile-time path — source-tree thirdparty/certificates for dev
        //    builds. Empty define (the unset-fallback we installed at use
        //    site) is filtered by the empty-string guard.
#ifdef LIBREMIDDLEWARE_CERTIFICATES_DIR
        {
            const char* compiled = LIBREMIDDLEWARE_CERTIFICATES_DIR;
            if (compiled != nullptr && compiled[0] != '\0') {
                fs::path p(compiled);
                if (isUsableCertsDir(p))
                    return p;
            }
        }
#endif

        // 3. compile-time install path — where the install rule actually
        //    writes the bundle. Unlike the candidates below it this survives a
        //    split prefix (libraries under one root, ${datadir} under another),
        //    where no relative walk from a binary reaches the certificates.
        //    Same empty-string guard: the define is "" in a build that never
        //    means to install.
#ifdef LIBREMIDDLEWARE_INSTALLED_CERTIFICATES_DIR
        {
            const char* installed = LIBREMIDDLEWARE_INSTALLED_CERTIFICATES_DIR;
            if (installed != nullptr && installed[0] != '\0') {
                std::error_code ec;
                auto canonical = fs::weakly_canonical(fs::path(installed), ec);
                if (!ec && isUsableCertsDir(canonical))
                    return canonical;
            }
        }
#endif

        // 4. library-relative candidates — the shared object carrying this
        //    code need not live under the same prefix as the process that
        //    loaded it (a host binary from /usr/bin pulling LibreSCRS out of
        //    /opt/librescrs/lib). Derive the bundle from the library's own
        //    location before falling back to the executable's.
        if (auto lib = libraryPath()) {
            for (const auto& cand : certsDirCandidatesForLibrary(*lib)) {
                std::error_code ec;
                auto canonical = fs::weakly_canonical(cand, ec);
                if (ec)
                    continue;
                if (isUsableCertsDir(canonical))
                    return canonical;
            }
        }

        // 5. exe-relative candidates — packaged-runtime layouts.
        //    macOS bundle: <exe>/../Resources/certificates (tried first on Darwin)
        //    Linux FHS:    <exe>/../share/librescrs/certificates
        if (auto exe = exePath()) {
            const auto exeDir = exe->parent_path();
            std::vector<fs::path> candidates;
#ifdef __APPLE__
            candidates.push_back(exeDir / ".." / "Resources" / "certificates");
#endif
            candidates.push_back(exeDir / ".." / "share" / "librescrs" / "certificates");
            for (const auto& cand : candidates) {
                std::error_code ec;
                auto canonical = fs::weakly_canonical(cand, ec);
                if (ec)
                    continue;
                if (isUsableCertsDir(canonical))
                    return canonical;
            }
        }

        return std::nullopt;
    } catch (...) {
        // Any filesystem_error / bad_alloc / path-construction throw degrades
        // to "no bundled certs" — caller's system-trust fallback still works.
        return std::nullopt;
    }
}

} // namespace LibreSCRS::Trust::detail
