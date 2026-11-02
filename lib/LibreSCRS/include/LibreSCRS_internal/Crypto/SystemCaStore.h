// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

#include <openssl/err.h>
#include <openssl/x509_vfy.h>

#include <array>
#include <cstdlib>
#include <filesystem>
#include <string>
#include <system_error>

/// @file
/// @brief The one place that says where the operating system keeps the
///        certificate authorities it trusts.
///
/// The bundled OpenSSL cannot find them on its own: its compiled-in OPENSSLDIR
/// is a directory nothing installs (that is deliberate — it must never load a
/// configuration file from a path a user could write to), so
/// X509_STORE_set_default_paths() yields an empty store unless SSL_CERT_FILE or
/// SSL_CERT_DIR is set. The bundled curl bakes the build host's paths instead,
/// which an AppImage or a package built on another distribution does not share.
/// Chain validation, time-stamp verification and the https client all ask
/// here, so a process has one notion of "the system store", found on the host
/// it runs on.

namespace LibreSCRS::Internal::Crypto {

/// @brief A CA bundle file and a hashed CA directory; either may be empty.
struct SystemCaStore
{
    std::string file;
    std::string directory;
};

/// @brief The bundle files the Linux distributions and macOS ship, the most
///        common first: Debian, Ubuntu, Arch, Gentoo; Fedora and RHEL;
///        openSUSE; CentOS and RHEL 7; Alpine, the BSDs and macOS.
inline constexpr std::array<const char*, 5> kSystemCaFiles{
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/ca-bundle.pem",
    "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
    "/etc/ssl/cert.pem",
};

/// @brief Hashed certificate directories (c_rehash layout).
inline constexpr std::array<const char*, 1> kSystemCaDirectories{
    "/etc/ssl/certs",
};

/// @brief @c SSL_CERT_FILE and @c SSL_CERT_DIR when set — the overrides
///        OpenSSL itself honours, and what a package points at a CA bundle it
///        ships — else the first bundle file and directory that exist here.
[[nodiscard]] inline SystemCaStore findSystemCaStore()
{
    const auto fromEnv = [](const char* name) -> std::string {
        const char* value = std::getenv(name);
        return value != nullptr ? std::string(value) : std::string();
    };
    SystemCaStore out{fromEnv("SSL_CERT_FILE"), fromEnv("SSL_CERT_DIR")};
    std::error_code ec;
    if (out.file.empty()) {
        for (const char* candidate : kSystemCaFiles) {
            if (std::filesystem::is_regular_file(candidate, ec)) {
                out.file = candidate;
                break;
            }
        }
    }
    if (out.directory.empty()) {
        for (const char* candidate : kSystemCaDirectories) {
            if (std::filesystem::is_directory(candidate, ec)) {
                out.directory = candidate;
                break;
            }
        }
    }
    return out;
}

/// @brief Adds the system store to @p store. A location that cannot be read
///        adds nothing; its error is cleared so it does not stand in for the
///        reason a later verification fails.
inline void addSystemCaStore(X509_STORE* store)
{
    const auto ca = findSystemCaStore();
    if (!ca.file.empty())
        X509_STORE_load_file(store, ca.file.c_str());
    if (!ca.directory.empty())
        X509_STORE_load_path(store, ca.directory.c_str());
    ERR_clear_error();
}

} // namespace LibreSCRS::Internal::Crypto
