// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware."
#endif

#pragma once

#include "TrustAnchorProvider.h"

#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace LibreSCRS::Trust::detail {

/// @brief Walks a directory tree at construction time, loads every .cer/.crt/.pem
///        as a DER trust anchor. Source label encodes the relative path.
class BundledCertsProvider : public TrustAnchorProvider
{
public:
    /// @brief Construct from a directory path.
    /// @note Walks the directory tree synchronously at construction.
    ///       Subsequent calls to @ref anchors return cached results.
    explicit BundledCertsProvider(std::string bundledCertDir);

    [[nodiscard]] std::vector<TrustAnchor> anchors() const override;

private:
    std::string bundledCertDir;
    std::vector<TrustAnchor> cached;
};

/// @brief Resolve the on-disk directory holding bundled root certificates at
///        runtime. Order (first usable candidate wins):
///        1. env @c LIBRESCRS_CERTIFICATES_DIR (dev/test override).
///        2. compile-time @c LIBREMIDDLEWARE_CERTIFICATES_DIR (source-tree path
///           for dev builds).
///        3. exe-relative: Linux @c \<exe\>/../share/librescrs/certificates,
///           macOS bundle @c \<exe\>/../Resources/certificates.
/// @return Path to the first directory that exists and contains at least one
///         file with a cert-like extension (@c .crt / @c .pem / @c .cer /
///         @c .der). Returns @c std::nullopt if no candidate qualifies — the
///         caller then falls back to the system trust store via the
///         @ref TrustConfig::includeSystemTrustStore toggle.
[[nodiscard]] std::optional<std::filesystem::path> resolveBundledCertsDir() noexcept;

} // namespace LibreSCRS::Trust::detail
