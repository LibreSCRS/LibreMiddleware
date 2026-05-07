// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware."
#endif

#pragma once

#include "TrustAnchorProvider.h"

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

} // namespace LibreSCRS::Trust::detail
