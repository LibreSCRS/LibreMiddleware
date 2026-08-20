// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

#include <openssl/types.h>

#include <cstdint>
#include <memory>
#include <span>
#include <string>

namespace LibreSCRS::RsEId::Core {

/// @brief Trust anchors a card Security Object is validated against.
class TrustStore
{
public:
    TrustStore();
    ~TrustStore();

    TrustStore(const TrustStore&) = delete;
    TrustStore& operator=(const TrustStore&) = delete;

    /// @brief Add one DER-encoded anchor, for callers holding raw bytes.
    void addCertificate(std::span<const std::uint8_t> derCert);

    /// @brief Add every .cer/.crt/.pem anchor in @p folderPath. Missing folder is not an error.
    void loadFromFolder(const std::string& folderPath);

    [[nodiscard]] int certificateCount() const noexcept;

    /// @brief Underlying store. Internal seam for the verifier in this library.
    [[nodiscard]] X509_STORE* native() const noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> impl;
};

} // namespace LibreSCRS::RsEId::Core
