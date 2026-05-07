// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

/// @file
/// @brief Out-of-line implementation of @ref LibreSCRS::Trust::TrustConfig::Builder.
///
/// The aggregate @ref TrustConfig is plain data (header-only); the Builder is
/// out-of-line so the per-setter validation logic can be revised without an
/// ABI break.

#include <LibreSCRS/Trust/TrustConfig.h>

#include <algorithm>
#include <filesystem>
#include <stdexcept>
#include <string>
#include <utility>

namespace LibreSCRS::Trust {

namespace {

bool hasHttpScheme(std::string_view url) noexcept
{
    constexpr std::string_view http{"http://"};
    constexpr std::string_view https{"https://"};
    return url.starts_with(http) || url.starts_with(https);
}

} // namespace

TrustConfig::Builder::Builder() = default;
TrustConfig::Builder::~Builder() = default;
TrustConfig::Builder::Builder(Builder&&) noexcept = default;
TrustConfig::Builder& TrustConfig::Builder::operator=(Builder&&) noexcept = default;

TrustConfig::Builder& TrustConfig::Builder::addTrustedListSource(std::string url, bool isLotl, bool eager)
{
    if (url.empty()) {
        throw std::invalid_argument{"TrustConfig::Builder::addTrustedListSource: url is empty"};
    }
    if (!hasHttpScheme(url)) {
        throw std::invalid_argument{
            "TrustConfig::Builder::addTrustedListSource: url must begin with http:// or https://"};
    }
    const bool duplicate = std::any_of(cfg.trustedListSources.begin(), cfg.trustedListSources.end(),
                                       [&](const TrustedListSource& s) { return s.url == url; });
    if (duplicate) {
        throw std::invalid_argument{"TrustConfig::Builder::addTrustedListSource: url already added"};
    }
    cfg.trustedListSources.push_back(TrustedListSource{std::move(url), isLotl, eager});
    return *this;
}

TrustConfig::Builder& TrustConfig::Builder::setCacheDirectory(std::filesystem::path path)
{
    if (path.empty()) {
        cfg.cacheDirectory.reset();
        return *this;
    }
    // Validate the parent directory exists. A non-existent parent indicates a
    // typo or misconfigured deploy layout; the cache directory itself is
    // created lazily by the engine when it first writes a TL file.
    std::error_code ec;
    auto parent = path.parent_path();
    if (!parent.empty()) {
        if (!std::filesystem::exists(parent, ec) || ec) {
            throw std::invalid_argument{"TrustConfig::Builder::setCacheDirectory: parent directory does not exist"};
        }
    }
    cfg.cacheDirectory = std::move(path);
    return *this;
}

TrustConfig::Builder& TrustConfig::Builder::setIncludeSystemTrustStore(bool include) noexcept
{
    cfg.includeSystemTrustStore = include;
    return *this;
}

TrustConfig::Builder& TrustConfig::Builder::setTrustedListFile(std::filesystem::path path)
{
    std::error_code ec;
    if (!std::filesystem::is_regular_file(path, ec) || ec) {
        throw std::invalid_argument{"TrustConfig::Builder::setTrustedListFile: path is not a readable regular file"};
    }
    cfg.trustedListFile = std::move(path);
    return *this;
}

TrustConfig::Builder& TrustConfig::Builder::setTrustedListFileSigningCert(std::filesystem::path path)
{
    std::error_code ec;
    if (!std::filesystem::is_regular_file(path, ec) || ec) {
        throw std::invalid_argument{
            "TrustConfig::Builder::setTrustedListFileSigningCert: path is not a readable regular file"};
    }
    cfg.trustedListFileSigningCert = std::move(path);
    return *this;
}

TrustConfig TrustConfig::Builder::build() && noexcept
{
    return std::move(cfg);
}

} // namespace LibreSCRS::Trust
