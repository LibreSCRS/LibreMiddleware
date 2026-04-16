// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "pinned_tl_certs.h"

namespace libresign::pinned_certs {

namespace {
// Extract hostname from URL (between "://" and next "/" or end)
std::string_view extractHost(std::string_view url)
{
    auto schemeEnd = url.find("://");
    if (schemeEnd == std::string_view::npos)
        return {};
    auto hostStart = schemeEnd + 3;
    auto hostEnd = url.find('/', hostStart);
    if (hostEnd == std::string_view::npos)
        hostEnd = url.size();
    // Strip port if present
    auto colonPos = url.find(':', hostStart);
    if (colonPos != std::string_view::npos && colonPos < hostEnd)
        hostEnd = colonPos;
    return url.substr(hostStart, hostEnd - hostStart);
}

bool hostMatchesDomain(std::string_view host, std::string_view domain)
{
    if (host == domain)
        return true;
    // Check if host ends with ".domain"
    if (host.size() > domain.size() + 1 && host[host.size() - domain.size() - 1] == '.' &&
        host.substr(host.size() - domain.size()) == domain)
        return true;
    return false;
}
} // namespace

std::span<const uint8_t> pinnedCertForUrl(std::string_view url)
{
    auto host = extractHost(url);
    if (host.empty())
        return {};

    if (hostMatchesDomain(host, "ec.europa.eu"))
        return kEuLotlSigningCert;
    if (hostMatchesDomain(host, "mit.gov.rs"))
        return kSerbianTlSigningCert;
    return {};
}

} // namespace libresign::pinned_certs
