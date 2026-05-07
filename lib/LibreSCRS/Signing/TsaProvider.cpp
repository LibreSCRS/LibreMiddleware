// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <LibreSCRS/Signing/TsaProvider.h>

#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

namespace LibreSCRS::Signing {

TsaProvider staticTsa(std::string url)
{
    return [u = std::move(url)](const TsaContext&) {
        TsaRequest req;
        req.url = u;
        return req;
    };
}

TsaProvider staticTsaChecked(std::string_view url)
{
    // Basic pre-flight validation: scheme + non-empty authority. Rigorous
    // URL validation is libcurl's job at transport time; this factory just
    // catches the obvious "missed the scheme" / "empty string" / "http://"
    // configuration mistakes before signing is attempted.
    if (url.empty())
        throw std::invalid_argument("staticTsaChecked: URL must not be empty");

    constexpr std::string_view kHttp = "http://";
    constexpr std::string_view kHttps = "https://";
    std::string_view authority;
    if (url.substr(0, kHttp.size()) == kHttp)
        authority = url.substr(kHttp.size());
    else if (url.substr(0, kHttps.size()) == kHttps)
        authority = url.substr(kHttps.size());
    else
        throw std::invalid_argument("staticTsaChecked: URL must begin with http:// or https://");

    // The authority is the host (with optional userinfo, port) — everything
    // up to the first '/', '?', '#'. Require it to be non-empty.
    auto authorityEnd = authority.find_first_of("/?#");
    std::string_view host = authority.substr(0, authorityEnd);
    if (host.empty())
        throw std::invalid_argument("staticTsaChecked: URL authority (host) must not be empty");

    return staticTsa(std::string{url});
}

} // namespace LibreSCRS::Signing
