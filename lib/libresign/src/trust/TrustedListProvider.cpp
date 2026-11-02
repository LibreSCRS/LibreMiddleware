// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "TrustedListProvider.h"

#include <cctype>
#include <string>
#include <string_view>
#include <utility>

namespace libresign {

namespace {

bool isTimestampServiceType(std::string_view serviceType)
{
    return serviceType.find("Svctype/TSA/QTST") != std::string_view::npos;
}

bool isTrustAnchorServiceType(std::string_view serviceType)
{
    // ETSI TS 119 612 — qualified CA service types feed both
    // CARD_VERIFICATION-ish and SIGNING use cases.
    return serviceType.find("Svctype/CA/QC") != std::string_view::npos || isTimestampServiceType(serviceType);
}

// A service whose current status says it is no longer trusted. ETSI TS
// 119 612 v2 names withdrawn and deprecatedatnationallevel; v1 lists, which
// national schemes still publish, name supervisionrevoked,
// accreditationrevoked, supervisionincessation and revoked. Schemes spell
// the URI under their own host (".../TrstSvc/TrustedList/Svcstatus/withdrawn"
// under a national domain), so the status is judged by its last segment. A
// deny-list, not an allow-list of "granted": a v1 list's positive statuses
// (accredited, undersupervision, ...) are trusted, and refusing every status
// this code has not heard of would refuse whole national lists.
bool isNegativeServiceStatus(std::string_view status)
{
    const auto slash = status.rfind('/');
    std::string last{slash == std::string_view::npos ? status : status.substr(slash + 1)};
    for (auto& c : last)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return last == "withdrawn" || last == "deprecatedatnationallevel" || last == "supervisionrevoked" ||
           last == "accreditationrevoked" || last == "supervisionincessation" || last == "revoked";
}

} // namespace

std::vector<LibreSCRS::Trust::TrustAnchor> extractAnchorsFromTrustedList(const TrustedListInfo& info)
{
    std::vector<LibreSCRS::Trust::TrustAnchor> out;
    out.reserve(info.services.size());
    for (const auto& service : info.services) {
        if (service.certDer.empty())
            continue;
        if (!isTrustAnchorServiceType(service.serviceType))
            continue;
        if (isNegativeServiceStatus(service.status))
            continue;

        LibreSCRS::Trust::TrustAnchor a;
        a.certificateDer = service.certDer;
        out.push_back(std::move(a));
    }
    return out;
}

std::vector<std::vector<uint8_t>> timestampAuthorityCertificates(const TrustedListInfo& info)
{
    std::vector<std::vector<uint8_t>> out;
    for (const auto& service : info.services) {
        if (!service.certDer.empty() && isTimestampServiceType(service.serviceType) &&
            !isNegativeServiceStatus(service.status))
            out.push_back(service.certDer);
    }
    return out;
}

} // namespace libresign
