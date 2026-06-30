// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "TrustedListProvider.h"

#include <utility>

namespace libresign {

namespace {

bool isTrustAnchorServiceType(std::string_view serviceType)
{
    // ETSI TS 119 612 — qualified CA service types feed both
    // CARD_VERIFICATION-ish and SIGNING use cases.
    return serviceType.find("Svctype/CA/QC") != std::string_view::npos ||
           serviceType.find("Svctype/TSA/QTST") != std::string_view::npos;
}

} // namespace

std::vector<LibreSCRS::Trust::TrustAnchor> extractAnchorsFromTrustedList(const TrustedListInfo& info,
                                                                         const std::string& sourceLabel)
{
    std::vector<LibreSCRS::Trust::TrustAnchor> out;
    out.reserve(info.services.size());
    for (const auto& service : info.services) {
        if (service.certDer.empty())
            continue;
        if (!isTrustAnchorServiceType(service.serviceType))
            continue;

        LibreSCRS::Trust::TrustAnchor a;
        a.certificateDer = service.certDer;
        a.sourceLabel = sourceLabel + " [" + service.serviceType + "]";
        out.push_back(std::move(a));
    }
    return out;
}

} // namespace libresign
