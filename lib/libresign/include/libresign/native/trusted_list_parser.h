// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace libresign {

struct TrustedServiceEntry
{
    std::string providerName;
    std::string serviceName;
    std::string serviceType;      // e.g., "http://uri.etsi.org/TrstSvc/Svctype/CA/QC"
    std::string status;           // e.g., "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted"
    std::vector<uint8_t> certDer; // DER-encoded X.509 certificate
};

struct TrustedListInfo
{
    std::string schemeTerritory; // e.g., "RS", "EE", "DE"
    std::string schemeName;
    std::string issueDate;
    std::string nextUpdate;
    std::vector<TrustedServiceEntry> services;
    std::vector<std::string> pointersToOtherTSL; // LOTL: URLs of member state TLs
};

// WARNING — Trust path is currently unauthenticated.
//
// This parser extracts trust services from a TL/LOTL XML document but does
// NOT verify the XMLDSig ds:Signature on the document itself. Per eIDAS
// (Regulation (EU) 910/2014) and ETSI EN 319 015, every TL/LOTL is signed
// by its scheme operator and consumers MUST verify that signature before
// trusting any extracted certificate as a CA.
//
// Until that verification is implemented (TODO: integrate xmlsec1
// signature-verify path with the LOTL trust anchor pinned at compile time),
// callers MUST NOT use the output of this parser as authoritative trust
// material in production. The class is currently exposed only for
// development and tests; the signing pipeline does not depend on it.
class TrustedListParser
{
public:
    // Parse a TL or LOTL XML document.
    // Returns empty TrustedListInfo on parse failure.
    //
    // SECURITY: see warning above. The XML signature on the document is
    // not verified — output is structurally extracted but not authenticated.
    static TrustedListInfo parse(const std::vector<uint8_t>& xmlData);
    static TrustedListInfo parse(const std::string& xmlString);

    // Fetch and parse a TL from URL. SECURITY: see warning above.
    TrustedListInfo fetch(const std::string& url, int timeoutSeconds = 30);

    // Fetch LOTL, then fetch each member state TL.
    // Returns all entries from all member state TLs.
    // SECURITY: see warning above.
    std::vector<TrustedServiceEntry> fetchLotl(const std::string& lotlUrl, int timeoutSeconds = 30);
};

} // namespace libresign
