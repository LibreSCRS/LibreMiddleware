// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "native/trusted_list_parser.h"
#include "http_client.h"
#include "native_utils.h"

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>

#include <algorithm>
#include <climits>
#include <memory>

#include "xml_raii.h"

namespace libresign {

namespace {

using ::libresign::XmlDocPtr;
using ::libresign::XPathCtxPtr;
using ::libresign::XPathObjPtr;
using native_utils::base64Decode;

const auto* TSL_NS_X = BAD_CAST "http://uri.etsi.org/02231/v2#";
const auto* TSL_PREFIX = BAD_CAST "tsl";

// Extract text content from an XPath result (first match)
std::string xpathText(xmlXPathContextPtr ctx, const char* expr)
{
    XPathObjPtr obj(xmlXPathEvalExpression(reinterpret_cast<const xmlChar*>(expr), ctx));
    if (!obj || !obj->nodesetval || obj->nodesetval->nodeNr == 0) {
        return {};
    }

    xmlNodePtr node = obj->nodesetval->nodeTab[0];
    xmlChar* content = xmlNodeGetContent(node);
    if (!content) {
        return {};
    }

    std::string result(reinterpret_cast<const char*>(content));
    xmlFree(content);
    return result;
}

// Extract text content from an XPath relative to a context node
std::string xpathTextRelative(xmlXPathContextPtr ctx, xmlNodePtr contextNode, const char* expr)
{
    xmlNodePtr oldNode = ctx->node;
    ctx->node = contextNode;

    XPathObjPtr obj(xmlXPathEvalExpression(reinterpret_cast<const xmlChar*>(expr), ctx));

    ctx->node = oldNode;

    if (!obj || !obj->nodesetval || obj->nodesetval->nodeNr == 0) {
        return {};
    }

    xmlNodePtr node = obj->nodesetval->nodeTab[0];
    xmlChar* content = xmlNodeGetContent(node);
    if (!content) {
        return {};
    }

    std::string result(reinterpret_cast<const char*>(content));
    xmlFree(content);
    return result;
}

// Get all nodes matching an XPath relative to a context node
XPathObjPtr xpathNodesRelative(xmlXPathContextPtr ctx, xmlNodePtr contextNode, const char* expr)
{
    xmlNodePtr oldNode = ctx->node;
    ctx->node = contextNode;

    XPathObjPtr obj(xmlXPathEvalExpression(reinterpret_cast<const xmlChar*>(expr), ctx));

    ctx->node = oldNode;
    return obj;
}

TrustedListInfo parseDoc(xmlDocPtr doc)
{
    TrustedListInfo info;

    if (!doc) {
        return info;
    }

    XPathCtxPtr ctx(xmlXPathNewContext(doc));
    if (!ctx) {
        return info;
    }

    // Register the TSL namespace
    if (xmlXPathRegisterNs(ctx.get(), TSL_PREFIX, TSL_NS_X) != 0) {
        return info;
    }

    // Extract scheme information
    info.schemeTerritory = xpathText(ctx.get(), "//tsl:SchemeInformation/tsl:SchemeTerritory");
    info.schemeName = xpathText(ctx.get(), "//tsl:SchemeInformation/tsl:SchemeName/tsl:Name");
    info.issueDate = xpathText(ctx.get(), "//tsl:SchemeInformation/tsl:ListIssueDateTime");
    info.nextUpdate = xpathText(ctx.get(), "//tsl:SchemeInformation/tsl:NextUpdate/tsl:dateTime");

    // Extract pointers to other TSLs (LOTL), including per-pointer signing certs
    {
        XPathObjPtr pointerObj(xmlXPathEvalExpression(
            reinterpret_cast<const xmlChar*>("//tsl:PointersToOtherTSL/tsl:OtherTSLPointer"), ctx.get()));

        if (pointerObj && pointerObj->nodesetval) {
            for (int i = 0; i < pointerObj->nodesetval->nodeNr; ++i) {
                xmlNodePtr pointerNode = pointerObj->nodesetval->nodeTab[i];

                std::string url = xpathTextRelative(ctx.get(), pointerNode, "tsl:TSLLocation");
                if (url.empty())
                    continue;

                TslPointer pointer;
                pointer.url = std::move(url);

                std::string certB64 = xpathTextRelative(ctx.get(), pointerNode,
                                                        "tsl:ServiceDigitalIdentity/tsl:DigitalId/tsl:X509Certificate");
                if (!certB64.empty()) {
                    pointer.signingCertDer = base64Decode(certB64);
                }

                info.pointersToOtherTSL.push_back(std::move(pointer));
            }
        }
    }

    // Extract trust service providers
    XPathObjPtr providerObj(xmlXPathEvalExpression(
        reinterpret_cast<const xmlChar*>("//tsl:TrustServiceProviderList/tsl:TrustServiceProvider"), ctx.get()));

    if (!providerObj || !providerObj->nodesetval) {
        return info;
    }

    for (int p = 0; p < providerObj->nodesetval->nodeNr; ++p) {
        xmlNodePtr providerNode = providerObj->nodesetval->nodeTab[p];

        std::string providerName =
            xpathTextRelative(ctx.get(), providerNode, "tsl:TSPInformation/tsl:TSPName/tsl:Name");

        // Get all services for this provider
        XPathObjPtr serviceObj = xpathNodesRelative(ctx.get(), providerNode, "tsl:TSPServices/tsl:TSPService");

        if (!serviceObj || !serviceObj->nodesetval) {
            continue;
        }

        for (int s = 0; s < serviceObj->nodesetval->nodeNr; ++s) {
            xmlNodePtr serviceNode = serviceObj->nodesetval->nodeTab[s];

            TrustedServiceEntry entry;
            entry.providerName = providerName;

            entry.serviceName =
                xpathTextRelative(ctx.get(), serviceNode, "tsl:ServiceInformation/tsl:ServiceName/tsl:Name");

            entry.serviceType =
                xpathTextRelative(ctx.get(), serviceNode, "tsl:ServiceInformation/tsl:ServiceTypeIdentifier");

            entry.status = xpathTextRelative(ctx.get(), serviceNode, "tsl:ServiceInformation/tsl:ServiceStatus");

            std::string certB64 = xpathTextRelative(
                ctx.get(), serviceNode,
                "tsl:ServiceInformation/tsl:ServiceDigitalIdentity/tsl:DigitalId/tsl:X509Certificate");

            if (!certB64.empty()) {
                entry.certDer = base64Decode(certB64);
            }

            info.services.push_back(std::move(entry));
        }
    }

    return info;
}

} // anonymous namespace

TrustedListInfo TrustedListParser::parse(const std::vector<uint8_t>& xmlData)
{
    native_utils::ensureXmlInitialized();
    if (xmlData.empty()) {
        return {};
    }

    // XXE / billion-laughs / external DTD protection: disable network access
    // and external entity resolution. We only need to walk the document, not
    // expand entities.
    // XML_PARSE_NONET: forbid network access (no external DTDs over network)
    // XML_PARSE_NOCDATA: merge CDATA into text nodes
    // We deliberately do NOT set XML_PARSE_NOENT or XML_PARSE_DTDLOAD —
    // entities are kept as references (not expanded) and external DTDs are
    // not loaded, which mitigates XXE and billion-laughs attacks.
    constexpr int kSafeXmlOptions = XML_PARSE_NONET | XML_PARSE_NOCDATA;
    if (xmlData.size() > static_cast<size_t>(INT_MAX)) {
        return {};
    }
    XmlDocPtr doc(xmlReadMemory(reinterpret_cast<const char*>(xmlData.data()), static_cast<int>(xmlData.size()),
                                nullptr, nullptr, kSafeXmlOptions));
    return parseDoc(doc.get());
}

TrustedListInfo TrustedListParser::parse(const std::string& xmlString)
{
    if (xmlString.empty()) {
        return {};
    }

    // XML_PARSE_NONET: forbid network access (no external DTDs over network)
    // XML_PARSE_NOCDATA: merge CDATA into text nodes
    // We deliberately do NOT set XML_PARSE_NOENT or XML_PARSE_DTDLOAD —
    // entities are kept as references (not expanded) and external DTDs are
    // not loaded, which mitigates XXE and billion-laughs attacks.
    constexpr int kSafeXmlOptions = XML_PARSE_NONET | XML_PARSE_NOCDATA;
    if (xmlString.size() > static_cast<size_t>(INT_MAX)) {
        return {};
    }
    XmlDocPtr doc(
        xmlReadMemory(xmlString.data(), static_cast<int>(xmlString.size()), nullptr, nullptr, kSafeXmlOptions));
    return parseDoc(doc.get());
}

std::vector<uint8_t> TrustedListParser::fetchRaw(const std::string& url, int timeoutSeconds)
{
    auto result = fetchRawConditional(url, {}, {}, timeoutSeconds);
    return std::move(result.data);
}

TrustedListParser::FetchResult TrustedListParser::fetchRawConditional(const std::string& url, const std::string& etag,
                                                                      const std::string& lastModified,
                                                                      int timeoutSeconds)
{
    HttpClient client;
    FetchResult result;

    std::vector<std::string> headers;
    if (!etag.empty())
        headers.push_back("If-None-Match: " + etag);
    if (!lastModified.empty())
        headers.push_back("If-Modified-Since: " + lastModified);

    auto response =
        headers.empty() ? client.get(url, timeoutSeconds) : client.getWithHeaders(url, headers, timeoutSeconds);

    if (response.statusCode == 304) {
        result.notModified = true;
        return result;
    }

    if (response.statusCode != 200 || response.body.empty())
        return result;

    result.data = std::vector<uint8_t>(response.body.begin(), response.body.end());

    // Extract response headers for caching
    if (auto it = response.headers.find("etag"); it != response.headers.end())
        result.etag = it->second;
    if (auto it = response.headers.find("last-modified"); it != response.headers.end())
        result.lastModified = it->second;

    return result;
}

TrustedListInfo TrustedListParser::fetch(const std::string& url, int timeoutSeconds)
{
    HttpClient client;
    auto response = client.get(url, timeoutSeconds);

    if (response.statusCode != 200 || response.body.empty()) {
        return {};
    }

    return parse(response.body);
}

// LOTL pointers come from signed XML but are still attacker-controllable if
// the signer is compromised or trust is misconfigured — treat them as
// untrusted input. Reject non-https, private/loopback IPs, and cap the
// pointer count (EU LOTL typically lists ~30 member states; 64 is plenty).
bool TrustedListParser::isSafeTslUrl(const std::string& urlStr)
{
    constexpr std::string_view kHttpsPrefix = "https://";
    constexpr size_t kMaxHostLength = 253; // per RFC 1035 + safety margin
    if (urlStr.size() < kHttpsPrefix.size() + 1)
        return false;
    if (urlStr.size() > 2048) // sanity cap on full URL length
        return false;
    if (urlStr.compare(0, kHttpsPrefix.size(), kHttpsPrefix) != 0)
        return false;

    size_t hostStart = kHttpsPrefix.size();

    // F6: IPv6-literal hosts are bracketed (e.g. "https://[::1]/..."). The
    // pre-fix host extractor used find_first_of("/:?#", ...) which stopped
    // at the first ':' inside the brackets — yielding "[" as the host and
    // bypassing every private-range check. Detect bracket form first and
    // apply IPv6-specific rejection rules to the body inside the brackets.
    if (urlStr[hostStart] == '[') {
        size_t closeBracket = urlStr.find(']', hostStart + 1);
        if (closeBracket == std::string::npos)
            return false; // malformed — unterminated bracket

        std::string ipv6Body = urlStr.substr(hostStart + 1, closeBracket - hostStart - 1);
        if (ipv6Body.empty() || ipv6Body.size() > 45) // INET6_ADDRSTRLEN ~= 46
            return false;

        // Lowercase copy for case-insensitive prefix matches.
        std::string lower = ipv6Body;
        for (auto& c : lower) {
            if (c >= 'A' && c <= 'Z')
                c = static_cast<char>(c - 'A' + 'a');
        }

        auto bodyStartsWith = [&](std::string_view pfx) {
            return lower.size() >= pfx.size() && lower.compare(0, pfx.size(), pfx) == 0;
        };

        // Loopback (::1) and unspecified (::) addresses.
        if (lower == "::1" || lower == "::")
            return false;

        // Link-local fe80::/10 — covers fe80::, fe81::..fe8f::, fe90::..feaf::,
        // feb0::..febf::. The /10 range is fe80..febf in the leading bytes.
        if (bodyStartsWith("fe8") || bodyStartsWith("fe9") || bodyStartsWith("fea") || bodyStartsWith("feb"))
            return false;

        // Unique-Local Address (ULA) fc00::/7 — fc00..fdff in the leading byte.
        if (bodyStartsWith("fc") || bodyStartsWith("fd"))
            return false;

        // IPv4-mapped IPv6 (::ffff:a.b.c.d) — apply IPv4 private-range checks
        // against the embedded IPv4 portion. Both lower-cased "::ffff:" and
        // "0:0:0:0:0:ffff:" are common forms; only the canonical form is
        // pattern-matched here — anything more obfuscated is rejected.
        if (bodyStartsWith("::ffff:")) {
            std::string ipv4 = ipv6Body.substr(7); // after "::ffff:"
            // Reject obvious private ranges.
            auto v4StartsWith = [&](std::string_view pfx) {
                return ipv4.size() >= pfx.size() && ipv4.compare(0, pfx.size(), pfx) == 0;
            };
            if (v4StartsWith("127.") || v4StartsWith("10.") || v4StartsWith("169.254.") || v4StartsWith("192.168.") ||
                v4StartsWith("0.") || ipv4 == "0.0.0.0")
                return false;
            if (v4StartsWith("172.")) {
                size_t dot = ipv4.find('.', 4);
                if (dot != std::string::npos) {
                    try {
                        int second = std::stoi(ipv4.substr(4, dot - 4));
                        if (second >= 16 && second <= 31)
                            return false;
                    } catch (...) {
                        return false;
                    }
                }
            }
        }

        // Past the bracket checks — the IPv6 body is allowed (e.g. a public
        // 2001::/16 documentation/global address). Anything after ']' (port,
        // path, query, fragment) is fine; we don't need to parse it for this
        // SSRF guard.
        return true;
    }

    // Non-bracketed: existing IPv4/hostname extraction logic.
    size_t hostEnd = urlStr.find_first_of("/:?#", hostStart);
    if (hostEnd == std::string::npos)
        hostEnd = urlStr.size();
    std::string host = urlStr.substr(hostStart, hostEnd - hostStart);
    if (host.empty() || host.size() > kMaxHostLength)
        return false;

    // Reject obvious private/loopback literals. DNS names that resolve to
    // private addresses are not caught here — curl's CURLOPT_PROTOCOLS +
    // eventual DNS resolution are the last line of defense. This check is
    // defense-in-depth against literal-IP SSRF vectors (e.g.
    // https://169.254.169.254/...).
    auto startsWith = [&](std::string_view pfx) {
        return host.size() >= pfx.size() && host.compare(0, pfx.size(), pfx) == 0;
    };
    if (host == "localhost" || startsWith("127.") || startsWith("10.") || startsWith("169.254.") ||
        startsWith("192.168.") || startsWith("0.") || host == "::1")
        return false;
    // 172.16.0.0/12 — private range
    if (startsWith("172.")) {
        size_t dot = host.find('.', 4);
        if (dot != std::string::npos) {
            try {
                int second = std::stoi(host.substr(4, dot - 4));
                if (second >= 16 && second <= 31)
                    return false;
            } catch (...) {
                // malformed host, reject
                return false;
            }
        }
    }
    return true;
}

namespace {
constexpr size_t kMaxTslPointers = 64;
} // namespace

std::vector<TrustedServiceEntry> TrustedListParser::fetchLotl(const std::string& lotlUrl, int timeoutSeconds)
{
    auto lotlInfo = fetch(lotlUrl, timeoutSeconds);
    std::vector<TrustedServiceEntry> allEntries;

    // Include any services directly in the LOTL
    allEntries.insert(allEntries.end(), std::make_move_iterator(lotlInfo.services.begin()),
                      std::make_move_iterator(lotlInfo.services.end()));

    // Fetch each member state TL — but validate URL scheme/host first to
    // mitigate SSRF via a compromised or malformed LOTL that points at
    // cloud-metadata IPs, internal services, file://, etc.
    size_t fetched = 0;
    for (const auto& pointer : lotlInfo.pointersToOtherTSL) {
        if (fetched >= kMaxTslPointers)
            break;
        if (!isSafeTslUrl(pointer.url))
            continue;
        auto tlInfo = fetch(pointer.url, timeoutSeconds);
        allEntries.insert(allEntries.end(), std::make_move_iterator(tlInfo.services.begin()),
                          std::make_move_iterator(tlInfo.services.end()));
        ++fetched;
    }

    return allEntries;
}

} // namespace libresign
