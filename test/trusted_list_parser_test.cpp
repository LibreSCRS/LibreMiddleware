// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <gtest/gtest.h>

#ifdef LIBRESIGN_HAS_NATIVE

#include "native/trusted_list_parser.h"

#include <cstdlib>

using namespace libresign;

// Minimal TL XML for testing (not a real TL, just structure)
static const char* minimalTlXml = R"(<?xml version="1.0" encoding="UTF-8"?>
<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#">
  <SchemeInformation>
    <SchemeTerritory>RS</SchemeTerritory>
    <SchemeName><Name xml:lang="en">Serbian Trusted List</Name></SchemeName>
    <ListIssueDateTime>2026-01-01T00:00:00Z</ListIssueDateTime>
    <NextUpdate><dateTime>2026-07-01T00:00:00Z</dateTime></NextUpdate>
  </SchemeInformation>
  <TrustServiceProviderList>
    <TrustServiceProvider>
      <TSPInformation>
        <TSPName><Name xml:lang="en">Test CA</Name></TSPName>
      </TSPInformation>
      <TSPServices>
        <TSPService>
          <ServiceInformation>
            <ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/CA/QC</ServiceTypeIdentifier>
            <ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted</ServiceStatus>
            <ServiceDigitalIdentity>
              <DigitalId>
                <X509Certificate>MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A</X509Certificate>
              </DigitalId>
            </ServiceDigitalIdentity>
          </ServiceInformation>
        </TSPService>
      </TSPServices>
    </TrustServiceProvider>
  </TrustServiceProviderList>
</TrustServiceStatusList>)";

// Minimal LOTL XML with pointers to other TLs (including signing certs)
static const char* minimalLotlXml = R"(<?xml version="1.0" encoding="UTF-8"?>
<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#">
  <SchemeInformation>
    <SchemeTerritory>EU</SchemeTerritory>
    <SchemeName><Name xml:lang="en">EU List of Trusted Lists</Name></SchemeName>
    <ListIssueDateTime>2026-01-01T00:00:00Z</ListIssueDateTime>
    <NextUpdate><dateTime>2026-07-01T00:00:00Z</dateTime></NextUpdate>
  </SchemeInformation>
  <PointersToOtherTSL>
    <OtherTSLPointer>
      <ServiceDigitalIdentity>
        <DigitalId>
          <X509Certificate>AQAB</X509Certificate>
        </DigitalId>
      </ServiceDigitalIdentity>
      <TSLLocation>https://example.com/tl1.xml</TSLLocation>
    </OtherTSLPointer>
    <OtherTSLPointer>
      <TSLLocation>https://example.com/tl2.xml</TSLLocation>
    </OtherTSLPointer>
  </PointersToOtherTSL>
</TrustServiceStatusList>)";

// TL with multiple providers and services
static const char* multiProviderTlXml = R"(<?xml version="1.0" encoding="UTF-8"?>
<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#">
  <SchemeInformation>
    <SchemeTerritory>DE</SchemeTerritory>
    <SchemeName><Name xml:lang="en">German Trusted List</Name></SchemeName>
    <ListIssueDateTime>2026-03-01T00:00:00Z</ListIssueDateTime>
    <NextUpdate><dateTime>2026-09-01T00:00:00Z</dateTime></NextUpdate>
  </SchemeInformation>
  <TrustServiceProviderList>
    <TrustServiceProvider>
      <TSPInformation>
        <TSPName><Name xml:lang="en">Provider Alpha</Name></TSPName>
      </TSPInformation>
      <TSPServices>
        <TSPService>
          <ServiceInformation>
            <ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/CA/QC</ServiceTypeIdentifier>
            <ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted</ServiceStatus>
            <ServiceDigitalIdentity>
              <DigitalId>
                <X509Certificate>AQAB</X509Certificate>
              </DigitalId>
            </ServiceDigitalIdentity>
          </ServiceInformation>
        </TSPService>
        <TSPService>
          <ServiceInformation>
            <ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/TSA/QTST</ServiceTypeIdentifier>
            <ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted</ServiceStatus>
            <ServiceDigitalIdentity>
              <DigitalId>
                <X509Certificate>AQAB</X509Certificate>
              </DigitalId>
            </ServiceDigitalIdentity>
          </ServiceInformation>
        </TSPService>
      </TSPServices>
    </TrustServiceProvider>
    <TrustServiceProvider>
      <TSPInformation>
        <TSPName><Name xml:lang="en">Provider Beta</Name></TSPName>
      </TSPInformation>
      <TSPServices>
        <TSPService>
          <ServiceInformation>
            <ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/CA/QC</ServiceTypeIdentifier>
            <ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/withdrawn</ServiceStatus>
            <ServiceDigitalIdentity>
              <DigitalId>
                <X509Certificate>AQAB</X509Certificate>
              </DigitalId>
            </ServiceDigitalIdentity>
          </ServiceInformation>
        </TSPService>
      </TSPServices>
    </TrustServiceProvider>
  </TrustServiceProviderList>
</TrustServiceStatusList>)";

TEST(TrustedListParser, ParseMinimalTL)
{
    std::string xml(minimalTlXml);
    auto info = TrustedListParser::parse(xml);

    ASSERT_EQ(info.schemeTerritory, "RS");
    ASSERT_FALSE(info.schemeName.empty());
    ASSERT_EQ(info.issueDate, "2026-01-01T00:00:00Z");
    ASSERT_EQ(info.nextUpdate, "2026-07-01T00:00:00Z");
    ASSERT_EQ(info.services.size(), 1u);
    ASSERT_EQ(info.services[0].providerName, "Test CA");
    ASSERT_TRUE(info.services[0].serviceType.find("CA/QC") != std::string::npos);
    ASSERT_EQ(info.services[0].status, "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted");
    ASSERT_FALSE(info.services[0].certDer.empty());
}

TEST(TrustedListParser, ParseEmptyReturnsEmpty)
{
    auto info = TrustedListParser::parse(std::string(""));
    ASSERT_TRUE(info.schemeTerritory.empty());
    ASSERT_TRUE(info.services.empty());
}

TEST(TrustedListParser, ParseInvalidXmlReturnsEmpty)
{
    auto info = TrustedListParser::parse(std::string("not xml at all"));
    ASSERT_TRUE(info.schemeTerritory.empty());
}

TEST(TrustedListParser, ParseVectorOverload)
{
    std::string xml(minimalTlXml);
    std::vector<uint8_t> data(xml.begin(), xml.end());
    auto info = TrustedListParser::parse(data);

    ASSERT_EQ(info.schemeTerritory, "RS");
    ASSERT_EQ(info.services.size(), 1u);
}

TEST(TrustedListParser, ParseLotlExtractsPointers)
{
    std::string xml(minimalLotlXml);
    auto info = TrustedListParser::parse(xml);

    ASSERT_EQ(info.schemeTerritory, "EU");
    ASSERT_EQ(info.pointersToOtherTSL.size(), 2u);
    ASSERT_EQ(info.pointersToOtherTSL[0].url, "https://example.com/tl1.xml");
    ASSERT_FALSE(info.pointersToOtherTSL[0].signingCertDer.empty()); // has cert
    ASSERT_EQ(info.pointersToOtherTSL[1].url, "https://example.com/tl2.xml");
    ASSERT_TRUE(info.pointersToOtherTSL[1].signingCertDer.empty()); // no cert
    ASSERT_TRUE(info.services.empty());
}

TEST(TrustedListParser, ParseMultipleProvidersAndServices)
{
    std::string xml(multiProviderTlXml);
    auto info = TrustedListParser::parse(xml);

    ASSERT_EQ(info.schemeTerritory, "DE");
    ASSERT_EQ(info.services.size(), 3u);

    // Provider Alpha has 2 services
    ASSERT_EQ(info.services[0].providerName, "Provider Alpha");
    ASSERT_TRUE(info.services[0].serviceType.find("CA/QC") != std::string::npos);

    ASSERT_EQ(info.services[1].providerName, "Provider Alpha");
    ASSERT_TRUE(info.services[1].serviceType.find("TSA/QTST") != std::string::npos);

    // Provider Beta has 1 service with withdrawn status
    ASSERT_EQ(info.services[2].providerName, "Provider Beta");
    ASSERT_TRUE(info.services[2].status.find("withdrawn") != std::string::npos);
}

TEST(TrustedListParser, ParseEmptyVectorReturnsEmpty)
{
    std::vector<uint8_t> empty;
    auto info = TrustedListParser::parse(empty);
    ASSERT_TRUE(info.schemeTerritory.empty());
    ASSERT_TRUE(info.services.empty());
}

// ---------------------------------------------------------------------------
// F6: isSafeTslUrl — IPv6 bracket SSRF guard (pass-6 review)
//
// Pre-fix: the host extractor stopped at the first ':' inside an IPv6
// bracket literal "[::1]" or "[fd00::1]:443/", returning "[" as the host
// and bypassing every private-range check. The 4.0 fix routes bracketed
// hosts through an IPv6-aware path that rejects loopback, link-local
// fe80::/10, ULA fc00::/7, and IPv4-mapped private ranges.
// ---------------------------------------------------------------------------

TEST(TrustedListParserSafeUrl, RejectsBracketedIPv6Loopback)
{
    EXPECT_FALSE(TrustedListParser::isSafeTslUrl("https://[::1]/path"));
    EXPECT_FALSE(TrustedListParser::isSafeTslUrl("https://[::1]:443/path"));
}

TEST(TrustedListParserSafeUrl, RejectsBracketedIPv6Unspecified)
{
    EXPECT_FALSE(TrustedListParser::isSafeTslUrl("https://[::]/path"));
}

TEST(TrustedListParserSafeUrl, RejectsBracketedIPv6LinkLocal)
{
    EXPECT_FALSE(TrustedListParser::isSafeTslUrl("https://[fe80::1]/path"));
    EXPECT_FALSE(TrustedListParser::isSafeTslUrl("https://[FE80::abcd]/path"));
    EXPECT_FALSE(TrustedListParser::isSafeTslUrl("https://[febf::1]:8443/x"));
}

TEST(TrustedListParserSafeUrl, RejectsBracketedIPv6UniqueLocal)
{
    EXPECT_FALSE(TrustedListParser::isSafeTslUrl("https://[fc00::1]/path"));
    EXPECT_FALSE(TrustedListParser::isSafeTslUrl("https://[fd00::1]:443/"));
    EXPECT_FALSE(TrustedListParser::isSafeTslUrl("https://[FD12:3456:789a::1]/"));
}

TEST(TrustedListParserSafeUrl, RejectsBracketedIPv4MappedPrivate)
{
    EXPECT_FALSE(TrustedListParser::isSafeTslUrl("https://[::ffff:127.0.0.1]/"));
    EXPECT_FALSE(TrustedListParser::isSafeTslUrl("https://[::ffff:10.0.0.1]/"));
    EXPECT_FALSE(TrustedListParser::isSafeTslUrl("https://[::ffff:192.168.1.1]/"));
    EXPECT_FALSE(TrustedListParser::isSafeTslUrl("https://[::ffff:169.254.169.254]/"));
}

TEST(TrustedListParserSafeUrl, AcceptsPublicIPv6Documentation)
{
    // 2001:db8::/32 is the documentation/example range. Not private; the
    // guard only rejects loopback / link-local / ULA / IPv4-mapped private,
    // and accepts everything else (DNS resolution + curl is the next layer).
    EXPECT_TRUE(TrustedListParser::isSafeTslUrl("https://[2001:db8::1]/path"));
    EXPECT_TRUE(TrustedListParser::isSafeTslUrl("https://[2001:db8::1]:8443/path"));
}

TEST(TrustedListParserSafeUrl, RejectsMalformedBracket)
{
    EXPECT_FALSE(TrustedListParser::isSafeTslUrl("https://[::1/path")); // unterminated
    EXPECT_FALSE(TrustedListParser::isSafeTslUrl("https://[]/path"));   // empty body
}

TEST(TrustedListParserSafeUrl, ExistingIPv4PrivateChecksStillReject)
{
    EXPECT_FALSE(TrustedListParser::isSafeTslUrl("https://127.0.0.1/path"));
    EXPECT_FALSE(TrustedListParser::isSafeTslUrl("https://10.0.0.1/path"));
    EXPECT_FALSE(TrustedListParser::isSafeTslUrl("https://192.168.1.1/x"));
    EXPECT_FALSE(TrustedListParser::isSafeTslUrl("https://169.254.169.254/latest/meta-data/"));
    EXPECT_FALSE(TrustedListParser::isSafeTslUrl("https://172.16.0.1/x"));
    EXPECT_FALSE(TrustedListParser::isSafeTslUrl("https://172.31.255.255/x"));
    EXPECT_FALSE(TrustedListParser::isSafeTslUrl("https://localhost/path"));
}

TEST(TrustedListParserSafeUrl, AcceptsPublicHostname)
{
    EXPECT_TRUE(TrustedListParser::isSafeTslUrl("https://www.mtt.gov.rs/download/CyrilicTSL.xml"));
    EXPECT_TRUE(TrustedListParser::isSafeTslUrl("https://example.org/tl.xml"));
}

TEST(TrustedListParserSafeUrl, RejectsNonHttps)
{
    EXPECT_FALSE(TrustedListParser::isSafeTslUrl("http://example.org/tl.xml"));
    EXPECT_FALSE(TrustedListParser::isSafeTslUrl("file:///etc/passwd"));
    EXPECT_FALSE(TrustedListParser::isSafeTslUrl("ftp://example.org/x"));
}

// Live test -- fetch real Serbian TL (network required, may be slow)
TEST(TrustedListParser, FetchSerbianTL)
{
    if (!std::getenv("LIBRESCRS_TEST_LIVE_TL"))
        GTEST_SKIP() << "Set LIBRESCRS_TEST_LIVE_TL=1 to run";

    TrustedListParser parser;
    auto info = parser.fetch("https://www.mtt.gov.rs/download/CyrilicTSL.xml", 30);

    ASSERT_EQ(info.schemeTerritory, "RS");
    ASSERT_FALSE(info.services.empty());
    // Serbian TL should have at least a few CAs
    ASSERT_GE(info.services.size(), 2u);
}

#else
TEST(TrustedListParser, DISABLED_SkippedNativeNotCompiled)
{
    GTEST_SKIP();
}
#endif
