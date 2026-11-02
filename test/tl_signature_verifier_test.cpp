// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <gtest/gtest.h>

#include "fetch_and_verify_tl.h"
#include "mock_trusted_list_server.h"
#include "pinned_tl_certs.h"
#include "tl_cache.h"
#include "tl_signature_verifier.h"
#include "trusted_list_parser.h"
#include "trust/TrustedListProvider.h"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>
#include <system_error>
#include <unistd.h>
#include <vector>

using namespace libresign;

namespace {

// Read a file into a byte vector (returns empty on failure).
std::vector<uint8_t> readFile(const std::string& path)
{
    std::ifstream f(path, std::ios::binary);
    if (!f)
        return {};
    return {std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>()};
}

// Download Serbian TL if not cached. Returns empty if unavailable or not XML.
std::vector<uint8_t> getSerbianTl()
{
    const std::string cachePath = "/tmp/tsl-rs.xml";
    auto data = readFile(cachePath);
    // Check for XML: starts with "<?xml" or BOM + "<?xml"
    auto startsWithXml = [](const std::vector<uint8_t>& d) {
        if (d.size() < 5)
            return false;
        size_t off = 0;
        if (d.size() >= 3 && d[0] == 0xEF && d[1] == 0xBB && d[2] == 0xBF)
            off = 3; // skip UTF-8 BOM
        return off + 1 < d.size() && d[off] == '<' && d[off + 1] == '?';
    };
    if (!data.empty() && startsWithXml(data))
        return data;

    // Try downloading
    std::remove(cachePath.c_str());
    int rc = std::system("curl -sS -o /tmp/tsl-rs.xml "
                         "'https://www.mit.gov.rs/TrustedList/TSL-RS.xml' 2>/dev/null");
    if (rc != 0)
        return {};
    data = readFile(cachePath);
    if (!startsWithXml(data))
        return {};
    return data;
}

} // namespace

class TlSignatureVerifierTest : public ::testing::Test
{
protected:
    TlSignatureVerifier verifier;
};

TEST_F(TlSignatureVerifierTest, VerifyRealSerbianTl)
{
    auto tlXml = getSerbianTl();
    if (tlXml.empty())
        GTEST_SKIP() << "Serbian TL not available (no network or cache)";

    auto certSpan = pinned_certs::kSerbianTlSigningCert;
    bool ok = verifier.verify(tlXml, certSpan);
    EXPECT_TRUE(ok) << "Verification failed: " << verifier.lastError();
}

TEST_F(TlSignatureVerifierTest, TamperedContentFails)
{
    auto tlXml = getSerbianTl();
    if (tlXml.empty())
        GTEST_SKIP() << "Serbian TL not available";

    // Tamper: flip a byte in the middle of the document
    auto tampered = tlXml;
    size_t mid = tampered.size() / 2;
    tampered[mid] ^= 0xFF;

    auto certSpan = pinned_certs::kSerbianTlSigningCert;
    bool ok = verifier.verify(tampered, certSpan);
    EXPECT_FALSE(ok) << "Tampered TL should not verify";
}

TEST_F(TlSignatureVerifierTest, WrongCertFails)
{
    auto tlXml = getSerbianTl();
    if (tlXml.empty())
        GTEST_SKIP() << "Serbian TL not available";

    // Use the EU cert against the Serbian TL — should fail
    auto euCert = pinned_certs::kEuLotlSigningCert;
    bool ok = verifier.verify(tlXml, euCert);
    EXPECT_FALSE(ok) << "Wrong cert should not verify";
}

TEST_F(TlSignatureVerifierTest, EmptyInputFails)
{
    std::vector<uint8_t> empty;
    auto certSpan = pinned_certs::kSerbianTlSigningCert;

    EXPECT_FALSE(verifier.verify(empty, certSpan));
    EXPECT_FALSE(verifier.lastError().empty());
}

TEST_F(TlSignatureVerifierTest, EmptyCertFails)
{
    auto tlXml = getSerbianTl();
    if (tlXml.empty())
        GTEST_SKIP() << "Serbian TL not available";

    std::span<const uint8_t> emptyCert;
    EXPECT_FALSE(verifier.verify(tlXml, emptyCert));
}

TEST_F(TlSignatureVerifierTest, InvalidXmlFails)
{
    std::vector<uint8_t> garbage = {0x3C, 0x3F, 0x78, 0x6D, 0x6C}; // "<?xml" truncated
    auto certSpan = pinned_certs::kSerbianTlSigningCert;

    EXPECT_FALSE(verifier.verify(garbage, certSpan));
}

// Build a minimal-but-valid xmldsig SignedInfo carrying the supplied
// algorithm URIs (signature method + digest method) and a single
// reference. Returns the serialised XML byte buffer.
namespace {
std::vector<uint8_t> buildXmlWithAlgo(const std::string& sigAlgoUri, const std::string& digestAlgoUri,
                                      const std::string& referenceUri)
{
    std::string xml =
        R"(<?xml version="1.0" encoding="UTF-8"?>
<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#" Id="root">
  <SchemeInformation/>
  <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
    <ds:SignedInfo>
      <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
      <ds:SignatureMethod Algorithm=")" +
        sigAlgoUri + R"("/>
      <ds:Reference URI=")" +
        referenceUri + R"(">
        <ds:DigestMethod Algorithm=")" +
        digestAlgoUri + R"("/>
        <ds:DigestValue>aGVsbG8=</ds:DigestValue>
      </ds:Reference>
    </ds:SignedInfo>
    <ds:SignatureValue>YWFh</ds:SignatureValue>
  </ds:Signature>
</TrustServiceStatusList>
)";
    return {xml.begin(), xml.end()};
}
const std::string kTrustFixtures = std::string(LIBREMIDDLEWARE_SOURCE_DIR) + "/test/fixtures/trust/";

// The test signer's certificate, DER.
std::vector<uint8_t> testSignerCertDer()
{
    std::FILE* f = std::fopen((kTrustFixtures + "test-tl-signing-cert.pem").c_str(), "r");
    if (f == nullptr)
        return {};
    X509* x = PEM_read_X509(f, nullptr, nullptr, nullptr);
    std::fclose(f);
    if (x == nullptr)
        return {};
    const int len = i2d_X509(x, nullptr);
    std::vector<uint8_t> der(len > 0 ? static_cast<std::size_t>(len) : 0);
    unsigned char* p = der.data();
    if (len > 0)
        i2d_X509(x, &p);
    X509_free(x);
    return der;
}

// A self-signed EC certificate that signed nothing here.
std::vector<uint8_t> unrelatedCertDer()
{
    EVP_PKEY* key = EVP_EC_gen("P-256");
    X509* x = X509_new();
    X509_set_version(x, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(x), 7);
    X509_gmtime_adj(X509_getm_notBefore(x), -3600);
    X509_gmtime_adj(X509_getm_notAfter(x), 3600);
    X509_set_pubkey(x, key);
    X509_NAME_add_entry_by_txt(X509_get_subject_name(x), "CN", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char*>("Rotated Out"), -1, -1, 0);
    X509_set_issuer_name(x, X509_get_subject_name(x));
    X509_sign(x, key, EVP_sha256());
    const int len = i2d_X509(x, nullptr);
    std::vector<uint8_t> der(len > 0 ? static_cast<std::size_t>(len) : 0);
    unsigned char* p = der.data();
    if (len > 0)
        i2d_X509(x, &p);
    X509_free(x);
    EVP_PKEY_free(key);
    return der;
}

TrustedListEntry localEntry(std::vector<std::vector<uint8_t>> namedCerts)
{
    TrustedListEntry e;
    e.url = "file://" + kTrustFixtures + "synthetic-tl.xml";
    e.localFileOnly = true;
    e.signingCertsDer = std::move(namedCerts);
    return e;
}

std::string insertBeforeSignatureEnd(std::vector<uint8_t> xml, const std::string& content)
{
    std::string s(xml.begin(), xml.end());
    const auto at = s.rfind("</ds:Signature>");
    if (at != std::string::npos)
        s.insert(at, content);
    return s;
}

} // namespace

// ds:Object content inside the signature is outside what an enveloped
// signature over the document covers: the list still verifies, and the
// parser must not read a provider or a pointer planted there.
TEST_F(TlSignatureVerifierTest, ProvidersPlantedInsideTheSignatureAreNotRead)
{
    const auto cert = testSignerCertDer();
    ASSERT_FALSE(cert.empty());
    const std::string planted = R"(<ds:Object><TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#">
  <SchemeInformation><PointersToOtherTSL><OtherTSLPointer>
    <TSLLocation>https://planted.example/tl.xml</TSLLocation>
  </OtherTSLPointer></PointersToOtherTSL></SchemeInformation>
  <TrustServiceProviderList><TrustServiceProvider>
    <TSPInformation><TSPName><Name xml:lang="en">Planted TSP</Name></TSPName></TSPInformation>
    <TSPServices><TSPService><ServiceInformation>
      <ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/CA/QC</ServiceTypeIdentifier>
      <ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted</ServiceStatus>
      <ServiceDigitalIdentity><DigitalId><X509Certificate>AQAB</X509Certificate></DigitalId></ServiceDigitalIdentity>
    </ServiceInformation></TSPService></TSPServices>
  </TrustServiceProvider></TrustServiceProviderList>
</TrustServiceStatusList></ds:Object>
)";
    const auto tampered = insertBeforeSignatureEnd(readFile(kTrustFixtures + "synthetic-tl.xml"), planted);
    const std::vector<uint8_t> bytes(tampered.begin(), tampered.end());

    ASSERT_TRUE(verifier.verify(bytes, cert)) << verifier.lastError();
    const auto info = TrustedListParser::parse(bytes);
    ASSERT_EQ(info.services.size(), 1U);
    EXPECT_EQ(info.services[0].providerName, "LibreSCRS Test TSP");
    EXPECT_TRUE(info.pointersToOtherTSL.empty());
}

// The first reference detaches the signature for its enveloped-signature
// transform; the second digests the same element without it. Both digest
// the list as it was signed only if the signature goes back where it was.
// The third names the list by its Id, which covers it as URI="" does.
TEST_F(TlSignatureVerifierTest, SignatureReturnsToItsPlaceBetweenReferences)
{
    const auto cert = testSignerCertDer();
    ASSERT_FALSE(cert.empty());
    const auto xml = readFile(kTrustFixtures + "two-reference-tl.xml");
    ASSERT_FALSE(xml.empty());

    EXPECT_TRUE(verifier.verify(xml, cert)) << verifier.lastError();
}

// A signature over the scheme information alone leaves every provider and
// service unsigned: such a list is refused, however valid the signature is,
// and so is one whose providers were changed after signing.
TEST_F(TlSignatureVerifierTest, SignatureThatDoesNotCoverTheWholeListIsRefused)
{
    const auto cert = testSignerCertDer();
    ASSERT_FALSE(cert.empty());
    const auto xml = readFile(kTrustFixtures + "scheme-only-tl.xml");
    ASSERT_FALSE(xml.empty());

    EXPECT_FALSE(verifier.verify(xml, cert));
    EXPECT_NE(verifier.lastError().find("whole"), std::string::npos) << verifier.lastError();

    std::string changed(xml.begin(), xml.end());
    const auto at = changed.find("LibreSCRS Test TSP");
    ASSERT_NE(at, std::string::npos);
    changed.replace(at, std::string("LibreSCRS Test TSP").size(), "Planted TSP");
    EXPECT_FALSE(verifier.verify(std::vector<uint8_t>(changed.begin(), changed.end()), cert));
}

// A List of Trusted Lists names one certificate per signing key of the list
// it points to, the retired ones included: each is tried in order.
TEST(FetchAndVerifyTrustedList, EveryCertificateTheLotlNamesIsTried)
{
    const auto signer = testSignerCertDer();
    ASSERT_FALSE(signer.empty());

    auto result = fetchAndVerifyTrustedList(localEntry({unrelatedCertDer(), signer}), FetchOptions{});

    ASSERT_TRUE(result) << result.error;
    ASSERT_EQ(result.info.services.size(), 1U);
}

TEST(FetchAndVerifyTrustedList, NoNamedCertificateThatVerifiesIsAFailure)
{
    auto result = fetchAndVerifyTrustedList(localEntry({unrelatedCertDer()}), FetchOptions{});

    EXPECT_FALSE(result);
    EXPECT_NE(result.error.find("verification failed"), std::string::npos) << result.error;
}

TEST(FetchAndVerifyTrustedList, TreeOfAPlainListIsThatList)
{
    std::vector<std::string> verified;
    std::vector<std::string> failed;
    auto result = fetchTrustedListTree(
        localEntry({testSignerCertDer()}), FetchOptions{},
        [&](const std::string& url, const TrustedListInfo&) { verified.push_back(url); },
        [&](const std::string& url, const std::string&) { failed.push_back(url); });

    ASSERT_TRUE(result) << result.error;
    EXPECT_EQ(verified.size(), 1U);
    EXPECT_TRUE(failed.empty());
}

TEST(FetchAndVerifyTrustedList, ListPastItsNextUpdateIsRefused)
{
    TrustedListEntry entry = localEntry({testSignerCertDer()});
    entry.url = "file://" + kTrustFixtures + "stale-tl.xml";

    auto result = fetchAndVerifyTrustedList(entry, FetchOptions{});

    EXPECT_FALSE(result);
    EXPECT_NE(result.error.find("NextUpdate"), std::string::npos) << result.error;
}

namespace {

// A cache directory of its own: one shared with another run would serve the
// list off disk and leave the server unasked for a reason unrelated to the
// code under test.
class StaleCachedList : public ::testing::Test
{
protected:
    void SetUp() override
    {
        cacheDir = std::filesystem::temp_directory_path() /
                   ("librescrs-stale-tl-" + std::to_string(::getpid()) + "-" + std::to_string(++counter));
        std::filesystem::remove_all(cacheDir);
    }

    void TearDown() override
    {
        std::error_code ec;
        std::filesystem::remove_all(cacheDir, ec);
    }

    // The cache holds the stale list for @p url, well inside its lifetime.
    void cacheStaleListFor(const std::string& url)
    {
        TlCache(cacheDir.string()).store(url, readFile(kTrustFixtures + "stale-tl.xml"), "\"stale\"", "");
    }

    FetchResult fetch(const std::string& url)
    {
        TrustedListEntry entry;
        entry.url = url;
        entry.signingCertsDer = {testSignerCertDer()};
        FetchOptions opts;
        opts.cacheDirectory = cacheDir.string();
        return fetchAndVerifyTrustedList(entry, opts);
    }

    std::filesystem::path cacheDir;
    static inline int counter = 0;
};

} // namespace

// A list can pass its NextUpdate while its cached copy is still within the
// cache's lifetime. That copy is asked for again, once, instead of the list
// being refused until the cache lets go of it.
TEST_F(StaleCachedList, IsFetchedAgainOnceAndTheFreshListIsUsed)
{
    libresign::test::MockTrustedListServer server(kTrustFixtures + "synthetic-tl.xml");
    cacheStaleListFor(server.url());

    const auto result = fetch(server.url());

    ASSERT_TRUE(result) << result.error;
    EXPECT_EQ(result.info.services.size(), 1U);
    EXPECT_EQ(server.servedCount(), 1);
    const auto cached = TlCache(cacheDir.string()).load(server.url());
    ASSERT_TRUE(cached.has_value());
    EXPECT_EQ(cached->data, readFile(kTrustFixtures + "synthetic-tl.xml")) << "the fresh list replaced the stale one";
}

// A server still publishing the stale list gets one more request, not a loop,
// and the list is refused.
TEST_F(StaleCachedList, StillStaleAfterThatOneFetchIsRefused)
{
    libresign::test::MockTrustedListServer server(kTrustFixtures + "stale-tl.xml");
    cacheStaleListFor(server.url());

    const auto result = fetch(server.url());

    EXPECT_FALSE(result);
    EXPECT_NE(result.error.find("NextUpdate"), std::string::npos) << result.error;
    EXPECT_EQ(server.servedCount(), 1);
}

// A service the list says is no longer trusted -- withdrawn, or revoked in a
// v1 list -- is no anchor, whatever host the scheme spells its URI under.
TEST(TrustedListAnchors, ServicesWithANegativeStatusAreNotAnchors)
{
    const auto cert = testSignerCertDer();
    ASSERT_FALSE(cert.empty());
    TrustedListInfo info;
    const auto service = [&](const std::string& status) {
        TrustedServiceEntry e;
        e.serviceType = "http://uri.etsi.org/TrstSvc/Svctype/CA/QC";
        e.status = status;
        e.certDer = cert;
        return e;
    };
    info.services = {service("http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted"),
                     service("http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/withdrawn"),
                     service("http://www.mit.gov.rs/TrstSvc/TrustedList/Svcstatus/withdrawn"),
                     service("http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/deprecatedatnationallevel"),
                     service("http://uri.etsi.org/TrstSvc/Svcstatus/supervisionrevoked"),
                     service("http://www.mit.gov.rs/TrstSvc/TrustedList/Svcstatus/accredited")};

    const auto anchors = extractAnchorsFromTrustedList(info);
    EXPECT_EQ(anchors.size(), 2U) << "granted and accredited only";
}

TEST_F(TlSignatureVerifierTest, RejectsSha1SignatureMethod)
{
    auto xml =
        buildXmlWithAlgo("http://www.w3.org/2000/09/xmldsig#rsa-sha1", "http://www.w3.org/2001/04/xmlenc#sha256", "");
    auto certSpan = pinned_certs::kSerbianTlSigningCert;
    EXPECT_FALSE(verifier.verify(xml, certSpan));
    EXPECT_NE(verifier.lastError().find("unsupported signature algorithm"), std::string::npos)
        << "got: " << verifier.lastError();
}

TEST_F(TlSignatureVerifierTest, RejectsSha1DigestMethod)
{
    auto xml = buildXmlWithAlgo("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
                                "http://www.w3.org/2000/09/xmldsig#sha1", "");
    auto certSpan = pinned_certs::kSerbianTlSigningCert;
    EXPECT_FALSE(verifier.verify(xml, certSpan));
    EXPECT_NE(verifier.lastError().find("unsupported digest algorithm"), std::string::npos)
        << "got: " << verifier.lastError();
}

TEST_F(TlSignatureVerifierTest, XPathInjectionInReferenceUriIsLiteralLookup)
{
    // The legacy fallback used the URI-fragment as an XPath substring; an
    // attacker could supply id="' or '1'='1" to match the document root.
    // The safe lookup treats `id` as an opaque literal — so it must NOT
    // match any element (no element has Id literally equal to that string).
    const std::string injectId = "' or '1'='1";
    auto xml = buildXmlWithAlgo("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
                                "http://www.w3.org/2001/04/xmlenc#sha256", "#" + injectId);
    auto certSpan = pinned_certs::kSerbianTlSigningCert;
    EXPECT_FALSE(verifier.verify(xml, certSpan));
    EXPECT_NE(verifier.lastError().find("could not resolve reference URI"), std::string::npos)
        << "got: " << verifier.lastError();
}
