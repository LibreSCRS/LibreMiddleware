// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <gtest/gtest.h>
#include "dss_validation_client.h"
#include "signing_keys.h"
#include "signing_test_support/signing_test_support.h"

#include "dss/dss_service_manager.h"
#include "dss/dss_signing_service.h"
#include "http_client.h"

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <memory>
#include <string>
#include <utility>

#include <openssl/bio.h>
#include <openssl/cms.h>
#include <openssl/x509.h>

namespace fs = std::filesystem;

using namespace libresign::test;

static std::string getJarPath()
{
    return std::string(CMAKE_SOURCE_DIR) + "/tools/dss-service/target/dss-service-1.0.0-SNAPSHOT.jar";
}

static libresign::TrustConfig buildTestTrustConfig()
{
    libresign::TrustConfig cfg;
    libresign::TrustedListEntry serbianTl;
    serbianTl.url = "https://www.mit.gov.rs/TrustedList/TSL-RS.xml";
    serbianTl.isLotl = false;
    serbianTl.eager = true;
    cfg.trustedLists.push_back(std::move(serbianTl));
    cfg.cacheDirectory = (fs::temp_directory_path() / "librescrs-test-tsl").string();
    cfg.crlEnabled = true;
    cfg.ocspEnabled = true;
    return cfg;
}

// The pre-4.0 TrustStoreManager-based integration tests
// (CardVerificationStoreLoadsMupCerts, ChainDisplayIncludesSystemCerts,
// SigningScopeIncludesEverything, CertPathsContainExpectedSubdirs) were
// retired with the class itself. Bundled-cert + system-store coverage now
// lives in TrustStoreServiceTests (default-CI hermetic) and the LM
// X509_STORE-construction path is exercised end-to-end by the existing
// signing E2E tests.

// ============================================================================
// DSS service integration — signing with test data (no card)
// ============================================================================

class DSSSigningIntegrationTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        jarPath = getJarPath();
        if (!fs::exists(jarPath))
            GTEST_SKIP() << "DSS JAR not found: " << jarPath;
        // Java availability is checked by DSSServiceManager::ensureRunning()

        libresign::DSSServiceManager::Config cfg;
        cfg.jarPath = jarPath;
        cfg.startupTimeout = std::chrono::seconds(30);
        manager = std::make_unique<libresign::DSSServiceManager>(cfg);

        auto result = manager->ensureRunning();
        if (!result)
            GTEST_SKIP() << result.error;
    }

    void TearDown() override
    {
        if (manager)
            manager->stop();
    }

    std::string jarPath;
    std::unique_ptr<libresign::DSSServiceManager> manager;
};

TEST_F(DSSSigningIntegrationTest, HealthEndpointReturnsJson)
{
    libresign::HttpClient client;
    auto resp = client.get("http://localhost/health", 5, manager->unixSocketPath());
    EXPECT_EQ(resp.statusCode, 200);
    EXPECT_FALSE(resp.body.empty());
    EXPECT_NE(resp.body.find("ok"), std::string::npos);
}

TEST_F(DSSSigningIntegrationTest, ConfigEndpointAcceptsTrustConfig)
{
    libresign::DSSSigningService svc(*manager);

    auto config = buildTestTrustConfig();

    EXPECT_TRUE(svc.configure(config)) << "DSS /config should succeed";
    EXPECT_TRUE(svc.isConfigured());
}

// The oracle signs with a key the caller holds: it hands back the bytes to
// sign, the key signs them here, and it builds the document around the
// signature. Every format comes back with exactly one signature by the key,
// which the oracle's own validator does not find cryptographically broken, and
// the CAdES one also verifies with OpenSSL over the content.
TEST_F(DSSSigningIntegrationTest, SignsWithAKeyTheCallerHolds)
{
    libresign::DSSSigningService svc(*manager);
    const auto pdf = buildTestPdf();
    const auto xml = buildTestXml();
    const std::string text = "the contract";
    const struct
    {
        libresign::SignatureFormat format;
        libresign::SignaturePackaging packaging;
        std::string document;
        const char* fileName;
        const char* oracleFormat;
        const char* oraclePackaging;
    } cases[] = {
        {libresign::SignatureFormat::Pades, libresign::SignaturePackaging::Enveloped, pdf, "test.pdf", "PAdES",
         "ENVELOPED"},
        {libresign::SignatureFormat::Cades, libresign::SignaturePackaging::Detached, text, "test.txt", "CAdES",
         "DETACHED"},
        {libresign::SignatureFormat::Xades, libresign::SignaturePackaging::Enveloped, xml, "test.xml", "XAdES",
         "ENVELOPED"},
        {libresign::SignatureFormat::Jades, libresign::SignaturePackaging::Detached, text, "test.txt", "JAdES",
         "DETACHED"},
        {libresign::SignatureFormat::AsicE, libresign::SignaturePackaging::Detached, text, "test.txt", "ASiC_E",
         "ENVELOPED"},
    };
    const auto running = manager->ensureRunning();
    ASSERT_TRUE(running) << running.error;
    DSSValidationClient validator(running.baseUrl, manager->unixSocketPath());
    for (const auto& c : cases) {
        SCOPED_TRACE(c.fileName + std::string{" format "} + std::to_string(static_cast<int>(c.format)));
        libresign::SigningRequest req;
        req.document.assign(c.document.begin(), c.document.end());
        req.fileName = c.fileName;
        req.format = c.format;
        req.packaging = c.packaging;
        req.level = libresign::SignatureLevel::B_B;
        SoftSigningKey key(validSignerKey());

        const auto result = svc.sign(req, key);

        ASSERT_TRUE(result.success) << result.errorMessage;
        EXPECT_FALSE(result.signedDocument.empty());
        EXPECT_EQ(key.signCalls, 1);
        const bool detached =
            c.packaging == libresign::SignaturePackaging::Detached && c.format != libresign::SignatureFormat::AsicE;
        const auto report =
            validator.validate(result.signedDocument, c.oracleFormat, c.oraclePackaging,
                               detached ? std::span<const uint8_t>{req.document} : std::span<const uint8_t>{});
        ASSERT_TRUE(report.error.empty()) << report.error;
        ASSERT_EQ(report.signatureCount, 1);
        for (const auto& sig : report.signatures)
            EXPECT_NE(sig.indication, "TOTAL_FAILED") << sig.subIndication;
        if (c.format != libresign::SignatureFormat::Cades)
            continue;
        const unsigned char* p = result.signedDocument.data();
        const std::unique_ptr<CMS_ContentInfo, decltype(&CMS_ContentInfo_free)> cms(
            d2i_CMS_ContentInfo(nullptr, &p, static_cast<long>(result.signedDocument.size())), &CMS_ContentInfo_free);
        ASSERT_NE(cms, nullptr);
        const std::unique_ptr<BIO, decltype(&BIO_free)> content(
            BIO_new_mem_buf(req.document.data(), static_cast<int>(req.document.size())), &BIO_free);
        EXPECT_EQ(CMS_verify(cms.get(), nullptr, nullptr, content.get(), nullptr,
                             CMS_NO_SIGNER_CERT_VERIFY | CMS_BINARY | CMS_DETACHED),
                  1)
            << "the oracle's CAdES signature does not verify over the content";
    }
}

// ============================================================================
// RealCardSigningTest — RETIRED: every (PAdES/CAdES/ASiC-E)*(B-B/B-T/B-LT/
// B-LTA) combination is now covered by SigningE2ETest's parametric suite,
// which runs through both Native and DSS backends rather than just DSS.
// Real-card multi-PIN coverage lives in test/e2e/.
// ============================================================================
