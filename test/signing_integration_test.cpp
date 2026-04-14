// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <gtest/gtest.h>
#include "signing_test_support/signing_test_support.h"

#include "libresign/dss/dss_service_manager.h"
#include "libresign/dss/dss_signing_service.h"
#include "libresign/http_client.h"
#include "libresign/trust_store_manager.h"

#include <cstdlib>
#include <filesystem>
#include <fstream>

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
    cfg.trustedLists.push_back({"https://www.mit.gov.rs/TrustedList/TSL-RS.xml", false, true});
    cfg.cacheDirectory = (fs::temp_directory_path() / "librescrs-test-tsl").string();
    cfg.crlEnabled = true;
    cfg.ocspEnabled = true;
    return cfg;
}

// ============================================================================
// TrustStoreManager integration tests — uses real bundled certificates
// ============================================================================

class TrustStoreIntegrationTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        bundledDir = std::string(LIBREMIDDLEWARE_CERT_DIR);
        ASSERT_TRUE(fs::exists(bundledDir));
    }
    std::string bundledDir;
};

TEST_F(TrustStoreIntegrationTest, CardVerificationStoreLoadsMupCerts)
{
    libresign::TrustStoreManager mgr(bundledDir);
    auto store = mgr.buildStore(libresign::StoreScope::CARD_VERIFICATION);
    ASSERT_NE(store, nullptr);

    // Verify at least some MUP certs were loaded by checking store object count
    auto* objs = X509_STORE_get0_objects(store.get());
    int count = sk_X509_OBJECT_num(objs);
    EXPECT_GT(count, 10) << "Expected >10 certificates loaded from rs-mup/ + rs-pks/ + rs-mup-format/";
}

TEST_F(TrustStoreIntegrationTest, ChainDisplayIncludesSystemCerts)
{
    libresign::TrustStoreManager mgr(bundledDir);
    auto cardStore = mgr.buildStore(libresign::StoreScope::CARD_VERIFICATION);
    auto chainStore = mgr.buildStore(libresign::StoreScope::CHAIN_DISPLAY);

    ASSERT_NE(cardStore, nullptr);
    ASSERT_NE(chainStore, nullptr);

    int cardCount = sk_X509_OBJECT_num(X509_STORE_get0_objects(cardStore.get()));
    int chainCount = sk_X509_OBJECT_num(X509_STORE_get0_objects(chainStore.get()));

    // Chain display includes system certs — should be at least as many as bundled-only
    EXPECT_GE(chainCount, cardCount) << "CHAIN_DISPLAY should include system store + bundled";
}

TEST_F(TrustStoreIntegrationTest, SigningScopeIncludesEverything)
{
    libresign::TrustStoreManager mgr(bundledDir);
    auto signingStore = mgr.buildStore(libresign::StoreScope::SIGNING);
    ASSERT_NE(signingStore, nullptr);

    int count = sk_X509_OBJECT_num(X509_STORE_get0_objects(signingStore.get()));
    EXPECT_GT(count, 10) << "Signing store should include system + bundled certs";
}

TEST_F(TrustStoreIntegrationTest, CertPathsContainExpectedSubdirs)
{
    libresign::TrustStoreManager mgr(bundledDir);
    auto paths = mgr.certPathsForScope(libresign::StoreScope::CARD_VERIFICATION);

    bool hasMup = false, hasPks = false, hasFormat = false;
    for (const auto& p : paths) {
        if (p.find("rs-mup-format") != std::string::npos)
            hasFormat = true;
        else if (p.find("rs-mup") != std::string::npos)
            hasMup = true;
        else if (p.find("rs-pks") != std::string::npos)
            hasPks = true;
    }
    EXPECT_TRUE(hasMup) << "Expected rs-mup/ in cert paths";
    EXPECT_TRUE(hasPks) << "Expected rs-pks/ in cert paths";
    EXPECT_TRUE(hasFormat) << "Expected rs-mup-format/ in cert paths";
}

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

TEST_F(DSSSigningIntegrationTest, Pkcs11SignFailsWithInvalidModule)
{
    libresign::DSSSigningService svc(*manager);

    libresign::SigningRequest req;
    auto pdf = buildTestPdf();
    req.document = std::vector<uint8_t>(pdf.begin(), pdf.end());
    req.fileName = "test.pdf";
    req.format = libresign::SignatureFormat::PAdES;
    req.level = libresign::SignatureLevel::B_B;

    auto result = svc.sign(req, "/nonexistent/pkcs11.so", libresign::as_pin("0000"), "");
    EXPECT_FALSE(result.success);
    EXPECT_FALSE(result.errorMessage.empty());
}

// ============================================================================
// Real card signing test — requires LIBRESCRS_TEST_PIN env var
// ============================================================================

class RealCardSigningTest : public DSSSigningIntegrationTest
{
protected:
    void SetUp() override
    {
        DSSSigningIntegrationTest::SetUp();
        SKIP_IF_PIN_FAILED();

        auto cfgResult = readTestConfig();
        if (!cfgResult.valid)
            GTEST_SKIP() << cfgResult.skipReason;

        testPin = cfgResult.config.pin;
        pkcs11Path = cfgResult.config.pkcs11Module;
        tokenLabel = cfgResult.config.tokenLabel;

        if (!fs::exists(pkcs11Path))
            GTEST_SKIP() << "PKCS#11 module not found: " << pkcs11Path;
    }

    std::string testPin;
    std::string pkcs11Path;
    std::string tokenLabel;
};

TEST_F(RealCardSigningTest, SignPdf_BB)
{
    SKIP_IF_PIN_FAILED();
    libresign::DSSSigningService svc(*manager);

    auto pdfContent = buildTestPdf();
    libresign::SigningRequest req;
    req.document = std::vector<uint8_t>(pdfContent.begin(), pdfContent.end());
    req.fileName = "test.pdf";
    req.format = libresign::SignatureFormat::PAdES;
    req.level = libresign::SignatureLevel::B_B;
    req.allowExpiredCertificate = true;

    auto result = svc.sign(req, pkcs11Path, libresign::as_pin(testPin), "", tokenLabel);
    checkPinFailure(result);
    EXPECT_TRUE(result.success) << "Signing failed: " << result.errorMessage;
    EXPECT_FALSE(result.signedDocument.empty());

    // Verify the output starts with %PDF
    if (result.success && result.signedDocument.size() >= 4) {
        EXPECT_EQ(result.signedDocument[0], '%');
        EXPECT_EQ(result.signedDocument[1], 'P');
        EXPECT_EQ(result.signedDocument[2], 'D');
        EXPECT_EQ(result.signedDocument[3], 'F');

        // Save and verify with pdfsig
        std::string outPath = (fs::temp_directory_path() / "librescrs-test-bb-signed.pdf").string();
        std::ofstream ofs(outPath, std::ios::binary);
        ofs.write(reinterpret_cast<const char*>(result.signedDocument.data()),
                  static_cast<std::streamsize>(result.signedDocument.size()));
        ofs.close();
        fprintf(stderr, "[TEST] Saved B-B signed PDF to %s (%zu bytes)\n", outPath.c_str(),
                result.signedDocument.size());
    }
}

TEST_F(RealCardSigningTest, SignPdf_BT)
{
    SKIP_IF_PIN_FAILED();
    libresign::DSSSigningService svc(*manager);

    auto pdfContent = buildTestPdf();
    libresign::SigningRequest req;
    req.document = std::vector<uint8_t>(pdfContent.begin(), pdfContent.end());
    req.fileName = "test-bt.pdf";
    req.format = libresign::SignatureFormat::PAdES;
    req.level = libresign::SignatureLevel::B_T;
    req.tsa.url = "http://timestamp.digicert.com";
    req.allowExpiredCertificate = true;

    auto result = svc.sign(req, pkcs11Path, libresign::as_pin(testPin), "", tokenLabel);
    checkPinFailure(result);
    EXPECT_TRUE(result.success) << "B-T signing failed: " << result.errorMessage;
    EXPECT_FALSE(result.signedDocument.empty());
}

TEST_F(RealCardSigningTest, SignPdf_BLT)
{
    SKIP_IF_PIN_FAILED();
    libresign::DSSSigningService svc(*manager);

    auto trustCfg = buildTestTrustConfig();
    ASSERT_TRUE(svc.configure(trustCfg)) << "Trust config failed";

    auto pdfContent = buildTestPdf();
    libresign::SigningRequest req;
    req.document = std::vector<uint8_t>(pdfContent.begin(), pdfContent.end());
    req.fileName = "test-blt.pdf";
    req.format = libresign::SignatureFormat::PAdES;
    req.level = libresign::SignatureLevel::B_LT;
    req.tsa.url = "http://timestamp.digicert.com";
    req.allowExpiredCertificate = true;

    auto result = svc.sign(req, pkcs11Path, libresign::as_pin(testPin), "", tokenLabel);
    checkPinFailure(result);
    EXPECT_TRUE(result.success) << "B-LT signing failed: " << result.errorMessage;
    EXPECT_FALSE(result.signedDocument.empty());

    if (result.success && !result.signedDocument.empty()) {
        std::string outPath = (fs::temp_directory_path() / "librescrs-test-blt-signed.pdf").string();
        std::ofstream ofs(outPath, std::ios::binary);
        ofs.write(reinterpret_cast<const char*>(result.signedDocument.data()),
                  static_cast<std::streamsize>(result.signedDocument.size()));
        ofs.close();
        fprintf(stderr, "[TEST] Saved B-LT signed PDF to %s (%zu bytes)\n", outPath.c_str(),
                result.signedDocument.size());
    }
}

TEST_F(RealCardSigningTest, SignPdf_BLTA)
{
    SKIP_IF_PIN_FAILED();
    libresign::DSSSigningService svc(*manager);

    auto trustCfg = buildTestTrustConfig();
    ASSERT_TRUE(svc.configure(trustCfg)) << "Trust config failed";

    auto pdfContent = buildTestPdf();
    libresign::SigningRequest req;
    req.document = std::vector<uint8_t>(pdfContent.begin(), pdfContent.end());
    req.fileName = "test-blta.pdf";
    req.format = libresign::SignatureFormat::PAdES;
    req.level = libresign::SignatureLevel::B_LTA;
    req.tsa.url = "http://timestamp.digicert.com";
    req.allowExpiredCertificate = true;

    auto result = svc.sign(req, pkcs11Path, libresign::as_pin(testPin), "", tokenLabel);
    checkPinFailure(result);
    EXPECT_TRUE(result.success) << "B-LTA signing failed: " << result.errorMessage;
    EXPECT_FALSE(result.signedDocument.empty());

    if (result.success && !result.signedDocument.empty()) {
        std::string outPath = (fs::temp_directory_path() / "librescrs-test-blta-signed.pdf").string();
        std::ofstream ofs(outPath, std::ios::binary);
        ofs.write(reinterpret_cast<const char*>(result.signedDocument.data()),
                  static_cast<std::streamsize>(result.signedDocument.size()));
        ofs.close();
        fprintf(stderr, "[TEST] Saved B-LTA signed PDF to %s (%zu bytes)\n", outPath.c_str(),
                result.signedDocument.size());
    }
}

TEST_F(RealCardSigningTest, SignBinary_CAdES_BB)
{
    SKIP_IF_PIN_FAILED();
    libresign::DSSSigningService svc(*manager);

    std::string content = "Hello, this is a test document for CAdES signing.";

    libresign::SigningRequest req;
    req.document = std::vector<uint8_t>(content.begin(), content.end());
    req.fileName = "test.txt";
    req.format = libresign::SignatureFormat::CAdES;
    req.level = libresign::SignatureLevel::B_B;
    req.allowExpiredCertificate = true; // Gemalto test cert expired 2026-03-02

    auto result = svc.sign(req, pkcs11Path, libresign::as_pin(testPin), "", tokenLabel);
    checkPinFailure(result);
    EXPECT_TRUE(result.success) << "CAdES signing failed: " << result.errorMessage;
    EXPECT_FALSE(result.signedDocument.empty()) << "CAdES .p7s should not be empty";
}

TEST_F(RealCardSigningTest, SignText_ASiCE_BLTA)
{
    SKIP_IF_PIN_FAILED();
    libresign::DSSSigningService svc(*manager);

    auto trustCfg = buildTestTrustConfig();
    ASSERT_TRUE(svc.configure(trustCfg)) << "Trust config failed";

    std::string content = "Test document for ASiC-E B-LTA signing.";

    libresign::SigningRequest req;
    req.document = std::vector<uint8_t>(content.begin(), content.end());
    req.fileName = "test.txt";
    req.format = libresign::SignatureFormat::ASiC_E;
    req.level = libresign::SignatureLevel::B_LTA;
    req.tsa.url = "http://timestamp.digicert.com";
    req.allowExpiredCertificate = true;

    auto result = svc.sign(req, pkcs11Path, libresign::as_pin(testPin), "", tokenLabel);
    checkPinFailure(result);
    EXPECT_TRUE(result.success) << "ASiC-E B-LTA signing failed: " << result.errorMessage;
    EXPECT_FALSE(result.signedDocument.empty());

    if (result.success && !result.signedDocument.empty()) {
        // ASiC-E is a ZIP — verify PK magic bytes
        EXPECT_GE(result.signedDocument.size(), 4u);
        EXPECT_EQ(result.signedDocument[0], 'P');
        EXPECT_EQ(result.signedDocument[1], 'K');

        std::string outPath = (fs::temp_directory_path() / "librescrs-test-asice-blta.asice").string();
        std::ofstream ofs(outPath, std::ios::binary);
        ofs.write(reinterpret_cast<const char*>(result.signedDocument.data()),
                  static_cast<std::streamsize>(result.signedDocument.size()));
        ofs.close();
        fprintf(stderr, "[TEST] Saved ASiC-E B-LTA to %s (%zu bytes)\n", outPath.c_str(), result.signedDocument.size());
    }
}
