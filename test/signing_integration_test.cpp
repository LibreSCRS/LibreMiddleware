// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <gtest/gtest.h>
#include "signing_test_support/signing_test_support.h"

#include "dss/dss_service_manager.h"
#include "dss/dss_signing_service.h"
#include "http_client.h"

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

TEST_F(DSSSigningIntegrationTest, Pkcs11SignFailsWithInvalidModule)
{
    libresign::DSSSigningService svc(*manager);

    libresign::SigningRequest req;
    auto pdf = buildTestPdf();
    req.document = std::vector<uint8_t>(pdf.begin(), pdf.end());
    req.fileName = "test.pdf";
    req.format = libresign::SignatureFormat::Pades;
    req.level = libresign::SignatureLevel::B_B;

    auto result = svc.sign(req, "/nonexistent/pkcs11.so", libresign::as_pin("0000"), "", "");
    EXPECT_FALSE(result.success);
    EXPECT_FALSE(result.errorMessage.empty());
}

// ============================================================================
// RealCardSigningTest — RETIRED: every (PAdES/CAdES/ASiC-E)*(B-B/B-T/B-LT/
// B-LTA) combination is now covered by SigningE2ETest's parametric suite,
// which runs through both Native and DSS backends rather than just DSS.
// Real-card multi-PIN coverage lives in test/e2e/.
// ============================================================================
