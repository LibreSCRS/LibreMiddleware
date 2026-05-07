// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <gtest/gtest.h>
#include "dss/dss_service_manager.h"
#include "dss/dss_signing_service.h"

#include <filesystem>

namespace fs = std::filesystem;

class DSSIntegrationTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        // Locate the DSS service JAR
        jarPath = std::string(CMAKE_SOURCE_DIR) + "/tools/dss-service/target/dss-service-1.0.0-SNAPSHOT.jar";
        if (!fs::exists(jarPath)) {
            GTEST_SKIP() << "DSS service JAR not found at " << jarPath
                         << " — run 'cd tools/dss-service && mvn package -DskipTests' first";
        }

        // Java availability is checked by DSSServiceManager::ensureRunning()
    }

    std::string jarPath;
};

TEST_F(DSSIntegrationTest, ServiceStartsAndRespondsToHealth)
{
    libresign::DSSServiceManager::Config cfg;
    cfg.jarPath = jarPath;
    cfg.startupTimeout = std::chrono::seconds(30);

    libresign::DSSServiceManager mgr(cfg);
    auto result = mgr.ensureRunning();
    ASSERT_TRUE(result) << result.error;
    EXPECT_TRUE(mgr.isHealthy());
    mgr.stop();
    EXPECT_FALSE(mgr.isHealthy());
}

TEST_F(DSSIntegrationTest, SigningServiceReportsAvailable)
{
    libresign::DSSServiceManager::Config cfg;
    cfg.jarPath = jarPath;
    cfg.startupTimeout = std::chrono::seconds(30);

    libresign::DSSServiceManager mgr(cfg);
    mgr.ensureRunning();

    libresign::DSSSigningService svc(mgr);
    EXPECT_TRUE(svc.isAvailable());

    mgr.stop();
    EXPECT_FALSE(svc.isAvailable());
}
